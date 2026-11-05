use std::collections::{BTreeMap, BTreeSet};

use fpl_resource_observation::{
    Attachment, AttachmentTransport, Confidence, GpuBackend, GpuProfile, HostRef, Observation,
    Provenance, Resource, ResourceCatalog, ResourceId, ResourceProfile, StorageProfile,
    SCHEMA_VERSION,
};
use mycelium_peer_protocol::{HardwareBus, HardwareDevice, HardwareKind, HardwareSnapshot};

/// Hardware identity changes slowly, but a disappeared peer must not advertise
/// resources forever. This exceeds two normal five-minute collection periods.
const RESOURCE_TTL_SECONDS: u64 = 15 * 60;

pub fn project(snapshots: impl IntoIterator<Item = HardwareSnapshot>) -> ResourceCatalog {
    let mut catalog = ResourceCatalog {
        schema_version: SCHEMA_VERSION,
        ..ResourceCatalog::default()
    };
    for snapshot in snapshots {
        project_snapshot(snapshot, &mut catalog);
    }
    catalog.normalize();
    catalog
}

fn project_snapshot(snapshot: HardwareSnapshot, catalog: &mut ResourceCatalog) {
    let identities = snapshot
        .devices
        .iter()
        .filter_map(|device| {
            resource_kind_prefix(device).map(|prefix| {
                let provider_id = device.id.strip_prefix("hw:").unwrap_or(&device.id);
                (
                    device.id.clone(),
                    ResourceId(format!("{prefix}/{provider_id}")),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();

    for device in &snapshot.devices {
        let Some(resource_id) = identities.get(&device.id).cloned() else {
            continue;
        };
        let provenance = Provenance {
            provider: "mycelium".into(),
            observer: snapshot.node_id.clone(),
            source_id: Some(device.id.clone()),
        };
        let expires_at = snapshot.observed_at.saturating_add(RESOURCE_TTL_SECONDS);
        catalog.observations.push(Observation {
            schema_version: SCHEMA_VERSION,
            resource_id: resource_id.clone(),
            observed_at: snapshot.observed_at,
            expires_at,
            provenance: provenance.clone(),
            confidence: identity_confidence(device),
            value: Resource {
                label: device
                    .model
                    .clone()
                    .unwrap_or_else(|| device.locator.clone()),
                profile: profile(device),
            },
        });
        catalog.attachments.push(Observation {
            schema_version: SCHEMA_VERSION,
            resource_id: resource_id.clone(),
            observed_at: snapshot.observed_at,
            expires_at,
            provenance,
            confidence: Confidence::Strong,
            value: Attachment {
                resource_id,
                host: HostRef {
                    id: snapshot.node_id.clone(),
                    label: snapshot.hostname.clone(),
                },
                transport: transport(device),
                parent: device
                    .parent
                    .as_ref()
                    .and_then(|parent| identities.get(parent).cloned()),
            },
        });
    }
}

fn resource_kind_prefix(device: &HardwareDevice) -> Option<&'static str> {
    match &device.kind {
        HardwareKind::Accelerator if is_gpu(device) => Some("gpu"),
        HardwareKind::Accelerator => None,
        HardwareKind::StorageDevice | HardwareKind::StorageVolume => Some("storage"),
        // Raw USB/PCI nodes are topology evidence, not automatically useful
        // resources. Function probes will project cameras/audio independently.
        HardwareKind::PciDevice
        | HardwareKind::UsbDevice
        | HardwareKind::StorageController
        | HardwareKind::SecurityModule
        | HardwareKind::Battery
        | HardwareKind::BluetoothDevice => None,
        // Additive kinds from newer peers are ignored, not fatal. The envelope
        // signature still verifies because HardwareKind preserves the raw string.
        HardwareKind::Unknown(kind) => {
            eprintln!(
                "myceliumd: ignoring hardware device {} of unknown kind {kind:?}",
                device.locator
            );
            None
        }
    }
}

fn is_gpu(device: &HardwareDevice) -> bool {
    device
        .properties
        .get("class")
        .is_some_and(|class| class.trim_start_matches("0x").starts_with("03"))
        || ["metal", "cuda-hardware", "rocm-hardware", "drm"]
            .iter()
            .any(|capability| device.capabilities.contains(*capability))
}

fn identity_confidence(device: &HardwareDevice) -> Confidence {
    if device.serial_hash.is_some() {
        Confidence::Strong
    } else if matches!(device.kind, HardwareKind::Accelerator) {
        Confidence::Derived
    } else {
        Confidence::Weak
    }
}

fn profile(device: &HardwareDevice) -> ResourceProfile {
    match device.kind {
        HardwareKind::Accelerator => {
            let mut backends = BTreeSet::new();
            if device.capabilities.contains("metal") {
                backends.insert(GpuBackend::Metal);
            }
            if device.capabilities.contains("cuda-hardware") {
                backends.insert(GpuBackend::Cuda);
            }
            if device.capabilities.contains("rocm-hardware") {
                backends.insert(GpuBackend::Rocm);
            }
            ResourceProfile::Gpu(GpuProfile {
                vendor: device.vendor.clone(),
                model: device.model.clone(),
                backends,
                capabilities: device.capabilities.clone(),
                memory_total_bytes: property_u64(device, "memory_total_bytes"),
            })
        }
        HardwareKind::StorageDevice | HardwareKind::StorageVolume => {
            let mut capabilities = BTreeSet::new();
            if matches!(device.kind, HardwareKind::StorageVolume) {
                capabilities.insert("volume".into());
            }
            ResourceProfile::Storage(StorageProfile {
                vendor: device.vendor.clone(),
                model: device.model.clone(),
                capacity_bytes: property_u64(device, "size_bytes"),
                removable: device
                    .properties
                    .get("removable")
                    .map(|value| value == "1" || value.eq_ignore_ascii_case("true")),
                capabilities,
            })
        }
        _ => unreachable!("only projected device kinds are profiled"),
    }
}

fn property_u64(device: &HardwareDevice, key: &str) -> Option<u64> {
    device.properties.get(key)?.parse().ok()
}

fn transport(device: &HardwareDevice) -> AttachmentTransport {
    match device.bus {
        HardwareBus::Usb => AttachmentTransport::Usb {
            locator: device.locator.clone(),
            speed_mbps: property_u64(device, "speed_mbps"),
        },
        HardwareBus::Pci => AttachmentTransport::Pcie {
            address: device.locator.trim_start_matches("pci:").into(),
            current_speed: device.properties.get("current_link_speed").cloned(),
            current_width: device.properties.get("current_link_width").cloned(),
        },
        HardwareBus::Nvme => AttachmentTransport::Nvme {
            locator: device.locator.clone(),
        },
        HardwareBus::Scsi | HardwareBus::Sata => AttachmentTransport::Scsi {
            locator: device.locator.clone(),
        },
        HardwareBus::Virtio => AttachmentTransport::Virtio {
            locator: device.locator.clone(),
        },
        HardwareBus::Integrated => AttachmentTransport::Integrated {
            locator: device.locator.clone(),
        },
        HardwareBus::Thunderbolt | HardwareBus::Bluetooth | HardwareBus::Unknown => {
            AttachmentTransport::Unknown {
                locator: device.locator.clone(),
                attributes: BTreeMap::new(),
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(devices: Vec<HardwareDevice>) -> HardwareSnapshot {
        HardwareSnapshot {
            schema_version: 1,
            node_id: "peer-a".into(),
            hostname: "neo".into(),
            observed_at: 100,
            devices,
        }
    }

    fn device(kind: HardwareKind, bus: HardwareBus, id: &str) -> HardwareDevice {
        HardwareDevice {
            id: id.into(),
            parent: None,
            locator: format!("test:{id}"),
            kind,
            bus,
            vendor: None,
            model: Some(id.into()),
            serial_hash: None,
            capabilities: BTreeSet::new(),
            properties: BTreeMap::new(),
        }
    }

    #[test]
    fn gpu_projects_to_typed_resource_and_structural_attachment() {
        let mut gpu = device(
            HardwareKind::Accelerator,
            HardwareBus::Integrated,
            "apple-gpu",
        );
        gpu.capabilities.insert("metal".into());
        let catalog = project([snapshot(vec![gpu])]);
        assert_eq!(catalog.observations.len(), 1);
        assert_eq!(catalog.observations[0].value.kind().as_str(), "gpu");
        assert!(matches!(
            catalog.attachments[0].value.transport,
            AttachmentTransport::Integrated { .. }
        ));
        assert_eq!(catalog.observations[0].expires_at, 100 + 15 * 60);
    }

    #[test]
    fn raw_bus_devices_are_not_promoted_to_resources() {
        let usb = device(HardwareKind::UsbDevice, HardwareBus::Usb, "bus-node");
        let tpm = device(
            HardwareKind::SecurityModule,
            HardwareBus::Unknown,
            "tpm:tpm0",
        );
        let catalog = project([snapshot(vec![usb, tpm])]);
        assert!(catalog.observations.is_empty());
        assert!(catalog.attachments.is_empty());
    }

    #[test]
    fn storage_volume_keeps_parent_resource_relationship() {
        let disk = device(HardwareKind::StorageDevice, HardwareBus::Nvme, "disk");
        let mut volume = device(HardwareKind::StorageVolume, HardwareBus::Nvme, "volume");
        volume.parent = Some("disk".into());
        let catalog = project([snapshot(vec![disk, volume])]);
        let volume = catalog
            .attachments
            .iter()
            .find(|attachment| attachment.resource_id.0.ends_with("volume"))
            .unwrap();
        assert_eq!(
            volume.value.parent.as_ref().map(|id| id.0.as_str()),
            Some("storage/disk")
        );
    }

    #[test]
    fn non_gpu_accelerator_is_not_mislabeled() {
        let accelerator = device(HardwareKind::Accelerator, HardwareBus::Pci, "fpga");
        let catalog = project([snapshot(vec![accelerator])]);
        assert!(catalog.observations.is_empty());
    }

    #[test]
    fn refresh_changes_observation_lifetime_not_topology_attachment() {
        let mut gpu = device(HardwareKind::Accelerator, HardwareBus::Integrated, "gpu");
        gpu.capabilities.insert("metal".into());
        let first = project([snapshot(vec![gpu.clone()])]);
        let mut refreshed = snapshot(vec![gpu]);
        refreshed.observed_at = 200;
        let second = project([refreshed]);
        assert_ne!(first.attachments, second.attachments);
        assert_eq!(first.attachments[0].value, second.attachments[0].value);
    }
}
