use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use mycelium_peer_protocol::{
    sha256_hex, HardwareBus, HardwareDevice, HardwareKind, HardwareSnapshot, PeerHello,
    MAX_HARDWARE_DEVICES,
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

pub fn collect(peer: &PeerHello) -> Result<HardwareSnapshot, AnyError> {
    let mut devices = platform_devices(&peer.node_id)?;
    devices.sort_by(|left, right| left.id.cmp(&right.id));
    devices.dedup_by(|left, right| left.id == right.id);
    if devices.len() > MAX_HARDWARE_DEVICES {
        return Err(format!(
            "hardware inventory has {} devices; maximum is {MAX_HARDWARE_DEVICES}",
            devices.len()
        )
        .into());
    }
    let snapshot = HardwareSnapshot {
        schema_version: 1,
        node_id: peer.node_id.clone(),
        hostname: peer.hostname.clone(),
        observed_at: now(),
        devices,
    };
    snapshot.validate_for(&peer.node_id)?;
    Ok(snapshot)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hardware_id(node_id: &str, locator: &str) -> String {
    let digest = sha256_hex(format!("{node_id}\0{locator}").as_bytes());
    format!("hw:{}", &digest[..24])
}

fn serial_hash(value: Option<String>) -> Option<String> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| sha256_hex(value.as_bytes()))
}

#[cfg(target_os = "linux")]
fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn link_name(path: impl AsRef<Path>) -> Option<String> {
    fs::read_link(path).ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    })
}

#[cfg(target_os = "linux")]
fn platform_devices(node_id: &str) -> Result<Vec<HardwareDevice>, AnyError> {
    let mut devices = Vec::new();
    collect_linux_pci(node_id, &mut devices)?;
    collect_linux_usb(node_id, &mut devices)?;
    collect_linux_storage(node_id, &mut devices)?;
    collect_linux_tpm(node_id, Path::new("/sys/class/tpm"), &mut devices)?;
    Ok(devices)
}

/// Observe registered TPMs without opening a character device or issuing commands.
/// Presence is not evidence of usable sealing, hardware provenance, or attestation.
#[cfg(target_os = "linux")]
fn collect_linux_tpm(
    node_id: &str,
    root: &Path,
    out: &mut Vec<HardwareDevice>,
) -> Result<(), AnyError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(index) = name.strip_prefix("tpm") else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let path = entry.path();
        let version = match fs::read_to_string(path.join("tpm_version_major")) {
            Ok(value) => match value.trim() {
                "1" => "1",
                "2" => "2",
                _ => "unknown",
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "unknown",
            Err(error) => return Err(error.into()),
        };
        let locator = format!("tpm:{name}");
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: None,
            locator,
            kind: HardwareKind::SecurityModule,
            // TPM class registration alone does not establish its physical bus.
            bus: HardwareBus::Unknown,
            vendor: None,
            model: Some("TPM".into()),
            serial_hash: None,
            capabilities: BTreeSet::from(["tpm-present".into()]),
            properties: BTreeMap::from([
                ("tpm_version_major".into(), version.into()),
                ("source".into(), path.to_string_lossy().into_owned()),
                ("key_protection".into(), "unknown".into()),
                ("attestation".into(), "not_verified".into()),
            ]),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_linux_pci(node_id: &str, out: &mut Vec<HardwareDevice>) -> Result<(), AnyError> {
    let root = Path::new("/sys/bus/pci/devices");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let address = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let locator = format!("pci:{address}");
        let class = read_trim(path.join("class")).unwrap_or_default();
        let class_code = class.trim_start_matches("0x");
        let accelerator = class_code.starts_with("03") || class_code.starts_with("12");
        let mut capabilities = BTreeSet::new();
        if accelerator {
            capabilities.insert("compute".into());
            if read_trim(path.join("vendor")).as_deref() == Some("0x10de") {
                capabilities.insert("cuda-hardware".into());
            }
            if read_trim(path.join("vendor")).as_deref() == Some("0x1002") {
                capabilities.insert("rocm-hardware".into());
            }
            if Path::new("/dev/dri").exists() {
                capabilities.insert("drm".into());
            }
        }
        let mut properties = BTreeMap::new();
        for (name, file) in [
            ("vendor_id", "vendor"),
            ("device_id", "device"),
            ("subsystem_vendor_id", "subsystem_vendor"),
            ("subsystem_device_id", "subsystem_device"),
            ("class", "class"),
            ("numa_node", "numa_node"),
            ("current_link_speed", "current_link_speed"),
            ("current_link_width", "current_link_width"),
            ("max_link_speed", "max_link_speed"),
            ("max_link_width", "max_link_width"),
        ] {
            if let Some(value) = read_trim(path.join(file)) {
                properties.insert(name.into(), value);
            }
        }
        if let Some(driver) = link_name(path.join("driver")) {
            properties.insert("driver".into(), driver);
        }
        if let Some(group) = link_name(path.join("iommu_group")) {
            properties.insert("iommu_group".into(), group);
        }
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: None,
            locator,
            kind: if accelerator {
                HardwareKind::Accelerator
            } else {
                HardwareKind::PciDevice
            },
            bus: HardwareBus::Pci,
            vendor: properties.get("vendor_id").cloned(),
            model: properties.get("device_id").cloned(),
            serial_hash: None,
            capabilities,
            properties,
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn usb_parent(name: &str) -> Option<String> {
    let (bus, ports) = name.split_once('-')?;
    let (parent, _) = ports.rsplit_once('.')?;
    Some(format!("{bus}-{parent}"))
}

#[cfg(target_os = "linux")]
fn collect_linux_usb(node_id: &str, out: &mut Vec<HardwareDevice>) -> Result<(), AnyError> {
    let root = Path::new("/sys/bus/usb/devices");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let Some(vendor_id) = read_trim(path.join("idVendor")) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let locator = format!("usb:{name}");
        let mut properties = BTreeMap::from([("vendor_id".into(), vendor_id.clone())]);
        for (key, file) in [
            ("product_id", "idProduct"),
            ("usb_version", "version"),
            ("speed_mbps", "speed"),
            ("bus_number", "busnum"),
            ("device_number", "devnum"),
            ("device_class", "bDeviceClass"),
        ] {
            if let Some(value) = read_trim(path.join(file)) {
                properties.insert(key.into(), value);
            }
        }
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: usb_parent(&name).map(|parent| hardware_id(node_id, &format!("usb:{parent}"))),
            locator,
            kind: HardwareKind::UsbDevice,
            bus: HardwareBus::Usb,
            vendor: read_trim(path.join("manufacturer")).or(Some(vendor_id)),
            model: read_trim(path.join("product"))
                .or_else(|| properties.get("product_id").cloned()),
            serial_hash: serial_hash(read_trim(path.join("serial"))),
            capabilities: BTreeSet::new(),
            properties,
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn block_parent(name: &str) -> Option<&str> {
    if name.starts_with("nvme") {
        name.rsplit_once('p').map(|(parent, _)| parent)
    } else {
        name.trim_end_matches(|character: char| character.is_ascii_digit())
            .ne(name)
            .then(|| name.trim_end_matches(|character: char| character.is_ascii_digit()))
    }
}

#[cfg(target_os = "linux")]
fn storage_bus(name: &str, path: &Path) -> HardwareBus {
    if name.starts_with("nvme") {
        HardwareBus::Nvme
    } else if name.starts_with("vd") {
        HardwareBus::Virtio
    } else if fs::canonicalize(path)
        .ok()
        .is_some_and(|path| path.to_string_lossy().contains("/usb"))
    {
        HardwareBus::Usb
    } else if name.starts_with("sd") {
        HardwareBus::Scsi
    } else {
        HardwareBus::Unknown
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_storage(node_id: &str, out: &mut Vec<HardwareDevice>) -> Result<(), AnyError> {
    let root = Path::new("/sys/class/block");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("loop") || name.starts_with("ram") {
            continue;
        }
        let path = entry.path();
        let partition = path.join("partition").exists();
        let locator = format!("block:{name}");
        let mut properties = BTreeMap::new();
        for (key, file) in [
            ("major_minor", "dev"),
            ("sectors", "size"),
            ("removable", "removable"),
            ("rotational", "queue/rotational"),
            ("logical_block_bytes", "queue/logical_block_size"),
            ("physical_block_bytes", "queue/physical_block_size"),
        ] {
            if let Some(value) = read_trim(path.join(file)) {
                properties.insert(key.into(), value);
            }
        }
        if let Some(sectors) = properties
            .get("sectors")
            .and_then(|value| value.parse::<u64>().ok())
        {
            properties.insert("size_bytes".into(), sectors.saturating_mul(512).to_string());
        }
        let bus = storage_bus(&name, &path);
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: partition
                .then(|| block_parent(&name))
                .flatten()
                .map(|parent| hardware_id(node_id, &format!("block:{parent}"))),
            locator,
            kind: if partition {
                HardwareKind::StorageVolume
            } else {
                HardwareKind::StorageDevice
            },
            bus,
            vendor: read_trim(path.join("device/vendor")),
            model: read_trim(path.join("device/model")).or_else(|| Some(name.clone())),
            serial_hash: serial_hash(read_trim(path.join("device/serial"))),
            capabilities: BTreeSet::new(),
            properties,
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_devices(node_id: &str) -> Result<Vec<HardwareDevice>, AnyError> {
    let output = Command::new("/usr/sbin/system_profiler")
        .args([
            "SPDisplaysDataType",
            "SPPCIDataType",
            "SPUSBDataType",
            "SPNVMeDataType",
            "SPStorageDataType",
            "-json",
            "-detailLevel",
            "mini",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "system_profiler failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    Ok(parse_darwin_profiler(node_id, &value))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_devices(_node_id: &str) -> Result<Vec<HardwareDevice>, AnyError> {
    Ok(Vec::new())
}

#[cfg(target_os = "macos")]
fn parse_darwin_profiler(node_id: &str, root: &serde_json::Value) -> Vec<HardwareDevice> {
    let mut out = Vec::new();
    for (section, kind, bus) in [
        (
            "SPDisplaysDataType",
            HardwareKind::Accelerator,
            HardwareBus::Integrated,
        ),
        ("SPPCIDataType", HardwareKind::PciDevice, HardwareBus::Pci),
        ("SPUSBDataType", HardwareKind::UsbDevice, HardwareBus::Usb),
        (
            "SPNVMeDataType",
            HardwareKind::StorageDevice,
            HardwareBus::Nvme,
        ),
        (
            "SPStorageDataType",
            HardwareKind::StorageVolume,
            HardwareBus::Unknown,
        ),
    ] {
        if let Some(items) = root.get(section).and_then(serde_json::Value::as_array) {
            walk_darwin_items(node_id, section, items, None, kind, bus, &mut out);
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn walk_darwin_items(
    node_id: &str,
    section: &str,
    items: &[serde_json::Value],
    parent: Option<String>,
    default_kind: HardwareKind,
    default_bus: HardwareBus,
    out: &mut Vec<HardwareDevice>,
) {
    for (index, item) in items.iter().enumerate() {
        let Some(fields) = item.as_object() else {
            continue;
        };
        let name = string_field(fields, &["_name", "sppci_model", "device_name"])
            .unwrap_or_else(|| format!("{section}-{index}"));
        let stable = string_field(
            fields,
            &[
                "spusb_location_id",
                "location_id",
                "bsd_name",
                "device_identifier",
            ],
        )
        .unwrap_or_else(|| format!("{parent:?}:{name}:{index}"));
        let locator = format!("darwin:{section}:{stable}");
        let id = hardware_id(node_id, &locator);
        let is_display = section == "SPDisplaysDataType";
        let mut capabilities = BTreeSet::new();
        if is_display {
            capabilities.insert("graphics".into());
            if fields.iter().any(|(key, value)| {
                key.to_ascii_lowercase().contains("metal")
                    || key.to_ascii_lowercase().contains("mtl")
                    || scalar_string(value)
                        .is_some_and(|value| value.to_ascii_lowercase().contains("metal"))
            }) {
                capabilities.insert("metal".into());
            }
        }
        let mut properties = BTreeMap::new();
        for (key, value) in fields {
            if key == "_items" || key.to_ascii_lowercase().contains("serial") {
                continue;
            }
            if let Some(value) = scalar_string(value) {
                properties.insert(key.clone(), value);
            }
        }
        let vendor = string_field(fields, &["spdisplays_vendor", "manufacturer", "vendor"]);
        let model =
            string_field(fields, &["sppci_model", "device_model", "model", "_name"]).or(Some(name));
        let serial = fields
            .iter()
            .find(|(key, _)| key.to_ascii_lowercase().contains("serial"))
            .and_then(|(_, value)| scalar_string(value));
        out.push(HardwareDevice {
            id: id.clone(),
            parent: parent.clone(),
            locator,
            kind: if is_display {
                HardwareKind::Accelerator
            } else {
                default_kind.clone()
            },
            bus: if is_display
                && properties
                    .values()
                    .any(|value| value.to_ascii_lowercase().contains("built-in"))
            {
                HardwareBus::Integrated
            } else {
                default_bus.clone()
            },
            vendor,
            model,
            serial_hash: serial_hash(serial),
            capabilities,
            properties,
        });
        if let Some(children) = fields.get("_items").and_then(serde_json::Value::as_array) {
            walk_darwin_items(
                node_id,
                section,
                children,
                Some(id),
                default_kind.clone(),
                default_bus.clone(),
                out,
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn string_field(
    fields: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    names
        .iter()
        .find_map(|name| fields.get(*name).and_then(scalar_string))
}

#[cfg(target_os = "macos")]
fn scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_ids_are_peer_scoped_and_stable() {
        assert_eq!(
            hardware_id("peer-a", "pci:0000:01:00.0"),
            hardware_id("peer-a", "pci:0000:01:00.0")
        );
        assert_ne!(
            hardware_id("peer-a", "pci:0000:01:00.0"),
            hardware_id("peer-b", "pci:0000:01:00.0")
        );
    }

    #[test]
    fn raw_serials_are_never_retained() {
        let hashed = serial_hash(Some("secret-serial".into())).unwrap();
        assert_eq!(hashed.len(), 64);
        assert!(!hashed.contains("secret-serial"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_integrated_metal_gpu_is_an_accelerator() {
        let report = serde_json::json!({
            "SPDisplaysDataType": [{
                "_name": "Apple M4 Max",
                "sppci_bus": "spdisplays_builtin",
                "spdisplays_vendor": "Apple",
                "spdisplays_mtlgpufamilysupport": "spdisplays_metal4",
                "spdisplays_device-id": "0x0000"
            }]
        });
        let devices = parse_darwin_profiler("peer", &report);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].kind, HardwareKind::Accelerator);
        assert_eq!(devices[0].bus, HardwareBus::Integrated);
        assert!(devices[0].capabilities.contains("metal"));
        assert_eq!(devices[0].model.as_deref(), Some("Apple M4 Max"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_parent_parsers_preserve_bus_topology() {
        assert_eq!(usb_parent("1-2.3"), Some("1-2".into()));
        assert_eq!(usb_parent("1-2"), None);
        assert_eq!(block_parent("nvme0n1p2"), Some("nvme0n1"));
        assert_eq!(block_parent("sda3"), Some("sda"));
        assert_eq!(block_parent("sda"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tpm_observation_does_not_claim_protection() {
        let root = crate::test_dir("tpm-test");
        fs::create_dir_all(root.join("tpm0")).unwrap();
        fs::create_dir_all(root.join("tpm1")).unwrap();
        fs::create_dir_all(root.join("tpmrm0")).unwrap();
        fs::write(root.join("tpm0/tpm_version_major"), "2\n").unwrap();
        let mut devices = Vec::new();
        collect_linux_tpm("peer", &root, &mut devices).unwrap();
        devices.sort_by(|left, right| left.locator.cmp(&right.locator));
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].kind, HardwareKind::SecurityModule);
        assert_eq!(devices[0].properties["tpm_version_major"], "2");
        assert_eq!(devices[1].properties["tpm_version_major"], "unknown");
        assert_eq!(
            devices[0].capabilities,
            BTreeSet::from(["tpm-present".into()])
        );
        assert_eq!(devices[0].properties["key_protection"], "unknown");
        assert_eq!(devices[0].properties["attestation"], "not_verified");
        assert_eq!(devices[0].id, hardware_id("peer", "tpm:tpm0"));
        let mut absent = Vec::new();
        collect_linux_tpm("peer", &root.join("missing"), &mut absent).unwrap();
        assert!(absent.is_empty());
        // A malformed root must surface as an error, not reported absence.
        fs::write(root.join("not-a-directory"), "").unwrap();
        assert!(collect_linux_tpm("peer", &root.join("not-a-directory"), &mut absent).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
