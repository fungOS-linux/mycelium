use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    collect_linux_battery(node_id, Path::new("/sys/class/power_supply"), &mut devices)?;
    collect_linux_bluetooth(node_id, Path::new("/sys/class/bluetooth"), &mut devices)?;
    Ok(devices)
}

/// System batteries and their reported health counters from sysfs.
#[cfg(target_os = "linux")]
fn collect_linux_battery(
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
        let path = entry.path();
        if read_trim(path.join("type")).as_deref() != Some("Battery") {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let locator = format!("power:{name}");
        let mut properties = BTreeMap::new();
        for (key, file) in [
            ("status", "status"),
            ("capacity_percent", "capacity"),
            ("cycle_count", "cycle_count"),
            ("health", "health"),
            ("energy_now", "energy_now"),
            ("energy_full", "energy_full"),
            ("charge_now", "charge_now"),
            ("charge_full", "charge_full"),
            ("voltage_now", "voltage_now"),
            ("power_now", "power_now"),
            ("model_name", "model_name"),
            ("manufacturer", "manufacturer"),
        ] {
            if let Some(value) = read_trim(path.join(file)) {
                properties.insert(key.into(), value);
            }
        }
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: None,
            locator,
            kind: HardwareKind::Battery,
            bus: HardwareBus::Integrated,
            vendor: read_trim(path.join("manufacturer")),
            model: read_trim(path.join("model_name")).or(Some(name.clone())),
            serial_hash: serial_hash(read_trim(path.join("serial_number"))),
            capabilities: BTreeSet::from(["battery".into()]),
            properties,
        });
    }
    Ok(())
}

/// An adapter or connected peripheral observed via sysfs and BlueZ's
/// `bluetoothctl`. Peripheral battery is the controller's own report; it is a
/// discovery hint, not an attestation. Raw Bluetooth addresses are hashed.
#[cfg(target_os = "linux")]
fn collect_linux_bluetooth(
    node_id: &str,
    root: &Path,
    out: &mut Vec<HardwareDevice>,
) -> Result<(), AnyError> {
    // Adapters first, so a host with no peripherals still reports its radio.
    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = entry.path();
                let locator = format!("bluetooth:{}", name.to_ascii_lowercase());
                let mut properties =
                    BTreeMap::from([("transport".into(), "bluetooth".into())]);
                if let Some(address) = read_trim(path.join("address")) {
                    properties.insert("address".into(), address);
                }
                out.push(HardwareDevice {
                    id: hardware_id(node_id, &locator),
                    parent: None,
                    locator,
                    kind: HardwareKind::BluetoothDevice,
                    bus: HardwareBus::Bluetooth,
                    vendor: None,
                    model: Some(name.clone()),
                    serial_hash: None,
                    capabilities: BTreeSet::from(["wireless".into()]),
                    properties,
                });
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    // `bluetoothctl` is optional. Absence is normal on headless images and is
    // not an error; the adapter records above remain.
    let mut listed = bluetoothctl(&["devices", "Connected"])
        .map(|text| parse_bluetoothctl_device_list(&text))
        .unwrap_or_default();
    if listed.is_empty() {
        // Older BlueZ builds do not accept the `Connected` filter; fall back to
        // the full known-device list and trust each `info` connection flag.
        listed = bluetoothctl(&["devices"])
            .map(|text| parse_bluetoothctl_device_list(&text))
            .unwrap_or_default();
    }
    listed.truncate(64);
    for (address, label) in listed {
        let Some(info) = bluetoothctl(&["info", &address])
            .map(|text| parse_bluetoothctl_info(&text))
        else {
            continue;
        };
        if !info.connected {
            continue;
        }
        out.push(bluetooth_peripheral(node_id, &address, Some(label), &info));
    }
    Ok(())
}

/// Build a peripheral device record from parsed `bluetoothctl info` output.
/// Kept separate so the construction is type-checked and tested on every host.
#[cfg(any(target_os = "linux", test))]
fn bluetooth_peripheral(
    node_id: &str,
    address: &str,
    label: Option<String>,
    info: &BluetoothInfo,
) -> HardwareDevice {
    let locator = format!("bluetooth:{}", address.to_ascii_lowercase());
    let mut properties = BTreeMap::from([
        ("transport".into(), "bluetooth".into()),
        ("connected".into(), "true".into()),
    ]);
    if let Some(icon) = &info.icon {
        properties.insert("icon".into(), icon.clone());
    }
    if let Some(alias) = &info.alias {
        properties.insert("alias".into(), alias.clone());
    }
    if let Some(paired) = info.paired {
        properties.insert("paired".into(), paired.to_string());
    }
    if let Some(percent) = info.battery_percent {
        properties.insert("battery_percent".into(), percent.to_string());
    }
    let mut capabilities = BTreeSet::from(["wireless".to_string()]);
    if info.battery_percent.is_some() {
        capabilities.insert("battery-reported".into());
    }
    HardwareDevice {
        id: hardware_id(node_id, &locator),
        parent: None,
        locator,
        kind: HardwareKind::BluetoothDevice,
        bus: HardwareBus::Bluetooth,
        vendor: None,
        model: info
            .alias
            .clone()
            .or_else(|| info.name.clone())
            .or(label)
            .or_else(|| Some(address.to_string())),
        serial_hash: Some(sha256_hex(address.as_bytes())),
        capabilities,
        properties,
    }
}

#[cfg(target_os = "linux")]
fn bluetoothctl(args: &[&str]) -> Option<String> {
    // `--timeout` bounds a wedged or absent bluetoothd. An older build that
    // rejects the flag exits non-zero and we simply skip.
    let mut command = Command::new("bluetoothctl");
    command.args(["--timeout", "3"]).args(args);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(strip_ansi(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(any(target_os = "linux", test))]
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\u{1b}' {
            out.push(character);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }
    out
}

/// `Device AA:BB:CC:DD:EE:FF Name` lines from `bluetoothctl devices`.
#[cfg(any(target_os = "linux", test))]
fn parse_bluetoothctl_device_list(text: &str) -> Vec<(String, String)> {
    let mut devices = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let mut fields = line.splitn(3, char::is_whitespace);
        if fields.next() != Some("Device") {
            continue;
        }
        let Some(address) = fields.next().map(str::trim).filter(|value| !value.is_empty())
        else {
            continue;
        };
        let label = fields.next().unwrap_or("").trim().to_string();
        devices.push((address.to_string(), label));
    }
    devices
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BluetoothInfo {
    name: Option<String>,
    alias: Option<String>,
    icon: Option<String>,
    connected: bool,
    paired: Option<bool>,
    battery_percent: Option<u8>,
}

/// Parse the `key: value` block from `bluetoothctl info <addr>`.
#[cfg(any(target_os = "linux", test))]
fn parse_bluetoothctl_info(text: &str) -> BluetoothInfo {
    let mut info = BluetoothInfo::default();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" => info.name = Some(value.to_string()),
            "Alias" => info.alias = Some(value.to_string()),
            "Icon" => info.icon = Some(value.to_string()),
            "Connected" => info.connected = value.eq_ignore_ascii_case("yes"),
            "Paired" => info.paired = Some(value.eq_ignore_ascii_case("yes")),
            "Battery Percentage" => info.battery_percent = parse_battery_percent(value),
            _ => {}
        }
    }
    info
}

/// BlueZ prints either `75`, `0x4B`, or `0x4B (75)` depending on version.
#[cfg(any(target_os = "linux", test))]
fn parse_battery_percent(value: &str) -> Option<u8> {
    if let Some(open) = value.rfind('(') {
        if let Some(close) = value[open + 1..].find(')') {
            if let Ok(percent) = value[open + 1..open + 1 + close].trim().parse::<u8>() {
                return (percent <= 100).then_some(percent);
            }
        }
    }
    let value = value.split_whitespace().next()?;
    let percent = if let Some(hex) = value.strip_prefix("0x") {
        u8::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u8>().ok()?
    };
    (percent <= 100).then_some(percent)
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
            "SPBluetoothDataType",
            "SPPowerDataType",
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
    parse_darwin_bluetooth(node_id, root, &mut out);
    parse_darwin_power(node_id, root, &mut out);
    out
}

/// BLE/Bluetooth peripherals from `system_profiler`. Battery level is a hint,
/// not an attestation: it is the controller's own report.
#[cfg(target_os = "macos")]
fn parse_darwin_bluetooth(
    node_id: &str,
    root: &serde_json::Value,
    out: &mut Vec<HardwareDevice>,
) {
    let Some(controllers) = root
        .get("SPBluetoothDataType")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for controller in controllers {
        let Some(fields) = controller.as_object() else {
            continue;
        };
        for key in ["device_connected", "device_not_connected"] {
            let connected = key == "device_connected";
            let Some(devices) = fields.get(key).and_then(serde_json::Value::as_array) else {
                continue;
            };
            for entry in devices {
                let Some(entry) = entry.as_object() else {
                    continue;
                };
                for (name, details) in entry {
                    let details = details.as_object();
                    let address = details.and_then(|fields| {
                        string_field(fields, &["device_address", "device_addressString"])
                    });
                    let locator = format!(
                        "darwin:bluetooth:{}",
                        address.clone().unwrap_or_else(|| name.clone())
                    );
                    let mut properties = BTreeMap::from([
                        ("connected".into(), connected.to_string()),
                        ("transport".into(), "bluetooth".into()),
                    ]);
                    if let Some(details) = details {
                        for (field, label) in [
                            ("device_batteryLevel", "battery_percent"),
                            ("device_batteryLevelCase", "case_battery_percent"),
                            ("device_minorType", "minor_type"),
                            ("device_manufacturer", "manufacturer"),
                        ] {
                            if let Some(value) = string_field(details, &[field]) {
                                properties.insert(label.to_string(), value);
                            }
                        }
                    }
                    let mut capabilities = BTreeSet::from(["wireless".to_string()]);
                    if details
                        .and_then(|fields| string_field(fields, &["device_batteryLevel"]))
                        .is_some()
                    {
                        capabilities.insert("battery-reported".into());
                    }
                    out.push(HardwareDevice {
                        id: hardware_id(node_id, &locator),
                        parent: None,
                        locator,
                        kind: HardwareKind::BluetoothDevice,
                        bus: HardwareBus::Bluetooth,
                        vendor: details
                            .and_then(|fields| string_field(fields, &["device_manufacturer"])),
                        model: Some(name.clone()),
                        serial_hash: address.map(|value| sha256_hex(value.as_bytes())),
                        capabilities,
                        properties,
                    });
                }
            }
        }
    }
}

/// The system battery and its reported health counters.
#[cfg(target_os = "macos")]
fn parse_darwin_power(
    node_id: &str,
    root: &serde_json::Value,
    out: &mut Vec<HardwareDevice>,
) {
    let Some(items) = root
        .get("SPPowerDataType")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    for item in items {
        let Some(fields) = item.as_object() else {
            continue;
        };
        let info = fields
            .get("sppower_battery_health_info")
            .and_then(serde_json::Value::as_object);
        let model = fields
            .get("sppower_battery_model_info")
            .and_then(serde_json::Value::as_object);
        let device_name = model
            .and_then(|fields| string_field(fields, &["sppower_battery_model", "_name"]))
            .unwrap_or_else(|| "battery".into());
        let serial = model.and_then(|fields| {
            string_field(fields, &["sppower_battery_serial_number", "sppower_battery_serial"])
        });
        let locator = format!("darwin:power:{device_name}");
        let mut properties = BTreeMap::from([("source".into(), "system_profiler".into())]);
        if let Some(info) = info {
            for (field, label) in [
                ("sppower_battery_cycle_count", "cycle_count"),
                ("sppower_battery_health", "health"),
                ("sppower_battery_charge_capacity", "charge_capacity"),
                ("sppower_battery_full_charge_capacity", "full_charge_capacity"),
            ] {
                if let Some(value) = string_field(info, &[field]) {
                    properties.insert(label.to_string(), value);
                }
            }
        }
        out.push(HardwareDevice {
            id: hardware_id(node_id, &locator),
            parent: None,
            locator,
            kind: HardwareKind::Battery,
            bus: HardwareBus::Integrated,
            vendor: None,
            model: Some(device_name),
            serial_hash: serial.map(|value| sha256_hex(value.as_bytes())),
            capabilities: BTreeSet::from(["battery".into()]),
            properties,
        });
    }
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
        let root = std::env::temp_dir().join(format!(
            "mycelium-tpm-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_bluetooth_and_battery_are_discovered() {
        let report = serde_json::json!({
            "SPBluetoothDataType": [{
                "device_connected": [{
                    "Magic Trackpad": {
                        "device_address": "AA:BB:CC:DD:EE:FF",
                        "device_batteryLevel": "64%",
                        "device_minorType": "Trackpad"
                    }
                }],
                "device_not_connected": []
            }],
            "SPPowerDataType": [{
                "sppower_battery_health_info": {
                    "sppower_battery_cycle_count": "123",
                    "sppower_battery_health": "Good"
                },
                "sppower_battery_model_info": {
                    "sppower_battery_model": "bq20z451",
                    "sppower_battery_serial_number": "SECRET-BATTERY"
                }
            }]
        });
        let devices = parse_darwin_profiler("peer", &report);
        let trackpad = devices
            .iter()
            .find(|device| device.kind == HardwareKind::BluetoothDevice)
            .expect("bluetooth device");
        assert_eq!(trackpad.bus, HardwareBus::Bluetooth);
        assert_eq!(trackpad.model.as_deref(), Some("Magic Trackpad"));
        assert_eq!(trackpad.properties["connected"], "true");
        assert_eq!(trackpad.properties["battery_percent"], "64%");
        assert!(trackpad.capabilities.contains("battery-reported"));
        // The Bluetooth address is hashed, never gossiped raw.
        assert!(trackpad.serial_hash.is_some());
        assert!(!trackpad.properties.values().any(|v| v.contains("AA:BB")));
        let battery = devices
            .iter()
            .find(|device| device.kind == HardwareKind::Battery)
            .expect("battery device");
        assert_eq!(battery.properties["cycle_count"], "123");
        assert_eq!(battery.properties["health"], "Good");
        assert!(battery.serial_hash.as_deref().is_some_and(|h| h != "SECRET-BATTERY"));
    }

    #[test]
    fn bluetoothctl_lists_and_parses_connected_peripherals() {
        let listed = parse_bluetoothctl_device_list(
            "Device AA:BB:CC:DD:EE:FF Magic Trackpad\nDevice 11:22:33:44:55:66 Keyboard\n",
        );
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, "AA:BB:CC:DD:EE:FF");
        assert_eq!(listed[0].1, "Magic Trackpad");

        // Newer BlueZ hex+decimal form.
        let info = parse_bluetoothctl_info(
            "Device AA:BB:CC:DD:EE:FF (public)\n\tName: Trackpad\n\tAlias: Magic Trackpad\n\tIcon: input-mouse\n\tPaired: yes\n\tConnected: yes\n\tBattery Percentage: 0x4B (75)\n",
        );
        assert_eq!(info.name.as_deref(), Some("Trackpad"));
        assert_eq!(info.alias.as_deref(), Some("Magic Trackpad"));
        assert_eq!(info.icon.as_deref(), Some("input-mouse"));
        assert!(info.connected);
        assert_eq!(info.paired, Some(true));
        assert_eq!(info.battery_percent, Some(75));

        // Older plain percentage and a disconnected device.
        let info = parse_bluetoothctl_info(
            "Device 11:22:33:44:55:66\n\tName: Keyboard\n\tConnected: no\n\tBattery Percentage: 40\n",
        );
        assert!(!info.connected);
        assert_eq!(info.battery_percent, Some(40));

        assert_eq!(parse_battery_percent("0x64 (100)"), Some(100));
        assert_eq!(parse_battery_percent("0xFF (255)"), None);
        assert_eq!(strip_ansi("\u{1b}[0;94mDevice\u{1b}[0m AA"), "Device AA");

        let info = parse_bluetoothctl_info(
            "Device AA:BB:CC:DD:EE:FF\n\tAlias: Magic Trackpad\n\tIcon: input-mouse\n\tConnected: yes\n\tBattery Percentage: 0x4B (75)\n",
        );
        let device = bluetooth_peripheral(
            "peer",
            "AA:BB:CC:DD:EE:FF",
            Some("Trackpad".into()),
            &info,
        );
        assert_eq!(device.kind, HardwareKind::BluetoothDevice);
        assert_eq!(device.bus, HardwareBus::Bluetooth);
        assert_eq!(device.model.as_deref(), Some("Magic Trackpad"));
        assert_eq!(device.properties["battery_percent"], "75");
        assert_eq!(device.properties["icon"], "input-mouse");
        assert!(device.capabilities.contains("battery-reported"));
        // Address is hashed, never stored raw in the gossiped record.
        assert!(device.serial_hash.as_deref().is_some_and(|hash| hash.len() == 64));
        assert!(!device.properties.values().any(|value| value.contains("AA:BB")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_battery_is_discovered_without_a_device_file() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-battery-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("BAT0")).unwrap();
        fs::write(root.join("BAT0/type"), "Battery\n").unwrap();
        fs::write(root.join("BAT0/capacity"), "77\n").unwrap();
        fs::write(root.join("BAT0/status"), "Discharging\n").unwrap();
        fs::write(root.join("BAT0/cycle_count"), "42\n").unwrap();
        let mut devices = Vec::new();
        collect_linux_battery("peer", &root, &mut devices).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].kind, HardwareKind::Battery);
        assert_eq!(devices[0].properties["capacity_percent"], "77");
        assert_eq!(devices[0].properties["status"], "Discharging");
        assert_eq!(devices[0].properties["cycle_count"], "42");
        fs::remove_dir_all(&root).unwrap();
    }
}
