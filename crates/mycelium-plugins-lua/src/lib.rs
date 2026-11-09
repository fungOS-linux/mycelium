//! Lua plugin host for mycelium.
//!
//! # The ABI (one-way door, see docs/adr/0002)
//!
//! A plugin file defines a single global table:
//!
//! ```lua
//! plugin = {
//!   name  = "er-dns",           -- unique id; the driver is `lua:er-dns`
//!   kind  = "dns-filter",       -- router|switch|access-point|bmc|dns-filter|other
//!   match = function(target)    -- optional: {address="10.0.7.1", port=22} -> bool
//!     return target.address:match("^10%.") ~= nil
//!   end,
//!   capabilities = function()   -- called once at attach; declared data
//!     return {
//!       { id = "system.identify", description = "who am I", mutation = false,
//!         returns = "map {vendor, model, firmware, hostname}" },
//!       { id = "dns.block", description = "sinkhole a domain", mutation = true,
//!         params = { { name = "domain", ty = "string", docs = "e.g. ads.example" } } },
//!     }
//!   end,
//!   exec = function(cap, params, ctx)
//!     -- ctx   = { dry_run = bool, device = { id, kind, address } }
//!     -- pure:            return { result = <json value> }
//!     -- device work:     return { commands = { "show …" }, parse = "parse_fn" }
//!     -- opt-out of fail-on-nonzero: { ignore_errors = true }
//!   end,
//!   parse_fn = function(outputs, params)   -- named by `parse`
//!     return { result = … }
//!   end,
//!   probe = function(target)               -- optional, paired with recognize
//!     return { commands = {
//!       { program = "vendor-info", args = { "--json" }, decode = "json" }
//!     } }
//!   end,
//!   recognize = function(outputs, target)  -- pure recognition decision
//!     return outputs[1].product == "expected"
//!   end,
//! }
//! ```
//!
//! Plugins never touch sockets, files, or the wall clock: they *declare*
//! commands, and the Rust host runs them through a [`Transport`] — after
//! the write-gate/dry-run checks in `core::Device::invoke`, which every
//! plugin call passes through. Dynamic arguments use structured command
//! declarations and are quoted by Rust. Host decoders (`json`, `lines`, and
//! `key_value`) enforce output, depth, and node bounds before Lua sees data.
//! Control flow stays deterministic (tenet #7); the sandbox removes
//! os/io/debug/require (defense in depth).
//!
//! Pure device classifiers use a separate, smaller table:
//!
//! ```lua
//! classifier = {
//!   name = "snmp-system",
//!   classify = function(evidence) -- {source, address, facts}
//!     return { kind = "switch", vendor = "NETGEAR" } -- or nil
//!   end,
//! }
//! ```

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use mlua::{serde::LuaSerdeExt, FromLua, IntoLua, Lua, Table, Value as LuaValue};
use mycelium_core::{
    CapResult, CapSpec, CredentialSet, Device, DeviceClassification, DeviceClassifier, DeviceId,
    DeviceIdentityEvidence, DeviceKind, DeviceMeta, DiscoveredDevice, Driver, ExecContext,
    Inventory, MyceliumError, Params, Result, ServiceAdvertisement, Target, Transport, Value,
    ID_IDENTIFY,
};
use serde::Deserialize;
use tokio::sync::Mutex;

pub const BAMBU_RECOGNIZER: &str = include_str!("../recognizers/bambu.lua");
pub const HOMEKIT_RECOGNIZER: &str = include_str!("../recognizers/homekit.lua");
pub const AIRPLAY_RECOGNIZER: &str = include_str!("../recognizers/airplay.lua");
pub const PRINT_SCAN_RECOGNIZER: &str = include_str!("../recognizers/print_scan.lua");
pub const UNIFI_AP_PLUGIN: &str = include_str!("../plugins/unifi_ap.lua");
pub const SNMP_CLASSIFIER: &str = include_str!("../classifiers/snmp.lua");

const MAX_COMMANDS: usize = 32;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 65_536;

/// Built-ins are data interpreted through the same bounded interface as
/// operator-installed recognizers. The tuple label makes startup diagnostics
/// useful even when a script cannot be loaded far enough to expose its name.
pub const BUILTIN_RECOGNIZERS: &[(&str, &str)] = &[
    ("bambu-lan", BAMBU_RECOGNIZER),
    ("homekit", HOMEKIT_RECOGNIZER),
    ("airplay", AIRPLAY_RECOGNIZER),
    ("print-scan", PRINT_SCAN_RECOGNIZER),
];

/// JSON<->Lua bridge: serde_json::Value is *the* wire format at this seam,
/// so plugin authors see plain objects, never Rust enum tag noise.
struct JsonBridge(serde_json::Value);

impl IntoLua for JsonBridge {
    fn into_lua(self, lua: &Lua) -> mlua::Result<LuaValue> {
        use serde::Serialize;
        self.0.serialize(mlua::serde::Serializer::new(lua))
    }
}

impl FromLua for JsonBridge {
    fn from_lua(value: LuaValue, _lua: &Lua) -> mlua::Result<Self> {
        use serde::Deserialize;
        serde_json::Value::deserialize(mlua::serde::Deserializer::new(value)).map(JsonBridge)
    }
}

impl JsonBridge {
    fn to_core(v: &serde_json::Value) -> Value {
        Value::from_json(v)
    }
}

fn err(plugin: &str, e: &mlua::Error) -> MyceliumError {
    MyceliumError::Plugin { plugin: plugin.to_owned(), message: e.to_string() }
}

/// Fresh sandboxed instance with the plugin chunk executed. One per open
/// device: `mlua::Lua` is not shareable across threads, and per-device
/// globals keep plugin state from bleeding between appliances.
fn instantiate(source: &str, name: &str) -> Result<Lua> {
    instantiate_inner(source, name, false)
}

fn instantiate_inner(source: &str, name: &str, bounded: bool) -> Result<Lua> {
    let lua = Lua::new();
    if bounded {
        lua.set_memory_limit(8 * 1024 * 1024)
            .map_err(|e| err(name, &e))?;
        let ticks = std::sync::atomic::AtomicUsize::new(0);
        lua.set_hook(
            mlua::HookTriggers::new().every_nth_instruction(1000),
            move |_, _| {
                if ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 200 {
                    return Err(mlua::Error::RuntimeError(
                        "service provider instruction budget exceeded".into(),
                    ));
                }
                Ok(mlua::VmState::Continue)
            },
        )
        .map_err(|e| err(name, &e))?;
    }
    {
        // Remove dangerous stdlib entries before loading user code.
        const DANGEROUS: &[&str] =
            &["os", "io", "debug", "load", "dofile", "loadfile", "require", "package"];
        let keys: Vec<LuaValue> = lua
            .globals()
            .pairs::<LuaValue, LuaValue>()
            .filter_map(|kv| kv.ok())
            .map(|(k, _)| k)
            .collect();
        for k in keys {
            if let LuaValue::String(s) = &k {
                if DANGEROUS.contains(&s.to_string_lossy().as_str()) {
                    let _ = lua.globals().set(s.clone(), LuaValue::Nil);
                }
            }
        }
    }
    let chunk = lua.load(source).set_name(name).into_function().map_err(|e| err(name, &e))?;
    chunk.call::<()>(()).map_err(|e| err(name, &e))?;
    Ok(lua)
}

fn plugin_table(lua: &Lua, name: &str) -> Result<Table> {
    lua.globals().get::<Table>("plugin").map_err(|e| err(name, &e))
}

/// A validated plugin, ready to open devices. Validation happens at load
/// (fail loud at boot, not at first use).
pub struct Plugin {
    pub name: String,
    pub kind: DeviceKind,
    pub source: Arc<str>,
    has_match: bool,
    has_probe: bool,
}

impl Plugin {
    pub fn load(source: impl Into<Arc<str>>) -> Result<Self> {
        let source: Arc<str> = source.into();
        let lua = instantiate(&source, "<new>")?;
        let plugin = plugin_table(&lua, "<new>")?;
        let get_str = |key: &str| -> Result<String> {
            plugin.get::<String>(key).map_err(|_| MyceliumError::Plugin {
                plugin: "<new>".into(),
                message: format!("`plugin.{key}` must be a string"),
            })
        };
        let name = get_str("name")?;
        let kind_s = get_str("kind")?;
        let kind = serde_json::from_value::<DeviceKind>(serde_json::Value::String(kind_s.clone()))
            .map_err(|_| MyceliumError::Plugin {
                plugin: name.clone(),
                message: format!("unknown plugin.kind `{kind_s}`"),
            })?;
        for f in ["capabilities", "exec"] {
            if plugin.get::<mlua::Function>(f).is_err() {
                return Err(MyceliumError::Plugin {
                    plugin: name.clone(),
                    message: format!("`plugin.{f}` must be a function"),
                });
            }
        }
        let has_match = plugin.get::<mlua::Function>("match").is_ok();
        let has_probe = plugin.get::<mlua::Function>("probe").is_ok();
        let has_recognize = plugin.get::<mlua::Function>("recognize").is_ok();
        if has_probe != has_recognize {
            return Err(MyceliumError::Plugin {
                plugin: name,
                message: "`plugin.probe` and `plugin.recognize` must be declared together".into(),
            });
        }
        Ok(Self {
            name,
            kind,
            source,
            has_match,
            has_probe,
        })
    }

    pub fn driver(self: Arc<Self>, connect: Arc<dyn Connect>) -> LuaDriver {
        LuaDriver::new(self, connect)
    }

    /// Preserve a stable public driver name for a built-in dialect while
    /// operator-installed plugins continue to use `lua:<plugin>` names.
    pub fn driver_named(
        self: Arc<Self>,
        driver_name: impl Into<String>,
        connect: Arc<dyn Connect>,
    ) -> LuaDriver {
        LuaDriver::new_named(self, connect, driver_name.into())
    }

    fn declared_caps(&self, lua: &Lua) -> Result<BTreeMap<String, CapSpec>> {
        let plugin = plugin_table(lua, &self.name)?;
        let f: mlua::Function = plugin.get("capabilities").expect("validated at load");
        let out: LuaValue = f.call(()).map_err(|e| err(&self.name, &e))?;
        let json: serde_json::Value =
            lua.from_value(out).map_err(|e| err(&self.name, &e))?;
        let specs: Vec<CapSpec> = serde_json::from_value(json).map_err(|e| {
            MyceliumError::Plugin {
                plugin: self.name.clone(),
                message: format!("capabilities() must return declared CapSpec rows: {e}"),
            }
        })?;
        let mut map = BTreeMap::new();
        for mut spec in specs {
            if spec.id.is_empty() {
                return Err(MyceliumError::Plugin {
                    plugin: self.name.clone(),
                    message: "every declared capability needs an `id`".into(),
                });
            }
            let id = std::mem::take(&mut spec.id);
            map.insert(id, spec);
        }
        Ok(map)
    }
}

/// A pure advertisement-to-device recognizer. It shares the Lua sandbox with
/// drivers but has no connector, transport, filesystem, socket, or clock.
pub struct AdvertisementRecognizer {
    pub name: String,
    source: Arc<str>,
}

impl AdvertisementRecognizer {
    pub fn load(source: impl Into<Arc<str>>) -> Result<Self> {
        let source = source.into();
        let lua = instantiate(&source, "<recognizer>")?;
        let table = lua
            .globals()
            .get::<Table>("recognizer")
            .map_err(|error| err("<recognizer>", &error))?;
        let name = table
            .get::<String>("name")
            .map_err(|_| MyceliumError::Plugin {
                plugin: "<recognizer>".into(),
                message: "`recognizer.name` must be a string".into(),
            })?;
        if table.get::<mlua::Function>("recognize").is_err() {
            return Err(MyceliumError::Plugin {
                plugin: name,
                message: "`recognizer.recognize` must be a function".into(),
            });
        }
        Ok(Self { name, source })
    }

    pub fn recognize(
        &self,
        advertisement: &ServiceAdvertisement,
    ) -> Result<Option<DiscoveredDevice>> {
        let lua = instantiate(&self.source, &self.name)?;
        let table = lua
            .globals()
            .get::<Table>("recognizer")
            .map_err(|error| err(&self.name, &error))?;
        let function: mlua::Function = table.get("recognize").expect("validated at load");
        let mut input = serde_json::to_value(advertisement)
            .map_err(|error| MyceliumError::Parse(error.to_string()))?;
        if let Some(object) = input.as_object_mut() {
            let txt = advertisement
                .txt
                .iter()
                .filter_map(|item| item.split_once('='))
                .map(|(key, value)| (key.to_owned(), serde_json::Value::String(value.to_owned())))
                .collect();
            object.insert("txt_map".into(), serde_json::Value::Object(txt));
        }
        let output: LuaValue = function
            .call(JsonBridge(input))
            .map_err(|error| err(&self.name, &error))?;
        if matches!(output, LuaValue::Nil) {
            return Ok(None);
        }
        let json: serde_json::Value = lua
            .from_value(output)
            .map_err(|error| err(&self.name, &error))?;
        let mut device: DiscoveredDevice =
            serde_json::from_value(json).map_err(|error| MyceliumError::Plugin {
                plugin: self.name.clone(),
                message: format!("recognize() returned an invalid discovered device: {error}"),
            })?;
        validate_recognition(&self.name, &device)?;
        device.observed_at = advertisement.last_seen;
        if device.addresses.is_empty() {
            device.addresses.clone_from(&advertisement.addresses);
        }
        Ok(Some(device))
    }
}

fn validate_recognition(name: &str, device: &DiscoveredDevice) -> Result<()> {
    if device.stable_id.trim().is_empty()
        || device.stable_id.len() > 256
        || device.name.len() > 256
        || device.kind.trim().is_empty()
        || device.kind.len() > 128
        || device.attributes.len() > 64
        || device.services.len() > 32
        || device
            .services
            .iter()
            .any(|service| service.name.trim().is_empty() || service.port == 0)
    {
        return Err(MyceliumError::Plugin {
            plugin: name.into(),
            message: "recognition exceeds identity, attribute, or service bounds".into(),
        });
    }
    Ok(())
}

/// A pure evidence classifier. It shares the sandbox but has no connector,
/// transport, filesystem, socket, clock, or access to credentials.
pub struct LuaDeviceClassifier {
    pub name: String,
    source: Arc<str>,
}

impl LuaDeviceClassifier {
    pub fn load(source: impl Into<Arc<str>>) -> Result<Self> {
        let source = source.into();
        let lua = instantiate(&source, "<classifier>")?;
        let table = lua
            .globals()
            .get::<Table>("classifier")
            .map_err(|error| err("<classifier>", &error))?;
        let name = table
            .get::<String>("name")
            .map_err(|_| MyceliumError::Plugin {
                plugin: "<classifier>".into(),
                message: "`classifier.name` must be a string".into(),
            })?;
        if table.get::<mlua::Function>("classify").is_err() {
            return Err(MyceliumError::Plugin {
                plugin: name,
                message: "`classifier.classify` must be a function".into(),
            });
        }
        Ok(Self { name, source })
    }
}

impl DeviceClassifier for LuaDeviceClassifier {
    fn classify(&self, evidence: &DeviceIdentityEvidence) -> Result<Option<DeviceClassification>> {
        if evidence.source.len() > 128
            || evidence.address.len() > 256
            || evidence.facts.len() > 64
            || evidence
                .facts
                .iter()
                .any(|(key, value)| key.len() > 128 || value.len() > 4096)
        {
            return Err(MyceliumError::Plugin {
                plugin: self.name.clone(),
                message: "classification evidence exceeds bounds".into(),
            });
        }
        let lua = instantiate(&self.source, &self.name)?;
        let table = lua
            .globals()
            .get::<Table>("classifier")
            .map_err(|error| err(&self.name, &error))?;
        let function: mlua::Function = table.get("classify").expect("validated at load");
        let input = serde_json::to_value(evidence)
            .map_err(|error| MyceliumError::Parse(error.to_string()))?;
        let output: LuaValue = function
            .call(JsonBridge(input))
            .map_err(|error| err(&self.name, &error))?;
        if matches!(output, LuaValue::Nil) {
            return Ok(None);
        }
        let json: serde_json::Value = lua
            .from_value(output)
            .map_err(|error| err(&self.name, &error))?;
        let classification: DeviceClassification =
            serde_json::from_value(json).map_err(|error| MyceliumError::Plugin {
                plugin: self.name.clone(),
                message: format!("classify() returned invalid identity: {error}"),
            })?;
        for value in [
            classification.vendor.as_deref(),
            classification.model.as_deref(),
            classification.stable_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(MyceliumError::Plugin {
                    plugin: self.name.clone(),
                    message: "classification identity fields must be 1-256 bytes".into(),
                });
            }
        }
        Ok(Some(classification))
    }
}

/// Opens transports for plugin devices. The daemon injects real
/// connectables (SSH etc.); tests inject canned transports.
#[async_trait]
pub trait Connect: Send + Sync {
    async fn connect(&self, target: &Target, creds: &CredentialSet) -> Result<Arc<dyn Transport>>;
}

/// Blanket: plain async closures work as connectors.
#[async_trait]
impl<F, Fut> Connect for F
where
    F: Fn(Target, CredentialSet) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Arc<dyn Transport>>> + Send,
{
    async fn connect(&self, target: &Target, creds: &CredentialSet) -> Result<Arc<dyn Transport>> {
        (self)(target.clone(), creds.clone()).await
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutputDecoder {
    #[default]
    Raw,
    Json,
    Lines,
    KeyValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredCommand {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    decode: OutputDecoder,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedRawCommand {
    command: String,
    #[serde(default)]
    decode: OutputDecoder,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CommandDeclaration {
    Raw(String),
    Structured(StructuredCommand),
    DecodedRaw(DecodedRawCommand),
}

#[derive(Debug)]
struct PlannedCommand {
    rendered: String,
    decode: OutputDecoder,
}

fn target_json(target: &Target) -> serde_json::Value {
    match target {
        Target::Host { host, port, jump } => serde_json::json!({
            "address": host,
            "port": port.unwrap_or(0),
            "jump": jump,
        }),
        Target::Subnet { network } => serde_json::json!({"subnet": network}),
    }
}

fn shell_quote(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "'\\''"))
}

fn commands_from_plan(plugin: &str, plan: &serde_json::Value) -> Result<Vec<PlannedCommand>> {
    let Some(commands) = plan.get("commands") else {
        return Ok(Vec::new());
    };
    let declarations: Vec<CommandDeclaration> =
        serde_json::from_value(commands.clone()).map_err(|error| MyceliumError::Plugin {
            plugin: plugin.into(),
            message: format!("commands must be strings or structured command objects: {error}"),
        })?;
    if declarations.len() > MAX_COMMANDS {
        return Err(MyceliumError::Plugin {
            plugin: plugin.into(),
            message: format!("command plan exceeds the {MAX_COMMANDS}-command limit"),
        });
    }
    declarations
        .into_iter()
        .map(|declaration| match declaration {
            CommandDeclaration::Raw(command) => {
                if command.is_empty() || command.len() > MAX_ARGUMENT_BYTES * 4 {
                    return Err(MyceliumError::Plugin {
                        plugin: plugin.into(),
                        message: "raw command is empty or exceeds the command-size limit".into(),
                    });
                }
                Ok(PlannedCommand {
                    rendered: command,
                    decode: OutputDecoder::Raw,
                })
            }
            CommandDeclaration::DecodedRaw(command) => {
                if command.command.is_empty() || command.command.len() > MAX_ARGUMENT_BYTES * 4 {
                    return Err(MyceliumError::Plugin {
                        plugin: plugin.into(),
                        message: "raw command is empty or exceeds the command-size limit".into(),
                    });
                }
                Ok(PlannedCommand {
                    rendered: command.command,
                    decode: command.decode,
                })
            }
            CommandDeclaration::Structured(command) => {
                let safe_program = !command.program.is_empty()
                    && command.program.len() <= 256
                    && command.program.chars().all(|character| {
                        character.is_ascii_alphanumeric()
                            || matches!(character, '/' | '_' | '-' | '.')
                    });
                let safe_arguments = command.args.len() <= MAX_ARGUMENTS
                    && command.args.iter().all(|argument| {
                        argument.len() <= MAX_ARGUMENT_BYTES
                            && !argument.contains(['\0', '\r', '\n'])
                    });
                if !safe_program || !safe_arguments {
                    return Err(MyceliumError::Plugin {
                        plugin: plugin.into(),
                        message: "structured command exceeds program or argument bounds".into(),
                    });
                }
                let mut rendered = command.program;
                for argument in command.args {
                    rendered.push(' ');
                    rendered.push_str(&shell_quote(&argument));
                }
                Ok(PlannedCommand {
                    rendered,
                    decode: command.decode,
                })
            }
        })
        .collect()
}

fn validate_json_bounds(value: &serde_json::Value) -> bool {
    fn visit(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if depth > MAX_JSON_DEPTH || *nodes > MAX_JSON_NODES {
            return false;
        }
        match value {
            serde_json::Value::Array(values) => {
                values.iter().all(|value| visit(value, depth + 1, nodes))
            }
            serde_json::Value::Object(values) => {
                values.values().all(|value| visit(value, depth + 1, nodes))
            }
            _ => true,
        }
    }
    visit(value, 0, &mut 0)
}

fn decode_output(plugin: &str, decoder: OutputDecoder, output: &str) -> Result<serde_json::Value> {
    match decoder {
        OutputDecoder::Raw => Ok(serde_json::Value::String(output.to_owned())),
        OutputDecoder::Lines => Ok(serde_json::Value::Array(
            output
                .lines()
                .map(|line| serde_json::Value::String(line.to_owned()))
                .collect(),
        )),
        OutputDecoder::KeyValue => Ok(serde_json::Value::Object(
            output
                .lines()
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| {
                    (
                        key.trim().to_ascii_lowercase().replace(' ', "_"),
                        serde_json::Value::String(value.trim().to_owned()),
                    )
                })
                .filter(|(key, value)| !key.is_empty() && value.as_str() != Some(""))
                .collect(),
        )),
        OutputDecoder::Json => {
            let value: serde_json::Value =
                serde_json::from_str(output).map_err(|error| MyceliumError::Plugin {
                    plugin: plugin.into(),
                    message: format!("command returned invalid JSON: {error}"),
                })?;
            if !validate_json_bounds(&value) {
                return Err(MyceliumError::Plugin {
                    plugin: plugin.into(),
                    message: "decoded JSON exceeds depth or node bounds".into(),
                });
            }
            Ok(value)
        }
    }
}

async fn execute_commands(
    plugin: &str,
    transport: &dyn Transport,
    commands: &[PlannedCommand],
    ignore_errors: bool,
) -> Result<Vec<serde_json::Value>> {
    let mut outputs = Vec::with_capacity(commands.len());
    for command in commands {
        let output = transport.exec(&command.rendered).await?;
        if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
            return Err(MyceliumError::Plugin {
                plugin: plugin.into(),
                message: format!("command output exceeds the {MAX_OUTPUT_BYTES}-byte limit"),
            });
        }
        if !output.success() && !ignore_errors {
            return Err(MyceliumError::Device {
                exit_code: output.exit_code,
                stderr: output.stderr.trim().to_owned(),
            });
        }
        outputs.push(decode_output(plugin, command.decode, &output.stdout)?);
    }
    Ok(outputs)
}

pub struct LuaDriver {
    plugin: Arc<Plugin>,
    connect: Arc<dyn Connect>,
    driver_name: String,
}

impl LuaDriver {
    pub fn new(plugin: Arc<Plugin>, connect: Arc<dyn Connect>) -> Self {
        let driver_name = format!("lua:{}", plugin.name);
        Self::new_named(plugin, connect, driver_name)
    }

    fn new_named(plugin: Arc<Plugin>, connect: Arc<dyn Connect>, driver_name: String) -> Self {
        Self {
            plugin,
            connect,
            driver_name,
        }
    }
}

#[async_trait]
impl Driver for LuaDriver {
    fn name(&self) -> &str {
        &self.driver_name
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        if self.plugin.has_probe {
            let transport = self.connect.connect(target, creds).await?;
            let lua = instantiate(&self.plugin.source, &self.plugin.name)?;
            let plugin = plugin_table(&lua, &self.plugin.name)?;
            let target = target_json(target);
            let probe: mlua::Function = plugin.get("probe").expect("validated at load");
            let output: LuaValue = probe
                .call(JsonBridge(target.clone()))
                .map_err(|error| err(&self.plugin.name, &error))?;
            let plan: serde_json::Value = lua
                .from_value(output)
                .map_err(|error| err(&self.plugin.name, &error))?;
            let commands = commands_from_plan(&self.plugin.name, &plan)?;
            let outputs =
                execute_commands(&self.plugin.name, transport.as_ref(), &commands, false).await?;
            let recognize: mlua::Function = plugin.get("recognize").expect("validated at load");
            return recognize
                .call((
                    JsonBridge(serde_json::Value::Array(outputs)),
                    JsonBridge(target),
                ))
                .map_err(|error| err(&self.plugin.name, &error));
        }
        if !self.plugin.has_match {
            return Ok(false);
        }
        let lua = instantiate(&self.plugin.source, &self.plugin.name)?;
        let plugin = plugin_table(&lua, &self.plugin.name)?;
        let f: mlua::Function = plugin.get("match").expect("checked");
        let arg = JsonBridge(target_json(target));
        let hit: bool = f.call(arg).map_err(|e| err(&self.plugin.name, &e))?;
        Ok(hit)
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let transport = self.connect.connect(target, creds).await?;
        let lua = instantiate(&self.plugin.source, &self.plugin.name)?;
        let caps = self.plugin.declared_caps(&lua)?;
        if !caps.contains_key(ID_IDENTIFY) {
            return Err(MyceliumError::Plugin {
                plugin: self.plugin.name.clone(),
                message: format!("plugins must declare `{ID_IDENTIFY}` so attach() can name the device"),
            });
        }

        let address = match target {
            Target::Host { host, port, .. } => format!("{host}:{}", port.unwrap_or(0)),
            Target::Subnet { network } => network.clone(),
        };
        let device = LuaDevice {
            lua: Arc::new(Mutex::new(lua)),
            transport,
            plugin: self.plugin.clone(),
            meta: std::sync::OnceLock::new(),
            caps: std::sync::Mutex::new(Some(caps)),
        };
        // Identify via the plugin's own declared capability. Build meta
        // through a temporary invocation context.
        let ctx = ExecContext::readonly(ID_IDENTIFY);
        let out = device.invoke(&ctx, ID_IDENTIFY, Params::new()).await?;
        let map = match &out.output {
            Value::Map(m) => m.clone(),
            _ => Params::new(),
        };
        let slug = |s: &str| {
            s.to_ascii_lowercase()
                .replace(|c: char| !(c.is_ascii_alphanumeric()), "-")
                .trim_matches('-')
                .to_owned()
        };
        let id = match map.get("stable_id").and_then(Value::as_str) {
            Some(stable_id) if !stable_id.trim().is_empty() => {
                DeviceId::new(format!("{}-{}", slug(&self.plugin.name), slug(stable_id)))
            }
            _ => DeviceId::new(format!(
                "{}-{}",
                slug(
                    map.get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("device")
                ),
                slug(&self.plugin.name)
            )),
        };
        let meta = DeviceMeta {
            id: id.clone(),
            kind: self.plugin.kind,
            driver: self.plugin.name.clone(),
            vendor: map.get("vendor").and_then(|v| v.as_str()).map(str::to_owned),
            model: map.get("model").and_then(|v| v.as_str()).map(str::to_owned),
            firmware: map.get("firmware").and_then(|v| v.as_str()).map(str::to_owned),
            address,
        };
        let _ = device.meta.set(meta);
        inventory.add(Arc::new(device));
        Ok(id)
    }
}

pub struct LuaDevice {
    lua: Arc<Mutex<Lua>>,
    transport: Arc<dyn Transport>,
    plugin: Arc<Plugin>,
    meta: std::sync::OnceLock<DeviceMeta>,
    caps: std::sync::Mutex<Option<BTreeMap<String, CapSpec>>>,
}

impl LuaDevice {
    fn caps(&self) -> BTreeMap<String, CapSpec> {
        let guard = self.caps.lock().expect("caps poisoned");
        guard.clone().unwrap_or_default()
    }

    /// Available once attach() has identified the device; absent during
    /// the bootstrap identify invocation itself.
    fn meta_opt(&self) -> Option<&DeviceMeta> {
        self.meta.get()
    }
}

#[async_trait]
impl Device for LuaDevice {
    fn meta(&self) -> &DeviceMeta {
        self.meta.get().expect("meta set before device is shared")
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        self.caps()
    }

    /// A plugin that declares `topology.observe` (pure result: an array of
    /// observation rows) contributes to the network map.
    async fn observe(&self) -> Result<(Vec<mycelium_core::Observation>, Vec<String>)> {
        const ID: &str = "topology.observe";
        if !self.caps().contains_key(ID) {
            return Ok((Vec::new(), Vec::new()));
        }
        let ctx = ExecContext::readonly(ID);
        let out = self.invoke(&ctx, ID, Params::new()).await?;
        match out.output {
            Value::List(rows) => {
                let json = serde_json::Value::Array(rows.iter().map(Value::to_json).collect());
                let obs: Vec<mycelium_core::Observation> =
                    serde_json::from_value(json).map_err(|e| MyceliumError::Plugin {
                        plugin: self.plugin.name.clone(),
                        message: format!("topology.observe rows must match Observation: {e}"),
                    })?;
                Ok((obs, Vec::new()))
            }
            _ => Err(MyceliumError::Plugin {
                plugin: self.plugin.name.clone(),
                message: "topology.observe must return a list result".into(),
            }),
        }
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        // 1. Ask the plugin what to do (pure Lua; no device I/O here).
        let plan: serde_json::Value = {
            let guard = self.lua.lock().await;
            let lua = &*guard;
            let plugin = plugin_table(lua, &self.plugin.name)?;
            let exec: mlua::Function = plugin
                .get("exec")
                .expect("capabilities/exec validated at load");
            let m = self.meta_opt();
            let c = serde_json::json!({
                "dry_run": ctx.dry_run,
                "device": {
                    "id": m.map(|x| x.id.to_string()).unwrap_or_else(|| "pending".into()),
                    "kind": m.map(|x| x.kind.to_string()).unwrap_or_else(|| self.plugin.kind.to_string()),
                    "address": m.map(|x| x.address.clone()).unwrap_or_default(),
                },
            });
            let out: LuaValue = exec
                .call((cap.to_owned(), JsonBridge(Value::Map(params.clone()).to_json()), JsonBridge(c)))
                .map_err(|e| err(&self.plugin.name, &e))?;
            lua.from_value(out).map_err(|e| err(&self.plugin.name, &e))?
        };

        let commands = commands_from_plan(&self.plugin.name, &plan)?;

        // 2. Dry-run never touches the transport: the plan *is* the output.
        if ctx.dry_run && !commands.is_empty() {
            return Ok(CapResult::dry_run(Value::List(
                commands
                    .into_iter()
                    .map(|command| Value::Str(command.rendered))
                    .collect(),
            )));
        }

        // 3. Run the declared commands through the host transport.
        let ignore_errors = plan.get("ignore_errors").and_then(|v| v.as_bool()) == Some(true);
        let outputs = execute_commands(
            &self.plugin.name,
            self.transport.as_ref(),
            &commands,
            ignore_errors,
        )
        .await?;

        // 4. Pure result, or hand outputs to the named parse function.
        let parse_name = plan.get("parse").and_then(|p| p.as_str()).map(str::to_owned);
        match (commands.is_empty(), parse_name) {
            (true, _) => result_from_plan(&self.plugin, &plan),
            (false, None) => Ok(CapResult::ok(Value::List(
                outputs.into_iter().map(|o| Value::from_json(&o)).collect(),
            ))),
            (false, Some(name)) => {
                let params_json = Value::Map(params.clone()).to_json();
                let guard = self.lua.lock().await;
                let plugin = plugin_table(&guard, &self.plugin.name)?;
                let parse: mlua::Function = plugin.get(name.as_str()).map_err(|e| {
                    MyceliumError::Plugin {
                        plugin: self.plugin.name.clone(),
                        message: format!("parse function `{name}` missing: {e}"),
                    }
                })?;
                let out: LuaValue = parse
                    .call((JsonBridge(serde_json::Value::Array(outputs)), JsonBridge(params_json)))
                    .map_err(|e| err(&self.plugin.name, &e))?;
                let json: serde_json::Value =
                    guard.from_value(out).map_err(|e| err(&self.plugin.name, &e))?;
                result_from_plan(&self.plugin, &json)
            }
        }
    }
}

fn result_from_plan(plugin: &Plugin, plan: &serde_json::Value) -> Result<CapResult> {
    if plan.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return Err(MyceliumError::Plugin {
            plugin: plugin.name.clone(),
            message: plan
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("plugin reported failure")
                .to_owned(),
        });
    }
    let output = plan.get("result").cloned().unwrap_or(serde_json::Value::Null);
    Ok(CapResult {
        ok: true,
        output: JsonBridge::to_core(&output),
        message: plan.get("message").and_then(|m| m.as_str()).map(str::to_owned),
        dry_run: false,
    })
}

pub fn dns_aliases(source: &str, context: serde_json::Value) -> Result<BTreeMap<String, String>> {
    const NAME: &str = "dns-policy";
    if source.len() > 65536 || !validate_json_bounds(&context) {
        return Err(MyceliumError::Plugin {
            plugin: NAME.into(),
            message: "DNS policy input exceeds bound".into(),
        });
    }
    let lua = instantiate_inner(source, NAME, true)?;
    let policy: Table = lua.globals().get("dns_policy").map_err(|e| err(NAME, &e))?;
    let aliases: mlua::Function = policy.get("aliases").map_err(|e| err(NAME, &e))?;
    let result: JsonBridge = aliases
        .call(JsonBridge(context))
        .map_err(|e| err(NAME, &e))?;
    if !validate_json_bounds(&result.0)
        || serde_json::to_vec(&result.0)
            .map_err(|e| MyceliumError::Plugin {
                plugin: NAME.into(),
                message: e.to_string(),
            })?
            .len()
            > 8192
    {
        return Err(MyceliumError::Plugin {
            plugin: NAME.into(),
            message: "DNS policy output exceeds bound".into(),
        });
    }
    let result: BTreeMap<String, String> =
        serde_json::from_value(result.0).map_err(|_| MyceliumError::Plugin {
            plugin: NAME.into(),
            message: "DNS aliases must be a string map".into(),
        })?;
    if result.len() > 32 {
        return Err(MyceliumError::Plugin {
            plugin: NAME.into(),
            message: "too many DNS aliases".into(),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::RecordingTransport;

    const GUEST: &str = include_str!("../examples/guest_dns.lua");

    fn fixture() -> (Arc<Plugin>, Arc<RecordingTransport>) {
        let transport = Arc::new(RecordingTransport::new());
        let plugin = Arc::new(Plugin::load(GUEST).unwrap());
        (plugin, transport)
    }

    #[test]
    fn bambu_recognizer_projects_stable_identity_without_authority() {
        let recognizer = AdvertisementRecognizer::load(BAMBU_RECOGNIZER).unwrap();
        let advertisement: ServiceAdvertisement = serde_json::from_value(serde_json::json!({
            "instance": "22E8AJ5A0400044",
            "service_type": "urn:bambulab-com:device:3dprinter:1",
            "domain": "ssdp",
            "addresses": ["10.0.0.3"],
            "txt": [
                "devmodel.bambu.com=N7",
                "devname.bambu.com=P2S - Thing 2",
                "devconnect.bambu.com=lan",
                "devseclink.bambu.com=secure",
                "devversion.bambu.com=01.00.05.00"
            ],
            "first_seen": 40,
            "last_seen": 42
        }))
        .unwrap();
        let device = recognizer.recognize(&advertisement).unwrap().unwrap();
        assert_eq!(device.stable_id, "bambu:22E8AJ5A0400044");
        assert_eq!(device.name, "P2S - Thing 2");
        assert_eq!(device.model.as_deref(), Some("N7"));
        assert_eq!(device.observed_at, 42);
        assert!(device.addresses.contains(&"10.0.0.3".parse().unwrap()));
        assert_eq!(device.services.len(), 3);
    }

    #[test]
    fn bambu_recognizer_ignores_unrelated_ssdp() {
        let recognizer = AdvertisementRecognizer::load(BAMBU_RECOGNIZER).unwrap();
        let advertisement: ServiceAdvertisement = serde_json::from_value(serde_json::json!({
            "instance": "uuid:television",
            "service_type": "upnp:rootdevice",
            "domain": "ssdp",
            "first_seen": 40,
            "last_seen": 42
        }))
        .unwrap();
        assert!(recognizer.recognize(&advertisement).unwrap().is_none());
    }

    #[test]
    fn homekit_recognizer_identifies_hue_bridge() {
        let recognizer = AdvertisementRecognizer::load(HOMEKIT_RECOGNIZER).unwrap();
        let advertisement: ServiceAdvertisement = serde_json::from_value(serde_json::json!({
            "instance": "Philips Hue HomeKit",
            "service_type": "_hap._tcp",
            "domain": "local",
            "target": "ecb5fa134f06.local",
            "port": 8080,
            "txt": ["ci=2", "id=DB:9B:5B:AA:3A:F4", "md=BSB002", "pv=1.1", "sf=0"],
            "first_seen": 40,
            "last_seen": 42
        }))
        .unwrap();
        let device = recognizer.recognize(&advertisement).unwrap().unwrap();
        assert_eq!(device.stable_id, "homekit:db:9b:5b:aa:3a:f4");
        assert_eq!(device.kind, "automation.bridge");
        assert_eq!(device.vendor.as_deref(), Some("Philips Hue"));
        assert_eq!(device.model.as_deref(), Some("BSB002"));
        assert_eq!(device.services[0].port, 8080);
    }

    #[test]
    fn airplay_recognizer_identifies_amazon_receiver() {
        let recognizer = AdvertisementRecognizer::load(AIRPLAY_RECOGNIZER).unwrap();
        let advertisement: ServiceAdvertisement = serde_json::from_value(serde_json::json!({
            "instance": "Avery's 2nd TV",
            "service_type": "_airplay._tcp",
            "domain": "local",
            "target": "Android.local",
            "port": 7000,
            "txt": [
                "deviceid=4C:39:F0:11:96:92", "manufacturer=Amazon",
                "model=AFTTIFF43", "fv=p20.7.01085.5741"
            ],
            "first_seen": 40,
            "last_seen": 42
        }))
        .unwrap();
        let device = recognizer.recognize(&advertisement).unwrap().unwrap();
        assert_eq!(device.stable_id, "airplay:4c:39:f0:11:96:92");
        assert_eq!(device.vendor.as_deref(), Some("Amazon"));
        assert_eq!(device.model.as_deref(), Some("AFTTIFF43"));
        assert_eq!(device.services[0].name, "airplay");
    }

    #[test]
    fn print_scan_recognizer_unifies_printer_and_scanner_identity() {
        let recognizer = AdvertisementRecognizer::load(PRINT_SCAN_RECOGNIZER).unwrap();
        let advertisement = |service_type: &str, port| {
            serde_json::from_value::<ServiceAdvertisement>(serde_json::json!({
                "instance": "HP DeskJet 4200 series [32FCEA]",
                "service_type": service_type,
                "domain": "local",
                "target": "HP6C0B5E32FCEA.local",
                "port": port,
                "txt": [
                    "UUID=e7e33cd5-2eda-436b-b643-7f08eedd6597",
                    "usb_MFG=HP", "usb_MDL=DeskJet 4200 series"
                ],
                "first_seen": 40,
                "last_seen": 42
            }))
            .unwrap()
        };
        let printer = recognizer
            .recognize(&advertisement("_ipp._tcp", 631))
            .unwrap()
            .unwrap();
        let scanner = recognizer
            .recognize(&advertisement("_uscan._tcp", 8080))
            .unwrap()
            .unwrap();
        assert_eq!(printer.stable_id, scanner.stable_id);
        assert_eq!(printer.vendor.as_deref(), Some("HP"));
        assert_eq!(printer.services[0].name, "ipp");
        assert_eq!(scanner.services[0].name, "escl");
    }

    #[test]
    fn specific_recognizers_ignore_unrelated_advertisements() {
        let advertisement: ServiceAdvertisement = serde_json::from_value(serde_json::json!({
            "instance": "host",
            "service_type": "_ssh._tcp",
            "domain": "local",
            "port": 22,
            "first_seen": 40,
            "last_seen": 42
        }))
        .unwrap();
        for (_, source) in BUILTIN_RECOGNIZERS.iter().skip(1) {
            let recognizer = AdvertisementRecognizer::load(*source).unwrap();
            assert!(recognizer.recognize(&advertisement).unwrap().is_none());
        }
    }

    #[test]
    fn probe_and_recognize_must_be_declared_together() {
        let source = r#"
          plugin = {
            name = "broken", kind = "other",
            capabilities = function() return {} end,
            exec = function() return { result = {} } end,
            probe = function() return { commands = {} } end,
          }
        "#;
        let error = Plugin::load(source).err().expect("plugin must be rejected");
        assert!(error.to_string().contains("declared together"));
    }

    #[test]
    fn structured_arguments_are_shell_quoted_and_bounded() {
        let plan = serde_json::json!({
            "commands": [{"program": "set-inform", "args": ["http://host/a'; reboot"]}]
        });
        let commands = commands_from_plan("test", &plan).unwrap();
        assert_eq!(
            commands[0].rendered,
            "set-inform 'http://host/a'\\''; reboot'"
        );
        let invalid = serde_json::json!({
            "commands": [{"program": "sh -c", "args": []}]
        });
        assert!(commands_from_plan("test", &invalid).is_err());
    }

    #[tokio::test]
    async fn unifi_plugin_probes_attaches_and_decodes_json() {
        const INFO: &str = "mca-cli-op info 2>/dev/null || info 2>/dev/null";
        let transport = Arc::new(RecordingTransport::new());
        transport.reply(
            INFO,
            "Model: UAP-AC-Pro-Gen2\nVersion: 6.6.77.15402\nMAC Address: 24:a4:3c:00:00:01\nHostname: office-ap\n",
        );
        transport.reply("wstalist", r#"[{"mac":"aa:bb:cc:dd:ee:ff"}]"#);
        let plugin = Arc::new(Plugin::load(UNIFI_AP_PLUGIN).unwrap());
        let connector_transport = transport.clone();
        let driver = plugin.driver_named(
            "unifi",
            Arc::new(move |_: Target, _| {
                let transport = connector_transport.clone();
                async move { Ok(transport as Arc<dyn Transport>) }
            }),
        );
        assert_eq!(driver.name(), "unifi");
        let target = Target::host("192.168.99.11");
        let credentials = CredentialSet::default();
        assert!(driver.recognizes(&target, &credentials).await.unwrap());

        let inventory = Inventory::new();
        let id = driver
            .attach(&target, &credentials, &inventory)
            .await
            .unwrap();
        assert_eq!(id.to_string(), "unifi-24-a4-3c-00-00-01");
        let device = inventory.get(&id.to_string()).unwrap();
        assert_eq!(device.meta().vendor.as_deref(), Some("Ubiquiti"));
        assert_eq!(device.meta().model.as_deref(), Some("UAP-AC-Pro-Gen2"));
        let stations = device
            .invoke(
                &ExecContext::readonly("wlan.list-stations"),
                "wlan.list-stations",
                Params::new(),
            )
            .await
            .unwrap();
        assert_eq!(stations.output.as_list().unwrap().len(), 1);

        let set_inform = &device.capabilities()["unifi.set-inform"];
        assert!(set_inform.mutation);
        assert_eq!(
            set_inform
                .verification
                .as_ref()
                .map(|verification| verification.capability.as_str()),
            Some("unifi.status")
        );
        let calls_before = transport.calls.lock().unwrap().len();
        let dry_run = device
            .invoke(
                &ExecContext {
                    capability: "unifi.set-inform".into(),
                    allow_writes: false,
                    dry_run: true,
                },
                "unifi.set-inform",
                params_internal("url", "http://host/a';reboot"),
            )
            .await
            .unwrap();
        assert_eq!(
            dry_run.output,
            Value::List(vec![Value::Str(
                "set-inform 'http://host/a'\\'';reboot'".into()
            )])
        );
        assert_eq!(transport.calls.lock().unwrap().len(), calls_before);
    }

    #[tokio::test]
    async fn command_output_is_bounded_before_decoding() {
        let transport = RecordingTransport::new();
        transport.reply("huge", "x".repeat(MAX_OUTPUT_BYTES + 1));
        let commands = vec![PlannedCommand {
            rendered: "huge".into(),
            decode: OutputDecoder::Raw,
        }];
        let error = execute_commands("test", &transport, &commands, false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("output exceeds"));
    }

    #[tokio::test]
    async fn attaches_and_identifies_through_lua() {
        let (plugin, transport) = fixture();
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.clone().driver(Arc::new(move |_target: Target, _creds| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let creds = CredentialSet::default().with_user("u");
        let id = driver
            .attach(&Target::host("10.0.0.9"), &creds, &inv)
            .await
            .unwrap();
        assert_eq!(id.to_string(), "gh0st-guest");
        let dev = inv.get(&id.to_string()).unwrap();
        let meta = dev.meta();
        assert_eq!(meta.vendor.as_deref(), Some("Test"));
        assert_eq!(meta.model.as_deref(), Some("guestbox"));
        assert_eq!(meta.driver, "guest");
        assert!(dev.capabilities().contains_key("dns.block"));
    }

    #[tokio::test]
    async fn match_is_pure_lua_on_target_desc() {
        let (plugin, _transport) = fixture();
        let driver = plugin.driver(Arc::new(|_: Target, _| async { panic!("no connect for match") }));
        assert!(driver.recognizes(&Target::Host { host: "x".into(), port: Some(8053), jump: None }, &CredentialSet::default()).await.unwrap());
        assert!(!driver.recognizes(&Target::host("x"), &CredentialSet::default()).await.unwrap());
    }

    #[tokio::test]
    async fn commands_run_through_host_transport() {
        let (plugin, transport) = fixture();
        transport.reply("list", "a.com\nb.com\n");
        transport.reply("block ads.example", "");
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.driver(Arc::new(move |_: Target, _| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let id = driver.attach(&Target::host("h"), &CredentialSet::default(), &inv).await.unwrap();
        let dev = inv.get(&id.to_string()).unwrap();

        let ctx = ExecContext::readonly("dns.list");
        let res = dev.invoke(&ctx, "dns.list", Params::new()).await.unwrap();
        assert_eq!(
            res.output,
            Value::List(vec![Value::Str("a.com".into()), Value::Str("b.com".into())])
        );

        // write gate: mutation without allow_writes never reaches Lua
        let gated = ExecContext { capability: "dns.block".into(), allow_writes: false, dry_run: false };
        let err = dev.invoke(&gated, "dns.block", params_internal("domain", "ads.example")).await.unwrap_err();
        assert!(matches!(err, MyceliumError::WritesNotPermitted(_)));
        assert!(!transport.calls.lock().unwrap().iter().any(|c| c.starts_with("block ")));

        // ...and opt-in runs the declared command
        let opted = ExecContext { capability: "dns.block".into(), allow_writes: true, dry_run: false };
        dev.invoke(&opted, "dns.block", params_internal("domain", "ads.example")).await.unwrap();
        assert!(transport.calls.lock().unwrap().iter().any(|c| c == "block ads.example"));
    }

    #[tokio::test]
    async fn dry_run_returns_plan_without_touching_transport() {
        let (plugin, transport) = fixture();
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.driver(Arc::new(move |_: Target, _| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let id = driver.attach(&Target::host("h"), &CredentialSet::default(), &inv).await.unwrap();
        let dev = inv.get(&id.to_string()).unwrap();
        let ctx = ExecContext { capability: "dns.block".into(), allow_writes: true, dry_run: true };
        let res = dev.invoke(&ctx, "dns.block", params_internal("domain", "ads.example")).await.unwrap();
        assert!(res.dry_run);
        assert_eq!(res.output, Value::List(vec![Value::Str("block ads.example".into())]));
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn sandbox_denies_stdlib() {
        let lua = instantiate(
            r#"
plugin = { name = "evil", kind = "other",
  capabilities = function() return {} end,
  exec = function() return { result = pcall(function() return io end) } end }
"#,
            "evil",
        )
        .unwrap();
        let io: LuaValue = lua.globals().get("io").unwrap();
        assert!(matches!(io, LuaValue::Nil));
    }

    #[test]
    fn load_validates_shape() {
        assert!(Plugin::load("plugin = { name = 'x' }").is_err());
        assert!(Plugin::load("local notglobal = {}").is_err());
        let bad_kind = Plugin::load(
            "plugin = { name = 'x', kind = 'toaster', capabilities = function() return {} end, exec = function() end }",
        );
        assert!(bad_kind.is_err());
    }

    fn params_internal(k: &str, v: &str) -> Params {
        Params::from_iter([(k.to_owned(), Value::Str(v.to_owned()))])
    }
}
#[test]
fn snmp_classifier_refines_identity_without_transport_access() {
    let classifier = LuaDeviceClassifier::load(SNMP_CLASSIFIER).unwrap();
    let evidence = DeviceIdentityEvidence {
        source: "snmp.system".into(),
        address: "192.0.2.10".into(),
        facts: BTreeMap::from([
            ("sys_descr".into(), "GS728TP Smart Switch".into()),
            ("sys_object_id".into(), "1.3.6.1.4.1.4526.100.7".into()),
        ]),
    };
    let result = classifier.classify(&evidence).unwrap().unwrap();
    assert_eq!(result.kind, Some(DeviceKind::Switch));
    assert_eq!(result.vendor.as_deref(), Some("NETGEAR"));
    assert_eq!(result.stable_id, None);
}

#[test]
fn classifier_rejects_unbounded_evidence_before_lua() {
    let classifier = LuaDeviceClassifier::load(SNMP_CLASSIFIER).unwrap();
    let evidence = DeviceIdentityEvidence {
        source: "snmp.system".into(),
        address: "192.0.2.10".into(),
        facts: BTreeMap::from([("sys_descr".into(), "x".repeat(4097))]),
    };
    assert!(classifier.classify(&evidence).is_err());
}
