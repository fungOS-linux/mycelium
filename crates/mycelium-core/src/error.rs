use thiserror::Error;

pub type Result<T> = std::result::Result<T, MyceliumError>;

#[derive(Debug, Error)]
pub enum MyceliumError {
    #[error("transport failure: {0}")]
    Transport(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("device `{device}` does not support capability `{capability}`")]
    Unsupported { device: String, capability: String },

    #[error("unknown device `{0}`")]
    UnknownDevice(String),

    #[error("unknown capability `{0}`")]
    UnknownCapability(String),

    #[error("parse failure: {0}")]
    Parse(String),

    #[error("plugin failure [{plugin}]: {message}")]
    Plugin { plugin: String, message: String },

    #[error("invalid parameters: {0}")]
    Validation(String),

    #[error("device returned an error (exit {exit_code}): {stderr}")]
    Device { exit_code: i32, stderr: String },

    /// Secure-by-default gate: the action mutates state and the session did
    /// not opt in. This is an explicit refusal, never a silent fallback.
    #[error("`{0}` changes device state; re-invoke with --write to allow")]
    WritesNotPermitted(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl MyceliumError {
    pub fn unsupported(device: impl Into<String>, capability: impl Into<String>) -> Self {
        MyceliumError::Unsupported {
            device: device.into(),
            capability: capability.into(),
        }
    }
}
