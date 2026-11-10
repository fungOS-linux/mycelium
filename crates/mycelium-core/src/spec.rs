use serde::{Deserialize, Serialize};

use crate::{ActionRisk, Params, Value};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MutationVerification {
    pub risk: ActionRisk,
    pub capability: String,
    #[serde(default)]
    pub params: Params,
}

/// Result of a capability invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapResult {
    pub ok: bool,
    /// Structured output, shape documented by the capability description.
    pub output: Value,
    /// Human-readable note (e.g. parsed device message).
    pub message: Option<String>,
    /// True when the device did not apply anything (read-only or --dry-run).
    pub dry_run: bool,
}

impl CapResult {
    pub fn ok(output: Value) -> Self {
        Self {
            ok: true,
            output,
            message: None,
            dry_run: false,
        }
    }

    pub fn dry_run(output: Value) -> Self {
        Self {
            ok: true,
            output,
            message: None,
            dry_run: true,
        }
    }

    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
}

/// What a capability expects and returns, as data (see design tenet:
/// structured interfaces are *declared*, only `exec` is code).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapSpec {
    /// Capability id when declared by a plugin (`vlan.list`); empty for
    /// hand-written Rust drivers which are keyed by map entry instead.
    #[serde(default)]
    pub id: String,
    /// One-line description shown by `mycelium describe`.
    pub description: String,
    /// Required parameters (name, type, docs).
    #[serde(default)]
    pub params: Vec<ParamSpec>,
    /// Optional parameters.
    #[serde(default)]
    pub optional: Vec<ParamSpec>,
    /// Whether invoking this changes device state.
    #[serde(default)]
    pub mutation: bool,
    /// Required to lower an ad-hoc mutation into the shared ActionPlan
    /// executor. Missing metadata makes direct writes fail closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<MutationVerification>,
    /// Free-form docs of the output shape.
    #[serde(default)]
    pub returns: Option<String>,
}

impl CapSpec {
    pub fn readonly(description: impl Into<String>) -> Self {
        Self {
            id: String::new(),
            description: description.into(),
            params: Vec::new(),
            optional: Vec::new(),
            mutation: false,
            verification: None,
            returns: None,
        }
    }

    pub fn mutation(description: impl Into<String>) -> Self {
        Self {
            mutation: true,
            ..Self::readonly(description)
        }
    }

    pub fn verified_by(mut self, risk: ActionRisk, capability: impl Into<String>) -> Self {
        self.verification = Some(MutationVerification {
            risk,
            capability: capability.into(),
            params: Params::new(),
        });
        self
    }

    pub fn param(
        mut self,
        name: impl Into<String>,
        ty: ParamType,
        docs: impl Into<String>,
    ) -> Self {
        self.params.push(ParamSpec {
            name: name.into(),
            ty,
            docs: docs.into(),
        });
        self
    }

    pub fn optional(
        mut self,
        name: impl Into<String>,
        ty: ParamType,
        docs: impl Into<String>,
    ) -> Self {
        self.optional.push(ParamSpec {
            name: name.into(),
            ty,
            docs: docs.into(),
        });
        self
    }

    pub fn returns(mut self, docs: impl Into<String>) -> Self {
        self.returns = Some(docs.into());
        self
    }

    /// Validate a call's params: all required present and type-correct.
    pub fn validate(&self, params: &crate::Params) -> Result<(), String> {
        for spec in &self.params {
            match params.get(&spec.name) {
                None => return Err(format!("missing required param `{}`", spec.name)),
                Some(v) => spec.ty.check(v).ok_or_else(|| {
                    format!("param `{}` expects {}, got {v:?}", spec.name, spec.ty)
                })?,
            }
        }
        for (name, _v) in params {
            let known = self
                .params
                .iter()
                .chain(&self.optional)
                .any(|p| &p.name == name);
            if !known {
                return Err(format!("unknown param `{name}`"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    #[serde(alias = "string")]
    Str,
    Int,
    Bool,
    Map,
    List,
}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ParamType::Str => "string",
            ParamType::Int => "int",
            ParamType::Bool => "bool",
            ParamType::Map => "map",
            ParamType::List => "list",
        };
        f.write_str(s)
    }
}

impl ParamType {
    pub fn check(&self, v: &Value) -> Option<()> {
        match (self, v) {
            (ParamType::Str, Value::Str(_))
            | (ParamType::Int, Value::Int(_))
            | (ParamType::Bool, Value::Bool(_))
            | (ParamType::Map, Value::Map(_))
            | (ParamType::List, Value::List(_)) => Some(()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ParamSpec {
    pub name: String,
    pub ty: ParamType,
    pub docs: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Params;

    fn spec() -> CapSpec {
        CapSpec::mutation("create a vlan")
            .param("id", ParamType::Int, "802.1q id")
            .optional("name", ParamType::Str, "label")
    }

    #[test]
    fn accepts_valid_params() {
        let mut p = Params::new();
        p.insert("id".into(), Value::Int(35));
        assert!(spec().validate(&p).is_ok());
    }

    #[test]
    fn rejects_missing_typed_and_unknown() {
        assert!(spec()
            .validate(&Params::new())
            .unwrap_err()
            .contains("missing required"));
        let mut wrong = Params::new();
        wrong.insert("id".into(), Value::Str("x".into()));
        assert!(spec().validate(&wrong).unwrap_err().contains("expects int"));
        let mut extra = Params::new();
        extra.insert("id".into(), Value::Int(2));
        extra.insert("bogus".into(), Value::Bool(true));
        assert!(spec()
            .validate(&extra)
            .unwrap_err()
            .contains("unknown param"));
    }
}
