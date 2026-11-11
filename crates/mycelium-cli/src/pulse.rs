//! `mycelium pulse`: the agent-facing client for the daemon-owned scheduler.
//!
//! The daemon owns the store, the cron evaluator and the run history. This
//! command only parses arguments and speaks the Unix RPC; the Pulse Spore uses
//! the same requests through its host bridge.

use myceliumd::client::{Client, ClientError};
use myceliumd::protocol::Request;
use myceliumd::pulse::{PulseList, PulseRun, UserPulse};
use serde_json::Value;

pub async fn command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Ok(usage());
    };
    let mut client = Client::connect().await?;
    match subcommand {
        "list" => {
            let value = client.call(&Request::PulseList).await?;
            if args.iter().any(|arg| arg == "--json") {
                return Ok(vec![pretty(&value)]);
            }
            let list: PulseList = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            Ok(format_list(&list))
        }
        "add" => {
            let mut schedule = None;
            let mut command = None;
            let mut id = String::new();
            let mut enabled = true;
            let mut write = false;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--schedule" => schedule = Some(value(args, &mut index, "--schedule")?),
                    "--command" => command = Some(value(args, &mut index, "--command")?),
                    "--id" => id = value(args, &mut index, "--id")?,
                    "--disabled" => enabled = false,
                    "--write" => write = true,
                    other => {
                        return Err(ClientError::Protocol(format!(
                            "pulse add: unknown argument {other:?}"
                        )))
                    }
                }
                index += 1;
            }
            if !write {
                return Err(ClientError::Protocol("pulse add requires --write".into()));
            }
            let schedule = schedule
                .ok_or_else(|| ClientError::Protocol("pulse add requires --schedule".into()))?;
            let command = command
                .ok_or_else(|| ClientError::Protocol("pulse add requires --command".into()))?;
            let pulse = UserPulse {
                id,
                schedule,
                command,
                enabled,
                created_at_ms: 0,
                updated_at_ms: 0,
                last_fired_ms: 0,
            };
            let value = client
                .call(&Request::PulsePut { pulse, write: true })
                .await?;
            let saved: UserPulse = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            Ok(vec![format!(
                "{} {}",
                saved.id,
                if saved.enabled { "enabled" } else { "disabled" }
            )])
        }
        "remove" => {
            let id = required_id(args)?;
            let write = args.iter().any(|arg| arg == "--write");
            if !write {
                return Err(ClientError::Protocol(
                    "pulse remove requires --write".into(),
                ));
            }
            let value = client
                .call(&Request::PulseRemove { id, write: true })
                .await?;
            Ok(vec![pretty(&value)])
        }
        "toggle" => {
            let id = required_id(args)?;
            let write = args.iter().any(|arg| arg == "--write");
            if !write {
                return Err(ClientError::Protocol(
                    "pulse toggle requires --write".into(),
                ));
            }
            let value = client.call(&Request::PulseList).await?;
            let list: PulseList = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            let mut pulse = list
                .user
                .into_iter()
                .find(|view| view.pulse.id == id)
                .map(|view| view.pulse)
                .ok_or_else(|| ClientError::Protocol(format!("no pulse {id:?}")))?;
            pulse.enabled = !pulse.enabled;
            let value = client
                .call(&Request::PulsePut { pulse, write: true })
                .await?;
            let saved: UserPulse = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            Ok(vec![format!(
                "{} {}",
                saved.id,
                if saved.enabled { "enabled" } else { "disabled" }
            )])
        }
        "runs" => {
            let mut id = None;
            let mut limit = 20usize;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--limit" => {
                        limit = value(args, &mut index, "--limit")?.parse().map_err(|_| {
                            ClientError::Protocol("--limit expects a number".into())
                        })?;
                    }
                    "--json" => {}
                    other if !other.starts_with("--") => id = Some(other.to_owned()),
                    other => {
                        return Err(ClientError::Protocol(format!(
                            "pulse runs: unknown argument {other:?}"
                        )))
                    }
                }
                index += 1;
            }
            let value = client
                .call(&Request::PulseRuns {
                    id,
                    limit: Some(limit),
                })
                .await?;
            if args.iter().any(|arg| arg == "--json") {
                return Ok(vec![pretty(&value)]);
            }
            let runs: Vec<PulseRun> = serde_json::from_value(value)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            Ok(format_runs(&runs))
        }
        other => Ok(vec![
            format!("pulse: unknown command {other:?}"),
            usage().join("\n"),
        ]),
    }
}

fn value(args: &[String], index: &mut usize, flag: &str) -> Result<String, ClientError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| ClientError::Protocol(format!("{flag} requires a value")))
}

fn required_id(args: &[String]) -> Result<String, ClientError> {
    args.iter()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .cloned()
        .ok_or_else(|| ClientError::Protocol("pulse command requires an id".into()))
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn format_list(list: &PulseList) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("SYSTEM".to_owned());
    for pulse in &list.system {
        lines.push(format!(
            "  {:<24} every {}s  {}",
            pulse.id, pulse.interval_secs, pulse.description
        ));
    }
    lines.push("USER".to_owned());
    if list.user.is_empty() {
        lines.push("  no user pulses".to_owned());
    } else {
        lines.push(format!(
            "  {:<24} {:<7} {:<14} {:<16} COMMAND",
            "ID", "ENABLED", "NEXT_AT_MS", "SCHEDULE"
        ));
        for view in &list.user {
            let next = view
                .next_at_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "never".into());
            lines.push(format!(
                "  {:<24} {:<7} {:<14} {:<16} {}",
                view.pulse.id,
                if view.pulse.enabled { "yes" } else { "no" },
                next,
                view.pulse.schedule,
                view.pulse.command.replace('\n', " ")
            ));
        }
    }
    lines
}

fn format_runs(runs: &[PulseRun]) -> Vec<String> {
    if runs.is_empty() {
        return vec!["no runs".into()];
    }
    let mut lines = Vec::with_capacity(runs.len() + 1);
    lines.push(format!(
        "{:<28} {:<20} {:<14} {:<8} DETAIL",
        "RUN", "PULSE", "FIRED_AT_MS", "OUTCOME"
    ));
    for run in runs {
        lines.push(format!(
            "{:<28} {:<20} {:<14} {:<8} {}",
            run.id,
            run.pulse_id,
            run.fired_at_ms,
            run.outcome,
            run.detail.replace('\n', " ")
        ));
    }
    lines
}

fn usage() -> Vec<String> {
    [
        "usage: mycelium pulse list [--json]",
        "       mycelium pulse add --schedule CRON --command CMD [--id ID] [--disabled] --write",
        "       mycelium pulse remove ID --write",
        "       mycelium pulse toggle ID --write",
        "       mycelium pulse runs [ID] [--limit N] [--json]",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
