// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure Hermes YAML generation, migration, and ownership recognition.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::error::CliError;
use crate::hooks::{generated_hooks, merge_hooks};

pub(super) const MCP_SERVER_NAME: &str = "nemo-relay";

pub(super) fn has_legacy_mcp_state(root: &Value) -> bool {
    root.pointer(&format!("/mcp_servers/{MCP_SERVER_NAME}"))
        .and_then(|server| server.get("args"))
        .and_then(Value::as_array)
        .is_some_and(|args| {
            args.first().and_then(Value::as_str) == Some("mcp")
                || (args.first().and_then(Value::as_str) == Some("plugin-shim")
                    && args.get(1).and_then(Value::as_str) == Some("mcp"))
        })
}

pub(super) fn user_config_path_with_override(
    default_home: &Path,
    hermes_home: Option<std::ffi::OsString>,
) -> PathBuf {
    hermes_home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_home.join(".hermes"))
        .join("config.yaml")
}

pub(crate) fn persistent_hook_command(
    relay: &Path,
    generation: &Path,
    generation_token: &str,
) -> Result<String, String> {
    crate::hooks::persistent_hook_forward_command(
        relay,
        crate::agents::CodingAgent::Hermes,
        generation,
        generation_token,
    )
}

#[cfg(test)]
pub(super) fn persistent_hook_command_for_platform(
    relay: &Path,
    generation: &Path,
    generation_token: &str,
    windows: bool,
) -> String {
    crate::hooks::persistent_hook_forward_command_for_platform(
        relay,
        crate::agents::CodingAgent::Hermes,
        generation,
        generation_token,
        windows,
    )
}

pub(super) fn persistent_config(
    existing: Option<&str>,
    relay: &Path,
    command: &str,
    generation: &Path,
    _generation_token: &str,
    _environment: &[String],
) -> Result<Value, CliError> {
    let mut root = parse_yaml_object(existing, "Hermes config")?;
    let owned = owned_install_command(&root, relay, Some(generation))?;
    strip_owned_hooks(&mut root, owned.as_deref())?;
    remove_owned_mcp(&mut root, owned.is_some())?;
    root = merge_hooks(
        root,
        generated_hooks(crate::agents::CodingAgent::Hermes, command),
    )?;
    Ok(root)
}

pub(super) fn strip_owned_hooks(
    root: &mut Value,
    owned_command: Option<&str>,
) -> Result<(), CliError> {
    let Some(hooks) = root.get_mut("hooks") else {
        return Ok(());
    };
    let remove_hooks = {
        let hooks = hooks
            .as_object_mut()
            .ok_or_else(|| CliError::Install("Hermes hooks must be an object".into()))?;
        let mut empty = Vec::new();
        for (event, groups) in hooks.iter_mut() {
            let groups = groups.as_array_mut().ok_or_else(|| {
                CliError::Install(format!("Hermes {event} hooks must be an array"))
            })?;
            groups.retain(|group| {
                group
                    .get("command")
                    .and_then(Value::as_str)
                    .is_none_or(|command| Some(command) != owned_command)
            });
            if groups.is_empty() {
                empty.push(event.clone());
            }
        }
        for event in empty {
            hooks.remove(&event);
        }
        hooks.is_empty()
    };
    if remove_hooks {
        root.as_object_mut()
            .expect("Hermes config root checked as object")
            .remove("hooks");
    }
    Ok(())
}

pub(super) fn remove_owned_mcp(root: &mut Value, owned: bool) -> Result<(), CliError> {
    let Some(servers) = root.get_mut("mcp_servers") else {
        return Ok(());
    };
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| CliError::Install("Hermes mcp_servers must be an object".into()))?;
    if owned {
        servers.remove(MCP_SERVER_NAME);
    }
    if servers.is_empty() {
        root.as_object_mut()
            .expect("Hermes config root checked as object")
            .remove("mcp_servers");
    }
    Ok(())
}

pub(super) fn owned_install_command(
    root: &Value,
    relay: &Path,
    expected_generation: Option<&Path>,
) -> Result<Option<String>, CliError> {
    if let Some((command, configured_relay, generation)) = managed_hook_command(root)
        && configured_relay == relay
        && expected_generation.is_none_or(|expected| generation == expected)
    {
        return Ok(Some(command));
    }
    let Some(server) = root.pointer(&format!("/mcp_servers/{MCP_SERVER_NAME}")) else {
        return Ok(None);
    };
    if server.get("command") != Some(&json!(relay)) {
        return Ok(None);
    }
    let env = server.get("env").and_then(Value::as_object);
    if server.get("args") == Some(&json!(["mcp"]))
        && env.and_then(|env| env.get("NEMO_RELAY_GATEWAY_BIND"))
            == Some(&json!(crate::bootstrap::LEGACY_FIXED_BIND))
    {
        let generation = env
            .and_then(|env| {
                env.get(crate::installation::generation::LEGACY_MCP_GENERATION_FILE_ENV)
            })
            .and_then(Value::as_str);
        let token = env
            .and_then(|env| {
                env.get(crate::installation::generation::LEGACY_MCP_GENERATION_TOKEN_ENV)
            })
            .and_then(Value::as_str);
        if let (Some(generation), Some(token)) = (generation, token)
            && !token.is_empty()
            && expected_generation.is_none_or(|expected| Path::new(generation) == expected)
        {
            let command = crate::hooks::persistent_hook_forward_command_at(
                relay,
                crate::agents::CodingAgent::Hermes,
                crate::bootstrap::LEGACY_FIXED_URL,
                Path::new(generation),
                token,
            )
            .map_err(CliError::Install)?;
            return Ok(Some(command));
        }
    }
    legacy_owned_command(root, relay)
}

pub(super) fn managed_hook_command(root: &Value) -> Option<(String, PathBuf, PathBuf)> {
    let mut common: Option<(String, PathBuf, PathBuf)> = None;
    for event in crate::agents::CodingAgent::Hermes.hook_events() {
        let candidates = root
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)?
            .iter()
            .filter_map(|entry| entry.get("command").and_then(Value::as_str))
            .filter_map(|command| {
                generated_hook_identity(command)
                    .map(|(relay, generation)| (command.to_string(), relay, generation))
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return None;
        }
        if common.as_ref().is_some_and(|value| value != &candidates[0]) {
            return None;
        }
        common = candidates.into_iter().next();
    }
    common
}

fn generated_hook_identity(command: &str) -> Option<(PathBuf, PathBuf)> {
    #[cfg(any(windows, test))]
    let arguments = crate::hooks::decode_windows_hook_command(command)
        .or_else(|| parse_posix_command(command))?;
    #[cfg(not(any(windows, test)))]
    let arguments = parse_posix_command(command)?;
    let gateway_index = arguments
        .iter()
        .position(|value| value == "--gateway-url")?;
    let generation_index = arguments
        .iter()
        .position(|value| value == "--generation-file")?;
    let token_index = arguments
        .iter()
        .position(|value| value == "--generation-token")?;
    if arguments.get(1).map(String::as_str) != Some("hook-forward")
        || arguments.get(2).map(String::as_str) != Some("hermes")
        || arguments
            .get(gateway_index + 1)
            .is_none_or(String::is_empty)
        || arguments.get(token_index + 1).is_none_or(String::is_empty)
        || !arguments.iter().any(|value| value == "--fail-closed")
    {
        return None;
    }
    Some((
        PathBuf::from(arguments.first()?),
        PathBuf::from(arguments.get(generation_index + 1)?),
    ))
}

fn parse_posix_command(command: &str) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' && !quoted {
            escaped = true;
        } else if character == '\'' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            if !current.is_empty() {
                arguments.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quoted {
        return None;
    }
    if !current.is_empty() {
        arguments.push(current);
    }
    (!arguments.is_empty()).then_some(arguments)
}

fn legacy_owned_command(root: &Value, relay: &Path) -> Result<Option<String>, CliError> {
    let server = &root["mcp_servers"][MCP_SERVER_NAME];
    if server.get("args") != Some(&json!(["mcp", "--agent", "hermes"])) {
        return Ok(None);
    }
    let Some(hooks) = root.get("hooks").and_then(Value::as_object) else {
        return Ok(None);
    };
    let mut common = None;
    for event in crate::agents::CodingAgent::Hermes.hook_events() {
        let commands = hooks
            .get(*event)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("command").and_then(Value::as_str))
            .filter(|command| legacy_command_uses_relay(command, relay))
            .collect::<Vec<_>>();
        if commands.len() != 1 || common.is_some_and(|value| value != commands[0]) {
            return Ok(None);
        }
        common = Some(commands[0]);
    }
    Ok(common.map(str::to_owned))
}

fn legacy_command_uses_relay(command: &str, relay: &Path) -> bool {
    let relay = relay.to_string_lossy();
    let quoted = crate::agents::shell_quote_arg_for_platform(&relay, cfg!(windows));
    [relay.as_ref(), quoted.as_str()].into_iter().any(|prefix| {
        command.strip_prefix(prefix).is_some_and(|arguments| {
            [" hook-forward hermes", " plugin-shim hook hermes"]
                .iter()
                .any(|marker| arguments.starts_with(marker))
        })
    })
}

pub(super) fn relay_is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(super) fn parse_yaml_object(raw: Option<&str>, description: &str) -> Result<Value, CliError> {
    let value = match raw.filter(|raw| !raw.trim().is_empty()) {
        Some(raw) => serde_yaml::from_str(raw)
            .map_err(|error| CliError::Install(format!("invalid {description}: {error}")))?,
        None => json!({}),
    };
    if value.is_object() {
        Ok(value)
    } else {
        Err(CliError::Install(format!(
            "{description} must contain an object"
        )))
    }
}

pub(super) fn yaml_bytes(value: &Value) -> Result<Vec<u8>, CliError> {
    serde_yaml::to_string(value)
        .map(String::into_bytes)
        .map_err(|error| CliError::Install(error.to_string()))
}
