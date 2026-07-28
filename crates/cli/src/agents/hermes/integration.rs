// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hermes-owned lifecycle-hook and proxy-environment configuration.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) use super::config::persistent_hook_command;
use super::config::{
    has_legacy_mcp_state, managed_hook_command, owned_install_command, parse_yaml_object,
    persistent_config, relay_is_executable, remove_owned_mcp, strip_owned_hooks,
    user_config_path_with_override, yaml_bytes,
};
use super::files::{
    FileSnapshot, FileTransaction, INSTALL_LOCK_TIMEOUT, PersistentPaths, acquire_allowlist_lock,
    acquire_install_lock, read_optional_utf8,
};
use super::trust::{json_bytes, parse_json_object, trusted_hooks, verify_trust};
use crate::agents::CodingAgent;
use crate::error::CliError;
use crate::filesystem::atomic_write_private;
use crate::installation::generation::{GenerationRetirement, InstallGeneration};

const PROXY_ENV_NAMES: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "AWS_CA_BUNDLE",
];

#[derive(Debug, Serialize, Deserialize)]
struct ProxyEnvState {
    schema_version: u32,
    previous: BTreeMap<String, Option<String>>,
    generated: BTreeMap<String, String>,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) struct HermesSetupSnapshot {
    files: Vec<FileSnapshot>,
}

/// Hermes host configuration is user-owned and reads only the user's Relay enrollment.
pub(crate) fn user_config_path(default_home: &Path) -> PathBuf {
    user_config_path_with_override(default_home, env::var_os("HERMES_HOME"))
}

/// Captures the effective durable Hermes `.env` proxy inputs before the shared service starts.
///
/// Ambient values are merged later by the common proxy resolver so a higher-precedence shell
/// conflict is rejected instead of silently changing the service route after activation.
pub(crate) fn proxy_environment(config: &Path) -> Result<Map<String, Value>, String> {
    let paths =
        PersistentPaths::for_config(config.to_path_buf()).map_err(|error| error.to_string())?;
    let raw = read_optional_utf8(&paths.env)
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    parse_dotenv_values(&raw)
        .map(|values| {
            values
                .into_iter()
                .map(|(name, value)| (name, Value::String(value)))
                .collect()
        })
        .map_err(|error| error.to_string())
}

pub(crate) fn snapshot_persistent(config: &Path) -> Result<HermesSetupSnapshot, String> {
    let paths =
        PersistentPaths::for_config(config.to_path_buf()).map_err(|error| error.to_string())?;
    let _lock = acquire_install_lock(&paths.config, INSTALL_LOCK_TIMEOUT)?;
    let _allowlist_lock = acquire_allowlist_lock(&paths.allowlist, INSTALL_LOCK_TIMEOUT)?;
    let files = paths
        .all()
        .iter()
        .map(|path| FileSnapshot::capture(path).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HermesSetupSnapshot { files })
}

pub(crate) fn capture_current_persistent_snapshot(
    snapshot: &HermesSetupSnapshot,
) -> Result<HermesSetupSnapshot, String> {
    let config = snapshot
        .files
        .first()
        .ok_or_else(|| "Hermes setup snapshot is empty".to_string())?
        .path();
    snapshot_persistent(config)
}

pub(crate) fn restore_persistent_snapshot(snapshot: &HermesSetupSnapshot) -> Result<(), String> {
    restore_persistent_snapshot_with_expected(snapshot, None)
}

pub(crate) fn restore_persistent_snapshot_cas(
    snapshot: &HermesSetupSnapshot,
    expected: &HermesSetupSnapshot,
) -> Result<(), String> {
    restore_persistent_snapshot_with_expected(snapshot, Some(expected))
}

fn restore_persistent_snapshot_with_expected(
    snapshot: &HermesSetupSnapshot,
    expected: Option<&HermesSetupSnapshot>,
) -> Result<(), String> {
    let config = snapshot
        .files
        .first()
        .ok_or_else(|| "Hermes setup snapshot is empty".to_string())?
        .path();
    let paths =
        PersistentPaths::for_config(config.to_path_buf()).map_err(|error| error.to_string())?;
    let _lock = acquire_install_lock(&paths.config, INSTALL_LOCK_TIMEOUT)?;
    let _allowlist_lock = acquire_allowlist_lock(&paths.allowlist, INSTALL_LOCK_TIMEOUT)?;
    let current = match expected {
        Some(expected) => {
            for file in &expected.files {
                file.require_current()?;
            }
            expected.files.clone()
        }
        None => paths
            .all()
            .iter()
            .map(|path| FileSnapshot::capture(path).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut transaction = FileTransaction::new(current, atomic_write_private);
    for file in snapshot.files.iter().rev() {
        if let Err(error) = file.restore_in(&mut transaction) {
            let rollback = transaction.rollback();
            return Err(with_rollback_errors(error, rollback));
        }
    }
    Ok(())
}

pub(crate) fn install_persistent(
    config: &Path,
    relay: &Path,
    install_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, CliError> {
    let relay = relay.canonicalize().unwrap_or_else(|_| relay.to_path_buf());
    let relay = crate::agents::portable_executable_path(relay);
    if !relay_is_executable(&relay) {
        return Err(CliError::Install(format!(
            "nemo-relay executable is missing or not executable at {}",
            relay.display()
        )));
    }
    let paths = PersistentPaths::for_config(config.to_path_buf())?;
    let _lock =
        acquire_install_lock(&paths.config, INSTALL_LOCK_TIMEOUT).map_err(CliError::Install)?;
    let _allowlist_lock = acquire_allowlist_lock(&paths.allowlist, INSTALL_LOCK_TIMEOUT)
        .map_err(CliError::Install)?;
    let plugin_config = crate::configuration::user_plugin_runtime_config()?;
    let environment = env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect::<Vec<_>>();
    let enrollment = crate::claude_desktop::enrollment_at(CodingAgent::Hermes, install_dir)
        .map_err(CliError::Install)?
        .ok_or_else(|| {
            CliError::Install("Hermes is not enrolled in the per-user coding-agent proxy".into())
        })?;
    let mut retirement = retire_generation_before_gateway_stop(&paths)?;
    let result = install_persistent_with_generation(
        paths,
        &relay,
        &environment,
        plugin_config.as_ref(),
        Some(&enrollment),
        retirement.as_ref(),
        SystemTime::now(),
        atomic_write_private,
    );
    finish_generation_mutation(result, retirement.as_mut(), "install")
}

pub(crate) fn refresh_proxy_environment(
    config: &Path,
    enrollment: &crate::claude_desktop::AgentProxyEnrollment,
) -> Result<(), CliError> {
    let paths = PersistentPaths::for_config(config.to_path_buf())?;
    let _lock =
        acquire_install_lock(&paths.config, INSTALL_LOCK_TIMEOUT).map_err(CliError::Install)?;
    let proxy_paths = [&paths.env, &paths.env_state, &paths.ca_bundle];
    let snapshots = proxy_paths
        .iter()
        .map(|path| FileSnapshot::capture(path))
        .collect::<Result<Vec<_>, _>>()?;
    let prepared = prepare_proxy_environment(&paths, enrollment)?;
    let mut transaction = FileTransaction::new(snapshots, atomic_write_private);
    let result = (|| {
        transaction.write(&paths.ca_bundle, &prepared.ca_bundle)?;
        transaction.write(&paths.env, prepared.dotenv.as_bytes())?;
        transaction.write(&paths.env_state, &prepared.state)?;
        verify_proxy_environment(&paths, enrollment)
    })();
    if let Err(error) = result {
        return rollback_error("refresh", error, &mut transaction);
    }
    Ok(())
}

pub(crate) fn persistent_state_exists(config: &Path) -> bool {
    PersistentPaths::for_config(config.to_path_buf())
        .ok()
        .and_then(|paths| persistent_paths_have_managed_state(&paths).ok())
        .unwrap_or(false)
}

pub(crate) fn uninstall_persistent(config: &Path) -> Result<Vec<PathBuf>, CliError> {
    let paths = PersistentPaths::for_config(config.to_path_buf())?;
    if !persistent_paths_have_managed_state(&paths)? {
        return Ok(Vec::new());
    }
    let _lock =
        acquire_install_lock(&paths.config, INSTALL_LOCK_TIMEOUT).map_err(CliError::Install)?;
    let _allowlist_lock = acquire_allowlist_lock(&paths.allowlist, INSTALL_LOCK_TIMEOUT)
        .map_err(CliError::Install)?;
    if !persistent_paths_have_managed_state(&paths)? {
        return Ok(Vec::new());
    }
    let mut retirement = retire_generation_before_gateway_stop(&paths)?;
    let result = uninstall_persistent_with(paths, atomic_write_private);
    finish_generation_mutation(result, retirement.as_mut(), "uninstall")
}

fn retire_generation_before_gateway_stop(
    paths: &PersistentPaths,
) -> Result<Option<GenerationRetirement>, CliError> {
    let mut retirement =
        GenerationRetirement::acquire(&paths.generation).map_err(CliError::Install)?;
    if let Some(retirement) = retirement.as_mut() {
        retirement
            .invalidate_for_replacement()
            .map_err(CliError::Install)?;
    }
    Ok(retirement)
}

fn finish_generation_mutation<T>(
    result: Result<T, CliError>,
    retirement: Option<&mut GenerationRetirement>,
    operation: &str,
) -> Result<T, CliError> {
    match result {
        Ok(value) => {
            if let Some(retirement) = retirement {
                retirement.commit_replacement();
            }
            Ok(value)
        }
        Err(error) => {
            let Some(retirement) = retirement else {
                return Err(error);
            };
            match retirement.restore_after_rollback() {
                Ok(()) => Err(error),
                Err(restore_error) => Err(CliError::Install(format!(
                    "{error}; additionally failed to restore the Hermes hook installation generation after {operation}: {restore_error}"
                ))),
            }
        }
    }
}

fn persistent_paths_have_managed_state(paths: &PersistentPaths) -> Result<bool, CliError> {
    if paths.generation.exists() {
        return Ok(true);
    }
    if paths.env_state.exists() {
        return Ok(true);
    }
    if let Some(raw) = read_optional_utf8(&paths.config)? {
        let config = parse_yaml_object(Some(&raw), "Hermes config")?;
        if config_has_managed_state(&config) {
            return Ok(true);
        }
    }
    if let Some(raw) = read_optional_utf8(&paths.allowlist)? {
        let allowlist = parse_json_object(Some(&raw), "Hermes shell-hook allowlist")?;
        if allowlist_has_owned_command(&allowlist, None) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn config_has_managed_state(config: &Value) -> bool {
    owned_command_from_config(config, None).is_some()
}

fn allowlist_has_owned_command(allowlist: &Value, command: Option<&str>) -> bool {
    allowlist
        .get("approvals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("command").and_then(Value::as_str))
        .any(|candidate| {
            command == Some(candidate)
                || (command.is_none() && is_persistent_relay_hook_command(candidate))
        })
}

fn is_persistent_relay_hook_command(command: &str) -> bool {
    command.contains("hook-forward")
        && command.contains("hermes")
        && command.contains("--gateway-url")
        && command.contains("--generation-file")
        && command.contains("--generation-token")
        && command.contains("--fail-closed")
}

fn owned_command_from_config(config: &Value, generation: Option<&Path>) -> Option<String> {
    let (command, _relay, configured_generation) = managed_hook_command(config)?;
    generation
        .is_none_or(|expected| configured_generation == expected)
        .then_some(command)
}

pub(crate) fn diagnose_persistent(
    config_path: &Path,
    install_dir: Option<&Path>,
) -> Result<String, String> {
    let paths = PersistentPaths::for_config(config_path.to_path_buf())
        .map_err(|error| error.to_string())?;
    let raw = fs::read_to_string(&paths.config)
        .map_err(|error| format!("failed to read {}: {error}", paths.config.display()))?;
    let config = parse_yaml_object(Some(&raw), "Hermes config").map_err(|e| e.to_string())?;
    let relay = relay_executable_from_config(&config)?;
    if !relay_is_executable(&relay) {
        return Err(format!(
            "configured nemo-relay executable is missing or not executable at {}",
            relay.display()
        ));
    }
    let generation = InstallGeneration::capture(paths.generation.clone())?;
    let command = persistent_hook_command(&relay, &paths.generation, generation.token())?;
    verify_hook_definitions(&config, &command)?;
    verify_trust(&paths.allowlist, &command)?;

    let enrollment = crate::claude_desktop::enrollment_at(CodingAgent::Hermes, install_dir)?
        .ok_or_else(|| "Hermes is not enrolled in the per-user coding-agent proxy".to_string())?;
    verify_proxy_environment(&paths, &enrollment)?;
    let observability_mode = configured_observability_mode(&config, true);
    Ok(format!(
        "proxy {} and {} hooks trusted at {}; provider observability: {observability_mode}",
        enrollment.gateway_url,
        CodingAgent::Hermes.hook_events().len(),
        paths.config.display()
    ))
}

fn configured_observability_mode(config: &Value, enrollment_verified: bool) -> &'static str {
    let native_provider = [
        config.pointer("/model/base_url"),
        config.pointer("/model/baseUrl"),
        config.get("base_url"),
        config.get("baseUrl"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(crate::claude_desktop::managed_native_provider_url);
    if enrollment_verified && native_provider {
        "managed_proxy"
    } else {
        "hook_only_degraded"
    }
}

/// Returns the exact Relay binary configured in Hermes's managed hook command.
pub(crate) fn configured_relay_executable(config_path: &Path) -> Result<PathBuf, String> {
    let raw = fs::read_to_string(config_path)
        .map_err(|error| format!("failed to read {}: {error}", config_path.display()))?;
    let config = parse_yaml_object(Some(&raw), "Hermes config").map_err(|e| e.to_string())?;
    let relay = relay_executable_from_config(&config)?;
    if !relay_is_executable(&relay) {
        return Err(format!(
            "configured nemo-relay executable is missing or not executable at {}",
            relay.display()
        ));
    }
    Ok(relay)
}

pub(crate) fn ensure_no_legacy_mcp_state(config_path: &Path) -> Result<(), String> {
    let Some(raw) = read_optional_utf8(config_path).map_err(|error| error.to_string())? else {
        return Ok(());
    };
    let root = parse_yaml_object(Some(&raw), "Hermes config").map_err(|error| error.to_string())?;
    if has_legacy_mcp_state(&root) {
        return Err(format!(
            "legacy Hermes MCP-gateway state is present at {}; this release does not migrate it in place. Run `nemo-relay uninstall hermes` with the old Relay binary, then run `nemo-relay install hermes` with this binary",
            config_path.display()
        ));
    }
    Ok(())
}

fn relay_executable_from_config(config: &Value) -> Result<PathBuf, String> {
    managed_hook_command(config)
        .map(|(_command, relay, _generation)| relay)
        .ok_or_else(|| "Hermes managed Relay hooks are missing or inconsistent".into())
}

#[allow(clippy::too_many_arguments)]
fn install_persistent_with_generation<W>(
    paths: PersistentPaths,
    relay: &Path,
    environment: &[String],
    plugin_config: Option<&Value>,
    enrollment: Option<&crate::claude_desktop::AgentProxyEnrollment>,
    generation_transaction: Option<&GenerationRetirement>,
    now: SystemTime,
    write: W,
) -> Result<Vec<PathBuf>, CliError>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    let snapshots = paths
        .all()
        .iter()
        .map(|path| FileSnapshot::capture(path))
        .collect::<Result<Vec<_>, _>>()?;
    let existing_config = read_optional_utf8(&paths.config)?;
    let existing_allowlist = read_optional_utf8(&paths.allowlist)?;
    let previous_command = match existing_config.as_deref() {
        Some(raw) => {
            let root = parse_yaml_object(Some(raw), "Hermes config")?;
            if has_legacy_mcp_state(&root) {
                return Err(CliError::Install(format!(
                    "legacy Hermes MCP-gateway state is present at {}; this release does not migrate it in place. Run `nemo-relay uninstall hermes` with the old Relay binary, then run `nemo-relay install hermes` with this binary",
                    paths.config.display()
                )));
            }
            owned_install_command(&root, relay, Some(&paths.generation))?
        }
        None => None,
    };
    let _ = (environment, plugin_config);
    let token = uuid::Uuid::now_v7().to_string();
    let command =
        persistent_hook_command(relay, &paths.generation, &token).map_err(CliError::Install)?;
    let config = persistent_config(
        existing_config.as_deref(),
        relay,
        &command,
        &paths.generation,
        &token,
        environment,
    )?;
    let allowlist = trusted_hooks(
        existing_allowlist.as_deref(),
        previous_command.as_deref(),
        &command,
        relay,
        now,
    )?;
    let config = yaml_bytes(&config)?;
    let allowlist = json_bytes(&allowlist)?;
    let generation = format!("{token}\n").into_bytes();
    let proxy_environment = enrollment
        .map(|enrollment| prepare_proxy_environment(&paths, enrollment))
        .transpose()?;

    let mut transaction = FileTransaction::new(snapshots, write);
    let result = (|| {
        // Trust is published before config so Hermes never observes a configured hook without
        // its exact approval. The config write is the transaction's commit point.
        transaction.write(&paths.generation, &generation)?;
        transaction.write(&paths.allowlist, &allowlist)?;
        transaction.write(&paths.config, &config)?;
        if let Some(proxy_environment) = proxy_environment.as_ref() {
            transaction.write(&paths.ca_bundle, &proxy_environment.ca_bundle)?;
            transaction.write(&paths.env, proxy_environment.dotenv.as_bytes())?;
            transaction.write(&paths.env_state, &proxy_environment.state)?;
        }
        verify_install(&paths, &command, &token, generation_transaction)
    })();
    if let Err(error) = result {
        return rollback_error("install", error, &mut transaction);
    }
    Ok(paths.all().into_iter().collect())
}

fn uninstall_persistent_with<W>(paths: PersistentPaths, write: W) -> Result<Vec<PathBuf>, CliError>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    uninstall_persistent_with_hook(paths, write, || {})
}

fn uninstall_persistent_with_hook<W>(
    paths: PersistentPaths,
    write: W,
    mut before_commit: impl FnMut(),
) -> Result<Vec<PathBuf>, CliError>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    let affected = paths
        .all()
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    let snapshots = paths
        .all()
        .iter()
        .map(|path| FileSnapshot::capture(path))
        .collect::<Result<Vec<_>, _>>()?;
    let proxy_environment = restored_proxy_environment(&paths)?;
    let config = read_optional_utf8(&paths.config)?
        .map(|raw| {
            let mut root = parse_yaml_object(Some(&raw), "Hermes config")?;
            let owned = owned_command_from_config(&root, Some(&paths.generation));
            strip_owned_hooks(&mut root, owned.as_deref())?;
            remove_owned_mcp(&mut root, owned.is_some())?;
            if root.as_object().is_some_and(Map::is_empty) {
                Ok(None)
            } else {
                yaml_bytes(&root).map(Some)
            }
        })
        .transpose()?
        .flatten();
    let owned = read_optional_utf8(&paths.config)?
        .and_then(|raw| parse_yaml_object(Some(&raw), "Hermes config").ok())
        .and_then(|root| owned_command_from_config(&root, Some(&paths.generation)));
    let allowlist = read_optional_utf8(&paths.allowlist)?
        .map(|raw| {
            let mut root = parse_json_object(Some(&raw), "Hermes shell-hook allowlist")?;
            let object = root
                .as_object_mut()
                .expect("allowlist root checked as object");
            if let Some(approvals) = object.get_mut("approvals") {
                let approvals = approvals.as_array_mut().ok_or_else(|| {
                    CliError::Install(
                        "Hermes shell-hook allowlist approvals must be an array".into(),
                    )
                })?;
                approvals.retain(|entry| {
                    entry
                        .get("command")
                        .and_then(Value::as_str)
                        .is_none_or(|command| Some(command) != owned.as_deref())
                });
                if approvals.is_empty() {
                    object.remove("approvals");
                }
            }
            if object.is_empty() {
                Ok(None)
            } else {
                json_bytes(&root).map(Some)
            }
        })
        .transpose()?
        .flatten();

    before_commit();
    let mut transaction = FileTransaction::new(snapshots, write);
    let result = (|| {
        transaction.remove(&paths.generation)?;
        transaction.replace(&paths.allowlist, allowlist.as_deref())?;
        transaction.replace(&paths.config, config.as_deref())?;
        if let Some(dotenv) = proxy_environment.as_ref() {
            transaction.replace(&paths.env, dotenv.as_deref().map(str::as_bytes))?;
        }
        transaction.remove(&paths.env_state)?;
        transaction.remove(&paths.ca_bundle)?;
        verify_uninstall(&paths, owned.as_deref())
    })();
    if let Err(error) = result {
        return rollback_error("uninstall", error, &mut transaction);
    }
    Ok(affected)
}

fn rollback_error<T, W>(
    operation: &str,
    error: String,
    transaction: &mut FileTransaction<W>,
) -> Result<T, CliError>
where
    W: FnMut(&Path, &[u8]) -> Result<(), String>,
{
    let error = with_rollback_errors(error, transaction.rollback());
    Err(CliError::Install(format!(
        "failed to {operation} Hermes proxy integration: {error}"
    )))
}

fn with_rollback_errors(error: String, rollback_errors: Vec<String>) -> String {
    if rollback_errors.is_empty() {
        error
    } else {
        format!(
            "{error}; rollback also failed: {}",
            rollback_errors.join("; ")
        )
    }
}

fn verify_install(
    paths: &PersistentPaths,
    command: &str,
    token: &str,
    generation_transaction: Option<&GenerationRetirement>,
) -> Result<(), String> {
    let raw = fs::read_to_string(&paths.config)
        .map_err(|error| format!("failed to verify {}: {error}", paths.config.display()))?;
    let config = parse_yaml_object(Some(&raw), "Hermes config").map_err(|e| e.to_string())?;
    verify_hook_definitions(&config, command)?;
    verify_trust(&paths.allowlist, command)?;

    let actual_token = match generation_transaction {
        Some(transaction) => transaction.active_visible_token()?,
        None => InstallGeneration::capture(paths.generation.clone())?
            .token()
            .to_owned(),
    };
    if actual_token != token {
        return Err("Hermes hook generation did not persist exactly".into());
    }
    Ok(())
}

fn verify_hook_definitions(config: &Value, command: &str) -> Result<(), String> {
    for event in CodingAgent::Hermes.hook_events() {
        let groups = config
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("Hermes hook {event} is missing"))?;
        let matching = groups
            .iter()
            .filter(|group| group.get("command").and_then(Value::as_str) == Some(command))
            .count();
        if matching != 1 {
            return Err(format!(
                "Hermes hook {event} expected exactly one trusted Relay handler"
            ));
        }
    }
    for (event, groups) in config
        .get("hooks")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::iter)
    {
        let groups = groups
            .as_array()
            .ok_or_else(|| format!("Hermes {event} hooks must be an array"))?;
        if !CodingAgent::Hermes.hook_events().contains(&event.as_str())
            && groups
                .iter()
                .any(|group| group.get("command").and_then(Value::as_str) == Some(command))
        {
            return Err("Hermes config contains an unexpected Relay hook handler".into());
        }
    }
    Ok(())
}

fn verify_uninstall(paths: &PersistentPaths, owned_command: Option<&str>) -> Result<(), String> {
    if paths.generation.exists() {
        return Err("Hermes hook generation fence still exists".into());
    }
    if paths.env_state.exists() || paths.ca_bundle.exists() {
        return Err("Hermes proxy environment state still exists".into());
    }
    if let Some(raw) = read_optional_utf8(&paths.config).map_err(|error| error.to_string())? {
        let config = parse_yaml_object(Some(&raw), "Hermes config").map_err(|e| e.to_string())?;
        if config_has_managed_state(&config) {
            return Err("managed Hermes Relay config still exists".into());
        }
    }
    if let Some(raw) = read_optional_utf8(&paths.allowlist).map_err(|error| error.to_string())? {
        let allowlist = parse_json_object(Some(&raw), "Hermes shell-hook allowlist")
            .map_err(|e| e.to_string())?;
        if allowlist_has_owned_command(&allowlist, owned_command) {
            return Err("managed Hermes Relay trust approval still exists".into());
        }
    }
    Ok(())
}

struct PreparedProxyEnvironment {
    dotenv: String,
    state: Vec<u8>,
    ca_bundle: Vec<u8>,
}

fn prepare_proxy_environment(
    paths: &PersistentPaths,
    enrollment: &crate::claude_desktop::AgentProxyEnrollment,
) -> Result<PreparedProxyEnvironment, CliError> {
    let existing = read_optional_utf8(&paths.env)?.unwrap_or_default();
    let current = parse_dotenv_values(&existing)?;
    let previous = match read_optional_utf8(&paths.env_state)? {
        Some(raw) => {
            serde_json::from_str::<ProxyEnvState>(&raw)
                .map_err(|error| {
                    CliError::Install(format!(
                        "invalid Hermes proxy environment state {}: {error}",
                        paths.env_state.display()
                    ))
                })?
                .previous
        }
        None => PROXY_ENV_NAMES
            .iter()
            .map(|name| ((*name).to_string(), current.get(*name).cloned()))
            .collect(),
    };
    let root = fs::read(&enrollment.root_ca_pem).map_err(|error| {
        CliError::Install(format!(
            "failed to read proxy CA {}: {error}",
            enrollment.root_ca_pem.display()
        ))
    })?;
    // `current` contains Relay's generated bundle on refresh. Select trust inputs from the
    // durable pre-enrollment snapshot so CA rotation never replaces the user's corporate/public
    // roots with the previous Relay root.
    let mut ca_bundle = select_base_ca_bundle(&previous, &paths.ca_bundle)?;
    if !ca_bundle.is_empty() && !ca_bundle.ends_with(b"\n") {
        ca_bundle.push(b'\n');
    }
    ca_bundle.extend_from_slice(&root);
    let ca_path = paths.ca_bundle.display().to_string();
    let no_proxy = sanitized_previous_no_proxy(&previous);
    let generated = BTreeMap::from([
        ("HTTP_PROXY".into(), enrollment.proxy_url.clone()),
        ("HTTPS_PROXY".into(), enrollment.proxy_url.clone()),
        ("http_proxy".into(), enrollment.proxy_url.clone()),
        ("https_proxy".into(), enrollment.proxy_url.clone()),
        ("NO_PROXY".into(), no_proxy.clone()),
        ("no_proxy".into(), no_proxy),
        ("REQUESTS_CA_BUNDLE".into(), ca_path.clone()),
        ("SSL_CERT_FILE".into(), ca_path.clone()),
        ("NODE_EXTRA_CA_CERTS".into(), ca_path.clone()),
        ("AWS_CA_BUNDLE".into(), ca_path),
    ]);
    let dotenv = replace_dotenv_values(&existing, &generated)?;
    let state = serde_json::to_vec_pretty(&ProxyEnvState {
        schema_version: 1,
        previous,
        generated,
    })
    .map_err(|error| CliError::Install(error.to_string()))?;
    Ok(PreparedProxyEnvironment {
        dotenv,
        state,
        ca_bundle,
    })
}

fn sanitized_previous_no_proxy(previous: &BTreeMap<String, Option<String>>) -> String {
    ["NO_PROXY", "no_proxy"]
        .into_iter()
        .filter_map(|name| previous.get(name).and_then(Option::as_deref))
        .map(crate::claude_desktop::sanitize_no_proxy)
        .flat_map(|value| {
            value
                .split(',')
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .filter(|entry| !entry.is_empty())
        .fold(Vec::<String>::new(), |mut entries, entry| {
            if !entries
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&entry))
            {
                entries.push(entry);
            }
            entries
        })
        .join(",")
}

fn select_base_ca_bundle(
    previous: &BTreeMap<String, Option<String>>,
    target: &Path,
) -> Result<Vec<u8>, CliError> {
    let mut configured = None::<(&str, PathBuf)>;
    for name in ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "AWS_CA_BUNDLE"] {
        let Some(path) = previous
            .get(name)
            .and_then(Option::as_deref)
            .map(PathBuf::from)
        else {
            continue;
        };
        if let Some((prior_name, prior_path)) = configured.as_ref()
            && prior_path != &path
        {
            return Err(CliError::Install(format!(
                "original Hermes {prior_name} and {name} select different CA bundles; make the trust source unambiguous before enrollment"
            )));
        }
        configured = Some((name, path));
    }
    let mut selected_path = None;
    let mut bundle = match configured {
        Some((name, path)) => {
            if path == target {
                return Err(CliError::Install(format!(
                    "original Hermes {name} resolves to Relay's managed target {}; restore the original CA setting before reinstalling",
                    target.display()
                )));
            }
            selected_path = Some(path.clone());
            read_ca_source(&path, "base CA bundle")?
        }
        None => native_ca_bundle()?,
    };

    if let Some(path) = previous
        .get("NODE_EXTRA_CA_CERTS")
        .and_then(Option::as_deref)
        .map(PathBuf::from)
        .filter(|path| Some(path) != selected_path.as_ref())
    {
        if path == target {
            return Err(CliError::Install(format!(
                "original Hermes NODE_EXTRA_CA_CERTS resolves to Relay's managed target {}; restore the original CA setting before reinstalling",
                target.display()
            )));
        }
        if !bundle.is_empty() && !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(&read_ca_source(&path, "NODE_EXTRA_CA_CERTS")?);
    }
    Ok(bundle)
}

fn read_ca_source(path: &Path, description: &str) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| {
        CliError::Install(format!(
            "failed to read Hermes {description} {}: {error}",
            path.display()
        ))
    })
}

fn native_ca_bundle() -> Result<Vec<u8>, CliError> {
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        let details = native
            .errors
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "the platform certificate store returned no certificates".into());
        return Err(CliError::Install(format!(
            "failed to export native trust roots for Hermes: {details}"
        )));
    }
    let mut bundle = Vec::new();
    for certificate in native.certs {
        bundle.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            bundle.extend_from_slice(line);
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    Ok(bundle)
}

fn restored_proxy_environment(paths: &PersistentPaths) -> Result<Option<Option<String>>, CliError> {
    let Some(raw) = read_optional_utf8(&paths.env_state)? else {
        return Ok(None);
    };
    let state = serde_json::from_str::<ProxyEnvState>(&raw).map_err(|error| {
        CliError::Install(format!(
            "invalid Hermes proxy environment state {}: {error}",
            paths.env_state.display()
        ))
    })?;
    let existing = read_optional_utf8(&paths.env)?.unwrap_or_default();
    let current = parse_dotenv_values(&existing)?;
    let restorations = state
        .previous
        .iter()
        .filter(|(name, _)| current.get(*name) == state.generated.get(*name))
        .map(|(name, previous)| (name.clone(), previous.clone()))
        .collect();
    let restored = replace_dotenv_optional_values(&existing, &restorations)?;
    Ok(Some((!restored.trim().is_empty()).then_some(restored)))
}

fn verify_proxy_environment(
    paths: &PersistentPaths,
    enrollment: &crate::claude_desktop::AgentProxyEnrollment,
) -> Result<(), String> {
    let raw = fs::read_to_string(&paths.env_state)
        .map_err(|error| format!("failed to read {}: {error}", paths.env_state.display()))?;
    let state = serde_json::from_str::<ProxyEnvState>(&raw)
        .map_err(|error| format!("invalid Hermes proxy environment state: {error}"))?;
    if state.schema_version != 1
        || state.generated.get("HTTPS_PROXY") != Some(&enrollment.proxy_url)
        || state.generated.get("REQUESTS_CA_BUNDLE") != Some(&paths.ca_bundle.display().to_string())
    {
        return Err("Hermes proxy environment state is stale".into());
    }
    let dotenv = fs::read_to_string(&paths.env)
        .map_err(|error| format!("failed to read {}: {error}", paths.env.display()))?;
    let values = parse_dotenv_values(&dotenv).map_err(|error| error.to_string())?;
    for (name, expected) in &state.generated {
        if values.get(name) != Some(expected) {
            return Err(format!(
                "Hermes .env field {name} differs from enrolled proxy state"
            ));
        }
        if let Some(ambient) = env::var_os(name).and_then(|value| value.into_string().ok())
            && ambient != *expected
        {
            return Err(format!(
                "ambient {name} overrides Hermes .env with a different value; unset it or align it with the enrolled proxy"
            ));
        }
    }
    if !paths.ca_bundle.is_file() {
        return Err(format!(
            "Hermes proxy CA bundle is missing at {}",
            paths.ca_bundle.display()
        ));
    }
    let expected_root = fs::read(&enrollment.root_ca_pem).map_err(|error| {
        format!(
            "failed to read enrolled proxy CA {}: {error}",
            enrollment.root_ca_pem.display()
        )
    })?;
    let actual_bundle = fs::read(&paths.ca_bundle)
        .map_err(|error| format!("failed to read {}: {error}", paths.ca_bundle.display()))?;
    if !actual_bundle.ends_with(&expected_root) {
        return Err("Hermes proxy CA bundle does not contain the enrolled proxy CA".into());
    }
    Ok(())
}

fn parse_dotenv_values(raw: &str) -> Result<BTreeMap<String, String>, CliError> {
    let mut values = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let candidate = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((name, value)) = candidate.split_once('=') else {
            continue;
        };
        if PROXY_ENV_NAMES.contains(&name) && values.insert(name.into(), value.into()).is_some() {
            return Err(CliError::Install(format!(
                "Hermes .env contains duplicate managed field {name}; remove the duplicate before installing"
            )));
        }
    }
    Ok(values)
}

fn replace_dotenv_values(raw: &str, values: &BTreeMap<String, String>) -> Result<String, CliError> {
    replace_dotenv_optional_values(
        raw,
        &values
            .iter()
            .map(|(name, value)| (name.clone(), Some(value.clone())))
            .collect(),
    )
}

fn replace_dotenv_optional_values(
    raw: &str,
    values: &BTreeMap<String, Option<String>>,
) -> Result<String, CliError> {
    let _ = parse_dotenv_values(raw)?;
    let mut lines = raw
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            let candidate = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            candidate
                .split_once('=')
                .is_none_or(|(name, _)| !values.contains_key(name))
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines.extend(
        values
            .iter()
            .filter_map(|(name, value)| value.as_ref().map(|value| format!("{name}={value}"))),
    );
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{}\n", lines.join("\n")))
    }
}

#[cfg(test)]
#[path = "../../../tests/coverage/agents/hermes_tests.rs"]
mod tests;
