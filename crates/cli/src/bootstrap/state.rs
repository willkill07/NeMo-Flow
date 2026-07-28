// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-user startup lock and ownership record for the agent proxy.

#[cfg(test)]
use std::env;
use std::fs;
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(test)]
use std::thread;
#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
use reqwest::Url;
#[cfg(test)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::filesystem::atomic_write;
#[cfg(test)]
use crate::filesystem::{LockAttempt, try_lock_exclusive};

#[cfg(test)]
use super::{BOOTSTRAP_LOCK_TIMEOUT, BOOTSTRAP_PROTOCOL_VERSION};
#[cfg(test)]
use crate::gateway::client::{RelayHealth, probe, request_shutdown};

#[cfg(test)]
pub(crate) const BOOTSTRAP_STATE_DIR_ENV: &str = "NEMO_RELAY_BOOTSTRAP_STATE_DIR";
pub(crate) const BOOTSTRAP_SHUTDOWN_TOKEN_ENV: &str = "NEMO_RELAY_BOOTSTRAP_SHUTDOWN_TOKEN";
#[cfg(test)]
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) struct OwnerRecord {
    service: String,
    version: String,
    bootstrap_protocol: u64,
    pid: u32,
    url: String,
    shutdown_token: String,
    bootstrap_fingerprint: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) struct RecoveryRecord {
    pub(super) from_instance: String,
    pub(super) endpoint_url: String,
    pub(super) to_instance: String,
}

#[cfg(test)]
impl OwnerRecord {
    fn new(pid: u32, url: &str, shutdown_token: &str, fingerprint: Option<&str>) -> Self {
        Self {
            service: "nemo-relay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            bootstrap_protocol: BOOTSTRAP_PROTOCOL_VERSION,
            pid,
            url: url.into(),
            shutdown_token: shutdown_token.into(),
            bootstrap_fingerprint: fingerprint.map(str::to_owned),
        }
    }

    fn valid_for(&self, url: &str) -> bool {
        self.service == "nemo-relay"
            && self.bootstrap_protocol == BOOTSTRAP_PROTOCOL_VERSION
            && self.url == url
            && !self.shutdown_token.is_empty()
            && self
                .bootstrap_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| !fingerprint.is_empty())
    }
}

/// Removes this process's ownership record when the gateway server exits.
#[derive(Debug)]
#[cfg(test)]
pub(crate) struct OwnerGuard {
    path: PathBuf,
    record: OwnerRecord,
}

#[cfg(test)]
impl Drop for OwnerGuard {
    fn drop(&mut self) {
        let _ = remove_if_matches(&self.path, &self.record);
    }
}

pub(crate) fn state_dir() -> Result<PathBuf, String> {
    crate::configuration::user_config_dir()
        .map(|path| path.join("bootstrap"))
        .ok_or_else(|| {
            "cannot determine the per-user NeMo Relay bootstrap state directory; set HOME or USERPROFILE"
                .into()
        })
}

pub(crate) fn legacy_gateway_artifact() -> Result<Option<PathBuf>, String> {
    let state = state_dir()?;
    let endpoint = "127.0.0.1-47632";
    for path in [
        state.join(format!("sidecar-{endpoint}.owner.json")),
        state.join(format!("gateway-{endpoint}.recovery.json")),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect legacy gateway state {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("failed to secure {}: {error}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn owner_path(state: &Path, url: &str) -> PathBuf {
    state.join(format!("sidecar-{}.owner.json", lock_name(url)))
}

#[cfg(test)]
pub(crate) fn lock_path(state: &Path, url: &str) -> PathBuf {
    state.join(format!("gateway-{}.lock", lock_name(url)))
}

#[cfg(test)]
fn recovery_path(state: &Path, url: &str) -> PathBuf {
    state.join(format!("gateway-{}.recovery.json", lock_name(url)))
}

#[cfg(test)]
pub(super) fn read_recovery(state: &Path, url: &str) -> Result<Option<RecoveryRecord>, String> {
    let path = recovery_path(state, url);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            format!(
                "failed to parse gateway recovery {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to read gateway recovery {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
pub(super) fn write_recovery(
    state: &Path,
    url: &str,
    record: &RecoveryRecord,
) -> Result<(), String> {
    let path = recovery_path(state, url);
    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("failed to encode gateway recovery: {error}"))?;
    atomic_write(&path, &bytes)
}

#[cfg(test)]
pub(crate) fn lock_endpoint(state: &Path, url: &str) -> Result<fs::File, String> {
    lock_endpoint_for(state, url, BOOTSTRAP_LOCK_TIMEOUT)
}

#[cfg(test)]
pub(crate) fn lock_endpoint_for(
    state: &Path,
    url: &str,
    timeout: Duration,
) -> Result<fs::File, String> {
    create_private_dir(state)?;
    let path = lock_path(state, url);
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("failed to open gateway lock {}: {error}", path.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match try_lock_exclusive(&lock) {
            Ok(LockAttempt::Acquired) => return Ok(lock),
            Ok(LockAttempt::Contended) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(LockAttempt::Contended) => {
                return Err(format!(
                    "timed out waiting for gateway startup lock {}",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "failed to acquire gateway startup lock {}: {error}",
                    path.display()
                ));
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn publish_owner_from_env(
    address: SocketAddr,
    shutdown_token: Option<&str>,
) -> Result<Option<OwnerGuard>, String> {
    let state = env::var_os(BOOTSTRAP_STATE_DIR_ENV);
    if state.is_none() && shutdown_token.is_none() {
        return Ok(None);
    }
    let state = state
        .map(PathBuf::from)
        .ok_or_else(|| format!("{BOOTSTRAP_STATE_DIR_ENV} is required for managed bootstrap"))?;
    if !state.is_absolute() {
        return Err(format!(
            "{BOOTSTRAP_STATE_DIR_ENV} must be an absolute path, got {}",
            state.display()
        ));
    }
    let token = shutdown_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            format!("{BOOTSTRAP_SHUTDOWN_TOKEN_ENV} is required for managed bootstrap")
        })?;
    if !address.ip().is_loopback() {
        return Err(format!(
            "managed bootstrap ownership requires a loopback address, got {address}"
        ));
    }
    create_private_dir(&state)?;
    let url = format!("http://{address}");
    let fingerprint = env::var(crate::configuration::BOOTSTRAP_FINGERPRINT_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let record = OwnerRecord::new(std::process::id(), &url, token, fingerprint.as_deref());
    let path = owner_path(&state, &url);
    write_owner_record(&path, &record)?;
    Ok(Some(OwnerGuard { path, record }))
}

#[cfg(test)]
pub(crate) fn stop_owned_and_reset(url: &str) -> Result<(), String> {
    let state = state_dir()?;
    if !state.exists() {
        return Ok(());
    }
    let _lock = lock_endpoint(&state, url)?;
    let path = owner_path(&state, url);
    let Some(owner) = read_owner_record(&path)? else {
        return Ok(());
    };
    if !owner.valid_for(url) {
        return Err(format!(
            "refusing to stop gateway from invalid ownership record {}",
            path.display()
        ));
    }
    match probe(url, owner.bootstrap_fingerprint.as_deref()) {
        RelayHealth::Unavailable => {
            remove_if_matches(&path, &owner)?;
            return Ok(());
        }
        RelayHealth::Compatible => {}
        RelayHealth::Incompatible | RelayHealth::Foreign => {
            return Err(format!(
                "refusing to stop an unverified process at managed gateway URL {url}"
            ));
        }
    }
    request_shutdown(
        url,
        owner
            .bootstrap_fingerprint
            .as_deref()
            .expect("validated owner record has a bootstrap fingerprint"),
        &owner.shutdown_token,
    )?;
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    loop {
        match probe(url, owner.bootstrap_fingerprint.as_deref()) {
            RelayHealth::Unavailable => break,
            RelayHealth::Compatible if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            RelayHealth::Compatible => {
                return Err(format!("managed Relay gateway at {url} did not stop"));
            }
            RelayHealth::Incompatible | RelayHealth::Foreign => {
                return Err(format!(
                    "a different process replaced the managed Relay gateway at {url} during shutdown"
                ));
            }
        }
    }
    remove_if_matches(&path, &owner)
}

#[cfg(test)]
fn write_owner_record(path: &Path, record: &OwnerRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("failed to encode gateway ownership: {error}"))?;
    atomic_write(path, &bytes)
}

#[cfg(test)]
pub(super) fn read_owner_record(path: &Path) -> Result<Option<OwnerRecord>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            format!(
                "failed to parse gateway ownership {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to read gateway ownership {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
fn remove_if_matches(path: &Path, expected: &OwnerRecord) -> Result<(), String> {
    if read_owner_record(path)?.as_ref() != Some(expected) {
        return Ok(());
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove gateway ownership {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
pub(crate) fn lock_name(url: &str) -> String {
    let raw = Url::parse(url)
        .ok()
        .and_then(|parsed| {
            let host = parsed.host_str()?;
            let port = parsed.port_or_known_default()?;
            Some(format!("{host}-{port}"))
        })
        .unwrap_or_else(|| url.to_string());
    let sanitized = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".into()
    } else {
        sanitized
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/shared/bootstrap_state_tests.rs"]
mod tests;
