// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persisted installer-owned state for the unified per-user coding-agent proxy.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::settings::{SettingsPatch, UpstreamProxy};

pub(super) const STATE_SCHEMA_VERSION: u32 = 6;
pub(super) const STATE_FILE_NAME: &str = "state.json";
pub(super) const JOURNAL_FILE_NAME: &str = "install-journal.json";
const LOCATOR_FILE_NAME: &str = ".nemo-relay-agent-proxy-state-path";
const LEGACY_LOCATOR_FILE_NAME: &str = "claude-desktop-state-path";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CertificateState {
    pub(super) root_der: PathBuf,
    pub(super) root_pem: PathBuf,
    #[serde(default)]
    pub(super) ca_key_der: PathBuf,
    #[serde(default)]
    pub(super) ca_key_handle: Option<String>,
    #[serde(default = "default_ca_signer_kind")]
    pub(super) ca_signer_kind: String,
    pub(super) root_sha1: String,
    pub(super) root_sha256: String,
    #[serde(default)]
    pub(super) host_set_sha256: String,
    pub(super) root_common_name: String,
    pub(super) not_before: String,
    pub(super) not_after: String,
}

fn default_ca_signer_kind() -> String {
    "file-pkcs8".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AgentEnrollment {
    pub(super) username: String,
    pub(super) token: String,
    pub(super) installed_at: String,
    pub(super) upstream_proxy: Option<UpstreamProxy>,
    #[serde(default)]
    pub(super) client_ca_bundle_source: Option<PathBuf>,
    #[serde(default)]
    pub(super) client_ca_bundle_variable: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DesktopState {
    pub(super) schema_version: u32,
    pub(super) generation: String,
    pub(super) installed_at: String,
    pub(super) relay_version: String,
    pub(super) relay_binary: PathBuf,
    pub(super) install_root: PathBuf,
    pub(super) user_config_dir: PathBuf,
    pub(super) platform: String,
    pub(super) service_identity: Option<String>,
    pub(super) bind: SocketAddr,
    pub(super) proxy_username: String,
    pub(super) proxy_token: String,
    pub(super) upstream_proxy: Option<UpstreamProxy>,
    pub(super) gateway_fingerprint: String,
    pub(super) max_hook_payload_bytes: usize,
    pub(super) configuration_fingerprint: String,
    pub(super) certificate: CertificateState,
    pub(super) settings: SettingsPatch,
    #[serde(default)]
    pub(super) claude_code_installed: bool,
    #[serde(default)]
    pub(super) claude_desktop_installed: bool,
    #[serde(default)]
    pub(super) enrollments: BTreeMap<String, AgentEnrollment>,
}

impl DesktopState {
    pub(super) fn state_path(&self) -> PathBuf {
        self.install_root.join(STATE_FILE_NAME)
    }

    pub(super) fn proxy_url(&self) -> String {
        self.proxy_url_for("claude").unwrap_or_else(|| {
            format!(
                "https://{}:{}@{}",
                self.proxy_username, self.proxy_token, self.bind
            )
        })
    }

    pub(super) fn claude_enrolled(&self) -> bool {
        self.enrollments.contains_key("claude")
    }

    pub(super) fn proxy_url_for(&self, agent: &str) -> Option<String> {
        let enrollment = self.enrollments.get(agent)?;
        Some(format!(
            "https://{}:{}@{}",
            enrollment.username, enrollment.token, self.bind
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct InstallJournal {
    pub(super) schema_version: u32,
    pub(super) operation: String,
    pub(super) stage: String,
    pub(super) generation: String,
    pub(super) old_state: Option<DesktopState>,
    #[serde(default)]
    pub(super) settings_snapshot: Option<crate::filesystem::FileSnapshot>,
    #[serde(default)]
    pub(super) provider_backup_snapshot: Option<crate::filesystem::FileSnapshot>,
    #[serde(default)]
    pub(super) marketplace_snapshot:
        Option<crate::installation::marketplace::DurableMarketplaceSnapshot>,
    #[serde(default)]
    pub(super) settings_result_snapshot: Option<crate::filesystem::FileSnapshot>,
    #[serde(default)]
    pub(super) provider_backup_result_snapshot: Option<crate::filesystem::FileSnapshot>,
    #[serde(default)]
    pub(super) marketplace_result_snapshot:
        Option<crate::installation::marketplace::DurableMarketplaceSnapshot>,
}

pub(super) fn install_root(install_dir: Option<&Path>) -> PathBuf {
    let selected = install_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::installation::marketplace::default_marketplace_install_dir)
        .join("agent-proxy");
    if selected.is_absolute() {
        selected
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&selected))
            .unwrap_or(selected)
    }
}

pub(super) fn legacy_state_path(install_dir: Option<&Path>) -> PathBuf {
    let selected = install_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::installation::marketplace::default_marketplace_install_dir)
        .join("claude-desktop")
        .join(STATE_FILE_NAME);
    if selected.is_absolute() {
        selected
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&selected))
            .unwrap_or(selected)
    }
}

pub(super) fn ensure_no_legacy_state(install_dir: Option<&Path>) -> Result<(), String> {
    let health = crate::gateway::client::probe(crate::bootstrap::LEGACY_FIXED_URL, None);
    ensure_no_legacy_state_with_health(install_dir, health)
}

fn ensure_no_legacy_state_with_health(
    install_dir: Option<&Path>,
    health: crate::gateway::client::RelayHealth,
) -> Result<(), String> {
    let state = legacy_state_path(install_dir);
    let locator = legacy_locator_path()?;
    let bootstrap = crate::bootstrap::state::legacy_gateway_artifact()?;
    let live_legacy_gateway = matches!(
        health,
        crate::gateway::client::RelayHealth::Compatible
            | crate::gateway::client::RelayHealth::Incompatible
    );
    if state.exists() || locator.exists() || bootstrap.is_some() || live_legacy_gateway {
        let source = if state.exists() {
            state.display().to_string()
        } else if locator.exists() {
            locator.display().to_string()
        } else if let Some(path) = bootstrap {
            path.display().to_string()
        } else {
            crate::bootstrap::LEGACY_FIXED_URL.into()
        };
        return Err(format!(
            "legacy wrapper/MCP-gateway or coding-agent proxy sidecar state exists at {source}; this release does not migrate it in place. Close enrolled agents, run `<old-nemo-relay> uninstall all` and `<old-nemo-relay> uninstall claude-desktop` with the old binary, verify its gateway has stopped and its state is removed, then run `nemo-relay install <agent>` with this binary"
        ));
    }
    Ok(())
}

pub(super) fn resolve_state_path(install_dir: Option<&Path>) -> Result<PathBuf, String> {
    if install_dir.is_none() {
        let locator = locator_path()?;
        if locator.exists() {
            return read_locator();
        }
    }
    Ok(install_root(install_dir).join(STATE_FILE_NAME))
}

pub(super) fn active_user_config_dir() -> Result<PathBuf, String> {
    let state_path = resolve_state_path(None)?;
    if state_path.exists() {
        return read(&state_path).map(|state| state.user_config_dir);
    }
    crate::configuration::user_config_dir()
        .ok_or_else(|| "cannot determine NeMo Relay user configuration directory".to_string())
}

pub(super) fn selected_state_path(install_dir: Option<&Path>) -> PathBuf {
    install_root(install_dir).join(STATE_FILE_NAME)
}

pub(super) fn write_locator(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "coding-agent proxy state locator requires an absolute path, got {}",
            path.display()
        ));
    }
    let locator = locator_path()?;
    let mut bytes = path.display().to_string().into_bytes();
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&locator, &bytes)
}

pub(super) fn remove_locator_if_matches(path: &Path) -> Result<(), String> {
    let locator = locator_path()?;
    if read_locator().ok().as_deref() != Some(path) {
        return Ok(());
    }
    remove_file_if_present(&locator)
}

fn read_locator() -> Result<PathBuf, String> {
    let locator = locator_path()?;
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        &locator,
        "coding-agent proxy state locator",
    )?;
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", locator.display()))?
        .trim();
    let path = PathBuf::from(raw);
    if raw.is_empty() || !path.is_absolute() {
        return Err(format!(
            "coding-agent proxy state locator {} does not contain an absolute path",
            locator.display()
        ));
    }
    Ok(path)
}

fn locator_path() -> Result<PathBuf, String> {
    crate::agents::shared::host::home_dir().map(|directory| directory.join(LOCATOR_FILE_NAME))
}

fn legacy_locator_path() -> Result<PathBuf, String> {
    let directory = crate::configuration::user_config_dir()
        .ok_or_else(|| "cannot determine NeMo Relay user configuration directory".to_string())?;
    Ok(directory.join(LEGACY_LOCATOR_FILE_NAME))
}

pub(super) fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_FILE_NAME)
}

pub(super) fn read(path: &Path) -> Result<DesktopState, String> {
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        path,
        "coding-agent proxy integration state",
    )?;
    let state = serde_json::from_slice::<DesktopState>(&bytes).map_err(|error| {
        format!(
            "invalid coding-agent proxy state {}: {error}",
            path.display()
        )
    })?;
    validate_state(&state, path)?;
    Ok(state)
}

fn validate_state(state: &DesktopState, path: &Path) -> Result<(), String> {
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported coding-agent proxy state schema {} in {}; reinstall with --force",
            state.schema_version,
            path.display()
        ));
    }
    let selected_root = path.parent().ok_or_else(|| {
        format!(
            "coding-agent proxy state path {} has no parent directory",
            path.display()
        )
    })?;
    if state.install_root != selected_root {
        return Err(format!(
            "refusing coding-agent proxy state whose install root {} differs from selected root {}",
            state.install_root.display(),
            selected_root.display()
        ));
    }
    if !state.user_config_dir.is_absolute() {
        return Err(format!(
            "coding-agent proxy state {} contains a non-absolute user configuration directory",
            path.display()
        ));
    }
    validate_generation(&state.generation)?;
    validate_service_identity(state)?;
    if !matches!(
        state.bind,
        SocketAddr::V4(bind)
            if *bind.ip() == Ipv4Addr::LOCALHOST
                && bind.port() != 0
                && state.bind != super::LEGACY_PROXY_BIND
    ) {
        return Err("coding-agent proxy state contains an invalid loopback listener".into());
    }
    validate_certificate_paths(state)?;
    Ok(())
}

fn validate_service_identity(state: &DesktopState) -> Result<(), String> {
    match (state.platform.as_str(), state.service_identity.as_deref()) {
        ("windows", Some(identity)) if valid_windows_sid(identity) => Ok(()),
        ("windows", _) => {
            Err("Windows coding-agent proxy state is missing its persisted user SID".into())
        }
        ("macos" | "linux", None) => Ok(()),
        ("macos" | "linux", Some(_)) => {
            Err("non-Windows coding-agent proxy state contains a service identity".into())
        }
        (platform, _) => Err(format!(
            "coding-agent proxy state contains an unsupported platform {platform:?}"
        )),
    }
}

fn valid_windows_sid(identity: &str) -> bool {
    let mut parts = identity.split('-');
    parts.next() == Some("S")
        && parts.next().is_some_and(|revision| revision == "1")
        && parts.clone().count() >= 2
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_generation(generation: &str) -> Result<(), String> {
    let mut components = Path::new(generation).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || generation.is_empty()
    {
        return Err("coding-agent proxy state contains an invalid generation identifier".into());
    }
    Ok(())
}

fn validate_certificate_paths(state: &DesktopState) -> Result<(), String> {
    let directory = state
        .install_root
        .join("generations")
        .join(&state.generation);
    for (actual, name) in [
        (&state.certificate.root_der, "root-ca.der"),
        (&state.certificate.root_pem, "root-ca.pem"),
    ] {
        let expected = directory.join(name);
        if actual != &expected {
            return Err(format!(
                "coding-agent proxy certificate path {} differs from installed generation {}",
                actual.display(),
                directory.display()
            ));
        }
    }
    let expected_ca_key = directory.join("root-ca-key.der");
    let expected_common_name = format!("NeMo Relay Agent Proxy {}", state.generation);
    if state.certificate.root_common_name != expected_common_name
        || !valid_hex_fingerprint(&state.certificate.root_sha1, 40)
        || !valid_hex_fingerprint(&state.certificate.root_sha256, 64)
        || !valid_hex_fingerprint(&state.certificate.host_set_sha256, 64)
    {
        return Err(
            "coding-agent proxy certificate state contains invalid identity metadata".into(),
        );
    }
    match state.certificate.ca_signer_kind.as_str() {
        "file-pkcs8"
            if state.certificate.ca_key_der == expected_ca_key
                && state.certificate.ca_key_handle.is_none() => {}
        "macos-keychain"
            if state.certificate.ca_key_der.as_os_str().is_empty()
                && state.certificate.ca_key_handle.as_deref()
                    == Some(
                        format!("com.nvidia.nemo-relay.agent-proxy.ca.{}", state.generation)
                            .as_str(),
                    ) => {}
        "windows-cng"
            if state.certificate.ca_key_der.as_os_str().is_empty()
                && state.certificate.ca_key_handle.as_deref()
                    == Some(
                        format!("NVIDIA NeMo Relay Agent Proxy CA {}", state.generation).as_str(),
                    ) => {}
        signer => {
            return Err(format!(
                "coding-agent proxy certificate state contains invalid {signer} signer metadata"
            ));
        }
    }
    Ok(())
}

fn valid_hex_fingerprint(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn write(state: &DesktopState) -> Result<(), String> {
    write_private_json(&state.state_path(), state)
}

pub(super) fn write_journal(root: &Path, journal: &InstallJournal) -> Result<(), String> {
    write_private_json(&journal_path(root), journal)
}

pub(super) fn read_journal(root: &Path) -> Result<InstallJournal, String> {
    let path = journal_path(root);
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        &path,
        "coding-agent proxy installation journal",
    )?;
    let journal = serde_json::from_slice::<InstallJournal>(&bytes).map_err(|error| {
        format!(
            "invalid coding-agent proxy journal {}: {error}",
            path.display()
        )
    })?;
    if journal.schema_version != STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported coding-agent proxy journal schema {} in {}",
            journal.schema_version,
            path.display()
        ));
    }
    let valid_stage = match journal.operation.as_str() {
        "install" => matches!(
            journal.stage.as_str(),
            "preparing"
                | "prepared"
                | "certificate_trusted"
                | "proxy_healthy"
                | "plugin_ready"
                | "settings_applied"
                | "verifying"
                | "committed"
        ),
        "uninstall" => matches!(
            journal.stage.as_str(),
            "started" | "committed" | "committed_final" | "committed_retained"
        ),
        _ => false,
    };
    if !valid_stage || journal.generation.is_empty() {
        return Err(format!(
            "coding-agent proxy journal {} has invalid operation metadata",
            path.display()
        ));
    }
    validate_generation(&journal.generation)?;
    if let Some(old_state) = journal.old_state.as_ref() {
        validate_state(old_state, &old_state.state_path())?;
    }
    Ok(journal)
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(path, &bytes)
}

pub(super) fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "refusing non-directory or symlinked coding-agent proxy path {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
        }
        Err(error) => {
            return Err(format!("failed to inspect {}: {error}", path.display()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("failed to protect {}: {error}", path.display()))?;
    }
    #[cfg(windows)]
    crate::filesystem::protect_private_windows_path(path)
        .map_err(|error| format!("failed to protect {}: {error}", path.display()))?;
    Ok(())
}

pub(super) fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{} is not a non-symlinked coding-agent proxy directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o700 {
            return Err(format!(
                "{} must have owner-only mode 700 (found {mode:o})",
                path.display()
            ));
        }
        // SAFETY: `geteuid` has no preconditions and does not mutate process state.
        let effective_user = unsafe { libc::geteuid() };
        if metadata.uid() != effective_user {
            return Err(format!(
                "{} is owned by user {} instead of the current user {effective_user}",
                path.display(),
                metadata.uid()
            ));
        }
    }
    #[cfg(windows)]
    if !crate::filesystem::windows_path_is_private(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
    {
        return Err(format!(
            "{} does not have an owner-only ACL",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn ensure_unowned_root_available(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "refusing to adopt non-directory or symlinked coding-agent proxy install root {}",
            path.display()
        ));
    }
    let mut entries = std::fs::read_dir(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| {
            format!(
                "failed to inspect coding-agent proxy install root {}: {error}",
                path.display()
            )
        })?
        .is_some()
    {
        return Err(format!(
            "refusing to adopt non-empty unowned coding-agent proxy install root {}; move its contents before installing",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/state_tests.rs"]
mod tests;
