// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persisted installer-owned state for the Claude Desktop sidecar.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::settings::{SettingsPatch, UpstreamProxy};

pub(super) const STATE_SCHEMA_VERSION: u32 = 1;
pub(super) const STATE_FILE_NAME: &str = "state.json";
pub(super) const JOURNAL_FILE_NAME: &str = "install-journal.json";
const LOCATOR_FILE_NAME: &str = "claude-desktop-state-path";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CertificateState {
    pub(super) root_der: PathBuf,
    pub(super) root_pem: PathBuf,
    pub(super) leaf_der: PathBuf,
    pub(super) leaf_key_der: PathBuf,
    pub(super) root_sha1: String,
    pub(super) root_sha256: String,
    pub(super) root_common_name: String,
    pub(super) not_before: String,
    pub(super) not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DesktopState {
    pub(super) schema_version: u32,
    pub(super) generation: String,
    pub(super) installed_at: String,
    pub(super) relay_version: String,
    pub(super) relay_binary: PathBuf,
    pub(super) install_root: PathBuf,
    pub(super) platform: String,
    pub(super) proxy_username: String,
    pub(super) proxy_token: String,
    pub(super) upstream_proxy: Option<UpstreamProxy>,
    pub(super) gateway_fingerprint: String,
    pub(super) max_hook_payload_bytes: usize,
    pub(super) configuration_fingerprint: String,
    pub(super) certificate: CertificateState,
    pub(super) settings: SettingsPatch,
    pub(super) plugin_preexisting: bool,
}

impl DesktopState {
    pub(super) fn state_path(&self) -> PathBuf {
        self.install_root.join(STATE_FILE_NAME)
    }

    pub(super) fn proxy_url(&self) -> String {
        format!(
            "http://{}:{}@{}",
            self.proxy_username,
            self.proxy_token,
            super::PROXY_BIND
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct InstallJournal {
    pub(super) schema_version: u32,
    pub(super) operation: String,
    pub(super) stage: String,
    pub(super) generation: String,
    pub(super) old_state: Option<DesktopState>,
}

pub(super) fn install_root(install_dir: Option<&Path>) -> PathBuf {
    let selected = install_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::installation::marketplace::default_marketplace_install_dir)
        .join("claude-desktop");
    if selected.is_absolute() {
        selected
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&selected))
            .unwrap_or(selected)
    }
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

pub(super) fn selected_state_path(install_dir: Option<&Path>) -> PathBuf {
    install_root(install_dir).join(STATE_FILE_NAME)
}

pub(super) fn write_locator(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "Claude Desktop state locator requires an absolute path, got {}",
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
        "Claude Desktop state locator",
    )?;
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", locator.display()))?
        .trim();
    let path = PathBuf::from(raw);
    if raw.is_empty() || !path.is_absolute() {
        return Err(format!(
            "Claude Desktop state locator {} does not contain an absolute path",
            locator.display()
        ));
    }
    Ok(path)
}

fn locator_path() -> Result<PathBuf, String> {
    let directory = crate::configuration::user_config_dir()
        .ok_or_else(|| "cannot determine NeMo Relay user configuration directory".to_string())?;
    Ok(directory.join(LOCATOR_FILE_NAME))
}

pub(super) fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_FILE_NAME)
}

pub(super) fn read(path: &Path) -> Result<DesktopState, String> {
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        path,
        "Claude Desktop integration state",
    )?;
    let state = serde_json::from_slice::<DesktopState>(&bytes)
        .map_err(|error| format!("invalid Claude Desktop state {}: {error}", path.display()))?;
    validate_state(&state, path)?;
    Ok(state)
}

fn validate_state(state: &DesktopState, path: &Path) -> Result<(), String> {
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported Claude Desktop state schema {} in {}; reinstall with --force",
            state.schema_version,
            path.display()
        ));
    }
    let selected_root = path.parent().ok_or_else(|| {
        format!(
            "Claude Desktop state path {} has no parent directory",
            path.display()
        )
    })?;
    if state.install_root != selected_root {
        return Err(format!(
            "refusing Claude Desktop state whose install root {} differs from selected root {}",
            state.install_root.display(),
            selected_root.display()
        ));
    }
    validate_generation(&state.generation)?;
    validate_certificate_paths(state)?;
    Ok(())
}

fn validate_generation(generation: &str) -> Result<(), String> {
    let mut components = Path::new(generation).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || generation.is_empty()
    {
        return Err("Claude Desktop state contains an invalid generation identifier".into());
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
        (&state.certificate.leaf_der, "api.anthropic.com.der"),
        (&state.certificate.leaf_key_der, "api.anthropic.com-key.der"),
    ] {
        let expected = directory.join(name);
        if actual != &expected {
            return Err(format!(
                "Claude Desktop certificate path {} differs from installed generation {}",
                actual.display(),
                directory.display()
            ));
        }
    }
    Ok(())
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
        "Claude Desktop installation journal",
    )?;
    let journal = serde_json::from_slice::<InstallJournal>(&bytes)
        .map_err(|error| format!("invalid Claude Desktop journal {}: {error}", path.display()))?;
    if journal.schema_version != STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported Claude Desktop journal schema {} in {}",
            journal.schema_version,
            path.display()
        ));
    }
    if !matches!(journal.operation.as_str(), "install" | "uninstall")
        || journal.generation.is_empty()
    {
        return Err(format!(
            "Claude Desktop journal {} has invalid operation metadata",
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
                "refusing non-directory or symlinked Claude Desktop path {}",
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

pub(super) fn ensure_unowned_root_available(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "refusing to adopt non-directory or symlinked Claude Desktop install root {}",
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
                "failed to inspect Claude Desktop install root {}: {error}",
                path.display()
            )
        })?
        .is_some()
    {
        return Err(format!(
            "refusing to adopt non-empty unowned Claude Desktop install root {}; move its contents before installing",
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
