// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::cognitive_complexity)]

//! Persistent, user-scoped wrapping for Claude Desktop's Code tab and bare Claude Code.

mod certificate;
mod operations;
mod platform;
mod proxy;
mod settings;
mod state;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::digest::{SHA256, digest};
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use crate::agents::CodingAgent;
use crate::error::CliError;
use crate::installation::{InstallRequest, UninstallRequest};
use operations::{DesktopOperations, SystemOperations};

pub(crate) const GATEWAY_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47632);
pub(crate) const PROXY_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47633);
const HEALTH_TIMEOUT: Duration = Duration::from_millis(750);
const START_TIMEOUT: Duration = Duration::from_secs(12);

#[cfg(test)]
static FIXED_PORT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct InstallProgress {
    trust_installed: bool,
    service_registered: bool,
    plugin_added: bool,
    settings_applied: bool,
    locator_written: bool,
}

#[derive(Default)]
struct RollbackErrors(Vec<String>);

impl RollbackErrors {
    fn record(&mut self, result: Result<(), String>) {
        if let Err(error) = result {
            self.0.push(error);
        }
    }

    fn finish(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self.0.join("; "))
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LaunchRequest {
    pub(crate) folder: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct SidecarRequest {
    pub(crate) state: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorCheck {
    name: String,
    ok: bool,
    details: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorReport {
    schema_version: u32,
    integration: &'static str,
    platform: String,
    state_path: PathBuf,
    ok: bool,
    effective_protection: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn push(&mut self, name: impl Into<String>, result: Result<String, String>) {
        match result {
            Ok(details) => self.checks.push(DoctorCheck {
                name: name.into(),
                ok: true,
                details,
            }),
            Err(details) => self.checks.push(DoctorCheck {
                name: name.into(),
                ok: false,
                details,
            }),
        }
    }

    fn finish(mut self) -> Self {
        self.ok = self.checks.iter().all(|check| check.ok);
        self.effective_protection = self.ok;
        self
    }
}

pub(crate) fn install(command: InstallRequest) -> Result<ExitCode, CliError> {
    install_inner(command).map_err(CliError::Install)?;
    Ok(ExitCode::SUCCESS)
}

fn install_inner(command: InstallRequest) -> Result<(), String> {
    install_with(&SystemOperations, command)
}

fn install_with(operations: &dyn DesktopOperations, command: InstallRequest) -> Result<(), String> {
    let platform = operations.platform()?;
    let install_root = state::install_root(command.install_dir.as_deref());
    let state_path = state::selected_state_path(command.install_dir.as_deref());
    let active_state_path = state::resolve_state_path(None)?;
    if active_state_path != state_path && active_state_path.exists() {
        return Err(format!(
            "Claude Desktop protection is already registered at {}; uninstall it before selecting {}",
            active_state_path.display(),
            state_path.display()
        ));
    }
    let journal_exists = state::journal_path(&install_root).exists();
    let mut old_state = state_path
        .exists()
        .then(|| state::read(&state_path))
        .transpose()?;
    if journal_exists && !command.force {
        return Err(format!(
            "an incomplete Claude Desktop installation journal exists at {}; close Claude and rerun with `nemo-relay install claude-desktop --force` to restore the prior generation before upgrading",
            state::journal_path(&install_root).display()
        ));
    }
    if old_state.is_some() && !command.force && !journal_exists {
        return Err(format!(
            "Claude Desktop protection is already installed at {}; use `nemo-relay install claude-desktop --force` to rotate and upgrade it",
            state_path.display()
        ));
    }

    if command.dry_run {
        println!("validate Claude Desktop and terminal Claude Code are closed");
        println!(
            "write owner-only Claude Desktop state at {}",
            state_path.display()
        );
        println!("bind persistent Relay gateway at http://{GATEWAY_BIND}");
        println!("bind authenticated CONNECT proxy at http://{PROXY_BIND}");
        println!(
            "issue and trust a constrained certificate for {}",
            certificate::INTERCEPTED_HOST
        );
        println!("transactionally update ~/.claude/settings.json");
        println!("install or reuse the Claude Code marketplace plugin");
        println!("register the {} per-user login service", platform.as_str());
        return Ok(());
    }

    let platform_details = operations.validate_supported_platform(platform)?;
    let application = operations.application_identity(platform)?;
    if old_state.is_none() {
        state::ensure_unowned_root_available(&install_root)?;
        operations.ensure_no_foreign_service(platform, &install_root)?;
    }
    let _operation_lock = desktop_operation_lock()?;
    ensure_claude_stopped(operations, platform, "installation")?;
    if state::journal_path(&install_root).exists() {
        recover_interrupted_operation(operations, &install_root, &state_path, platform)?;
    }
    old_state = state_path
        .exists()
        .then(|| state::read(&state_path))
        .transpose()?;
    if old_state.is_some() && !command.force {
        return Err(format!(
            "Claude Desktop protection was installed by another operation at {}; use --force to rotate it",
            state_path.display()
        ));
    }
    log::info!(
        target: "nemo_relay.installation",
        event = "install_preflight_complete",
        platform = platform.as_str(),
        platform_details = platform_details.as_str(),
        application = application.as_str();
        "Claude Desktop install preflight completed"
    );

    let relay_binary = operations.relay_binary()?;
    let (gateway_fingerprint, anthropic_base_url) = operations.persistent_gateway_identity()?;
    if anthropic_base_url.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err(format!(
            "Claude Desktop wrapping does not yet support a custom Anthropic gateway ({anthropic_base_url}); restore the default Anthropic upstream before installing"
        ));
    }

    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    let marketplace_preexisting = operations.plugin_exists(&marketplace_dir);
    let plugin_preexisting = old_state
        .as_ref()
        .map_or(marketplace_preexisting, |state| state.plugin_preexisting);
    let settings_path = operations.settings_path()?;
    let settings_snapshot = crate::filesystem::snapshot_optional_file(&settings_path)?;
    state::ensure_private_directory(&install_root)?;
    let generation = uuid::Uuid::now_v7().to_string();
    let mut journal = state::InstallJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "preparing".into(),
        generation: generation.clone(),
        old_state: old_state.clone(),
    };
    state::write_journal(&install_root, &journal)?;

    let prepared = (|| {
        if let Some(old) = old_state.as_ref() {
            operations.shutdown_proxy(old);
            let _ = operations.stop_service(old);
            settings::restore(&old.settings)?;
        }

        let certificate = certificate::generate(&install_root, &generation)?;
        let proxy_token = crate::provider_auth::TransparentProxyCredential::generate()
            .map_err(|error| error.to_string())?
            .expose()
            .to_string();
        let proxy_username = "nemo-relay".to_string();
        let provisional_proxy_url = format!("http://{proxy_username}:{proxy_token}@{PROXY_BIND}");

        let ca_path = if platform == platform::Platform::Linux {
            let combined = certificate
                .root_pem
                .parent()
                .expect("generated root has a parent")
                .join("claude-ca-bundle.pem");
            let existing = settings::existing_env_string(&settings_path, "NODE_EXTRA_CA_CERTS")?;
            let root_pem = std::fs::read_to_string(&certificate.root_pem).map_err(|error| {
                format!("failed to read {}: {error}", certificate.root_pem.display())
            })?;
            settings::compose_linux_ca_bundle(&combined, &root_pem, existing.as_deref())?;
            combined
        } else {
            certificate.root_pem.clone()
        };
        let provisional_settings = settings::prepare(
            &settings_path,
            &provisional_proxy_url,
            &state_path,
            &ca_path,
            platform.as_str(),
            old_state
                .as_ref()
                .and_then(|state| state.upstream_proxy.as_ref()),
        )?;
        let configuration_fingerprint = configuration_fingerprint(
            &generation,
            &relay_binary,
            &gateway_fingerprint,
            &certificate.root_sha256,
            provisional_settings.upstream_proxy.as_ref(),
        )?;
        let new_state = state::DesktopState {
            schema_version: state::STATE_SCHEMA_VERSION,
            generation: generation.clone(),
            installed_at: chrono::Utc::now().to_rfc3339(),
            relay_version: env!("CARGO_PKG_VERSION").into(),
            relay_binary: relay_binary.clone(),
            install_root: install_root.clone(),
            platform: platform.as_str().into(),
            proxy_username,
            proxy_token,
            upstream_proxy: provisional_settings.upstream_proxy.clone(),
            gateway_fingerprint: gateway_fingerprint.clone(),
            configuration_fingerprint,
            certificate,
            settings: settings::SettingsPatch {
                settings_path: settings_path.clone(),
                original_settings_absent: !settings_path.exists(),
                fields: Default::default(),
                previous_permissions: None,
            },
            plugin_preexisting,
        };
        state::write(&new_state)?;
        journal.stage = "prepared".into();
        state::write_journal(&install_root, &journal)?;
        Ok::<_, String>((new_state, ca_path))
    })();
    let (mut new_state, ca_path) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let recovery =
                recover_interrupted_operation(operations, &install_root, &state_path, platform);
            return Err(match recovery {
                Ok(()) => format!("{error}; restored the previous Claude Desktop generation"),
                Err(recovery) => format!("{error}; rollback also failed: {recovery}"),
            });
        }
    };

    let mut progress = InstallProgress::default();
    let result = (|| {
        operations.stop_direct_gateway()?;
        operations.install_trust(platform, &new_state.certificate)?;
        progress.trust_installed = true;
        journal.stage = "certificate_trusted".into();
        state::write_journal(&install_root, &journal)?;

        operations.register_service(&new_state)?;
        progress.service_registered = true;
        operations.start_service(&new_state)?;
        operations.wait_for_health(&new_state)?;
        journal.stage = "sidecar_healthy".into();
        state::write_journal(&install_root, &journal)?;

        // Refresh an existing direct-gateway installation as part of the migration. Its generated
        // hooks must invoke the same Relay binary as the sidecar so the Desktop-specific
        // fail-closed checks cannot be skipped by retaining an older plugin generation.
        operations.install_plugin(
            &marketplace_dir,
            marketplace_preexisting,
            command.skip_doctor,
        )?;
        progress.plugin_added = !marketplace_preexisting;
        journal.stage = "plugin_ready".into();
        state::write_journal(&install_root, &journal)?;

        let final_settings = settings::prepare(
            &settings_path,
            &new_state.proxy_url(),
            &state_path,
            &ca_path,
            platform.as_str(),
            new_state.upstream_proxy.as_ref(),
        )?;
        if final_settings.upstream_proxy != new_state.upstream_proxy {
            return Err(
                "Claude corporate proxy settings changed during installation; rolled back instead of committing an ambiguous route"
                    .into(),
            );
        }
        settings::apply(&final_settings)?;
        progress.settings_applied = true;
        new_state.settings = final_settings.patch;
        state::write(&new_state)?;
        journal.stage = "settings_applied".into();
        state::write_journal(&install_root, &journal)?;

        settings::matches(&new_state.settings)?;
        operations.wait_for_health(&new_state)?;
        if !command.skip_doctor {
            operations.post_install_doctor(&marketplace_dir)?;
        }
        if let Some(old) = old_state.as_ref() {
            operations.remove_trust(platform, &old.certificate)?;
        }
        state::write_locator(&state_path)?;
        progress.locator_written = true;
        state::remove_file_if_present(&state::journal_path(&install_root))?;
        Ok::<(), String>(())
    })();

    if let Err(error) = result {
        let rollback = rollback_install(
            operations,
            &new_state,
            old_state.as_ref(),
            &settings_snapshot,
            &progress,
            &marketplace_dir,
        );
        return Err(match rollback {
            Ok(()) => format!("{error}; restored the previous Claude Desktop generation"),
            Err(rollback) => format!("{error}; rollback also failed: {rollback}"),
        });
    }

    if let Some(old) = old_state.as_ref()
        && let Err(error) = remove_generation(&old.install_root, &old.generation)
    {
        println!(
            "warning: the upgraded Claude Desktop generation is active, but stale certificate files could not be removed: {error}"
        );
    }
    println!(
        "installed Claude Desktop protection generation {} at {}",
        new_state.generation,
        install_root.display()
    );
    Ok(())
}

type DesktopOperationLock = crate::installation::operation_lock::PluginOperationLock;

fn desktop_operation_lock() -> Result<DesktopOperationLock, String> {
    let directory = crate::configuration::user_config_dir()
        .ok_or_else(|| "cannot determine NeMo Relay user configuration directory".to_string())?
        .join("plugin-operations");
    crate::installation::operation_lock::PluginOperationLock::acquire(
        "claude-desktop",
        &directory,
        &directory,
        crate::installation::operation_lock::DEFAULT_OPERATION_LOCK_TIMEOUT,
    )
}

fn ensure_claude_stopped(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    action: &str,
) -> Result<(), String> {
    let active = operations.active_claude_processes(platform)?;
    if active.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "close Claude Desktop and terminal Claude Code before {action}; still running: {}",
            active.join(", ")
        ))
    }
}

fn recover_interrupted_operation(
    operations: &dyn DesktopOperations,
    install_root: &Path,
    state_path: &Path,
    current_platform: platform::Platform,
) -> Result<(), String> {
    let journal = state::read_journal(install_root)?;
    if let Some(old) = journal.old_state.as_ref()
        && platform::Platform::parse(&old.platform)? != current_platform
    {
        return Err("Claude Desktop journal belongs to a different operating system".into());
    }
    let current = state_path
        .exists()
        .then(|| state::read(state_path))
        .transpose()?;
    if journal.operation == "install" && journal.stage == "preparing" {
        if let Some(old) = journal.old_state.as_ref() {
            restore_protected_generation(operations, old, current_platform)?;
        } else {
            if let Some(current) = current.as_ref() {
                if current.generation != journal.generation {
                    return Err(format!(
                        "refusing to recover preparation generation {} over state generation {}",
                        journal.generation, current.generation
                    ));
                }
                state::remove_locator_if_matches(&current.state_path())?;
                state::remove_file_if_present(state_path)?;
            }
        }
        remove_generation(install_root, &journal.generation)?;
        state::remove_file_if_present(&state::journal_path(install_root))?;
        println!(
            "recovered interrupted Claude Desktop install preparation for generation {}",
            journal.generation
        );
        return Ok(());
    }
    if journal.operation == "uninstall" && journal.stage == "committed" {
        let old = journal.old_state.as_ref().ok_or_else(|| {
            "committed Claude Desktop uninstall journal has no prior generation".to_string()
        })?;
        if old.install_root != install_root
            || install_root.file_name().and_then(|name| name.to_str()) != Some("claude-desktop")
        {
            return Err(format!(
                "refusing to finish uninstall from unexpected root {}",
                install_root.display()
            ));
        }
        state::remove_locator_if_matches(&old.state_path())?;
        match std::fs::remove_dir_all(install_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to finish removing {}: {error}",
                    install_root.display()
                ));
            }
        }
        println!(
            "finished interrupted Claude Desktop uninstall for generation {}",
            journal.generation
        );
        return Ok(());
    }
    if let Some(current) = current.as_ref()
        && current.generation != journal.generation
        && journal.operation == "install"
    {
        return Err(format!(
            "refusing to recover journal generation {} over active generation {}",
            journal.generation, current.generation
        ));
    }

    match journal.operation.as_str() {
        "install" => {
            if let Some(new_state) = current.as_ref() {
                operations.shutdown_proxy(new_state);
                operations.unregister_service(new_state)?;
                if !new_state.settings.fields.is_empty() {
                    settings::restore(&new_state.settings)?;
                }
                operations.remove_trust(current_platform, &new_state.certificate)?;
                if !new_state.plugin_preexisting {
                    uninstall_plugin_if_present(operations, install_root)?;
                }
                state::remove_locator_if_matches(&new_state.state_path())?;
                state::remove_file_if_present(&new_state.state_path())?;
            }
            remove_generation(install_root, &journal.generation)?;
            if let Some(old) = journal.old_state.as_ref() {
                restore_protected_generation(operations, old, current_platform)?;
            } else if current
                .as_ref()
                .is_some_and(|state| state.plugin_preexisting)
            {
                restore_direct_gateway_plugin(operations, install_root)?;
            }
        }
        "uninstall" => {
            let old = journal.old_state.as_ref().ok_or_else(|| {
                "interrupted Claude Desktop uninstall journal has no prior generation".to_string()
            })?;
            operations.stop_direct_gateway()?;
            restore_protected_generation(operations, old, current_platform)?;
        }
        operation => {
            return Err(format!(
                "unsupported Claude Desktop journal operation {operation}"
            ));
        }
    }
    state::remove_file_if_present(&state::journal_path(install_root))?;
    println!(
        "recovered interrupted Claude Desktop {} operation for generation {}",
        journal.operation, journal.generation
    );
    Ok(())
}

fn restore_protected_generation(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    current_platform: platform::Platform,
) -> Result<(), String> {
    ensure_plugin_installed(operations, &installed.install_root)?;
    state::write(installed)?;
    settings::apply_installed(&installed.settings)?;
    operations.install_trust(current_platform, &installed.certificate)?;
    activate_service(operations, installed)?;
    state::write_locator(&installed.state_path())
}

fn activate_service(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
) -> Result<(), String> {
    operations.register_service(installed)?;
    operations.start_service(installed)?;
    operations.wait_for_health(installed)
}

fn ensure_plugin_installed(
    operations: &dyn DesktopOperations,
    install_root: &Path,
) -> Result<(), String> {
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    let exists = operations.plugin_exists(&marketplace_dir);
    operations.install_plugin(&marketplace_dir, exists, true)
}

fn uninstall_plugin_if_present(
    operations: &dyn DesktopOperations,
    install_root: &Path,
) -> Result<(), String> {
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    if !operations.plugin_exists(&marketplace_dir) {
        return Ok(());
    }
    operations.uninstall_plugin(&marketplace_dir)
}

fn restore_direct_gateway_plugin(
    operations: &dyn DesktopOperations,
    install_root: &Path,
) -> Result<(), String> {
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?;
    if !operations.plugin_exists(marketplace_dir) {
        operations.install_plugin(marketplace_dir, false, true)?;
    }
    operations.restart_direct_gateway()
}

fn rollback_install(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    settings_snapshot: &crate::filesystem::FileSnapshot,
    progress: &InstallProgress,
    marketplace_dir: &Path,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    let current_platform = platform::Platform::parse(&new_state.platform)?;
    undo_new_install_effects(
        operations,
        new_state,
        settings_snapshot,
        progress,
        marketplace_dir,
        current_platform,
        &mut errors,
    );
    restore_install_predecessor(
        operations,
        new_state,
        old_state,
        current_platform,
        &mut errors,
    );
    cleanup_failed_install(new_state, old_state, progress, &mut errors);
    errors.finish()
}

fn undo_new_install_effects(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    settings_snapshot: &crate::filesystem::FileSnapshot,
    progress: &InstallProgress,
    marketplace_dir: &Path,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) {
    operations.shutdown_proxy(new_state);
    if progress.service_registered {
        errors.record(operations.unregister_service(new_state));
    }
    if progress.settings_applied {
        errors.record(settings::restore(&new_state.settings).map(|_| ()));
    }
    if progress.plugin_added {
        errors.record(operations.uninstall_plugin(marketplace_dir));
    }
    errors.record(crate::filesystem::restore_file_snapshot(settings_snapshot));
    if progress.trust_installed {
        errors.record(operations.remove_trust(current_platform, &new_state.certificate));
    }
}

fn restore_install_predecessor(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) {
    if let Some(old) = old_state {
        restore_generation_best_effort(operations, old, current_platform, errors);
        return;
    }
    errors.record(state::remove_file_if_present(&new_state.state_path()));
    if new_state.plugin_preexisting {
        errors.record(restore_direct_gateway_plugin(
            operations,
            &new_state.install_root,
        ));
    }
}

fn restore_generation_best_effort(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) {
    errors.record(ensure_plugin_installed(operations, &installed.install_root));
    errors.record(state::write(installed));
    errors.record(operations.install_trust(current_platform, &installed.certificate));
    errors.record(activate_service(operations, installed));
    errors.record(state::write_locator(&installed.state_path()));
}

fn cleanup_failed_install(
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    progress: &InstallProgress,
    errors: &mut RollbackErrors,
) {
    if old_state.is_none() && progress.locator_written {
        let _ = state::remove_locator_if_matches(&new_state.state_path());
    }
    errors.record(remove_generation(
        &new_state.install_root,
        &new_state.generation,
    ));
    errors.record(state::remove_file_if_present(&state::journal_path(
        &new_state.install_root,
    )));
}

pub(crate) fn uninstall(command: UninstallRequest) -> Result<ExitCode, CliError> {
    uninstall_inner(command).map_err(CliError::Install)?;
    Ok(ExitCode::SUCCESS)
}

fn uninstall_inner(command: UninstallRequest) -> Result<(), String> {
    uninstall_with(&SystemOperations, command)
}

fn uninstall_with(
    operations: &dyn DesktopOperations,
    command: UninstallRequest,
) -> Result<(), String> {
    let path = state::resolve_state_path(command.install_dir.as_deref())?;
    let mut installed = state::read(&path)?;
    let platform = platform::Platform::parse(&installed.platform)?;
    if command.dry_run {
        platform::unregister_service(&installed, true)?;
        platform::remove_trust(platform, &installed.certificate, true)?;
        println!(
            "restore Relay-managed fields in {}",
            installed.settings.settings_path.display()
        );
        println!("remove {}", installed.install_root.display());
        return Ok(());
    }
    if installed
        .install_root
        .file_name()
        .and_then(|name| name.to_str())
        != Some("claude-desktop")
    {
        return Err(format!(
            "refusing to remove unexpected install root {}",
            installed.install_root.display()
        ));
    }
    let _operation_lock = desktop_operation_lock()?;
    ensure_claude_stopped(operations, platform, "uninstalling")?;
    if state::journal_path(&installed.install_root).exists() {
        recover_interrupted_operation(operations, &installed.install_root, &path, platform)?;
        if !path.exists() {
            println!(
                "finished the interrupted Claude Desktop uninstall from {}",
                installed.install_root.display()
            );
            return Ok(());
        }
        installed = state::read(&path)?;
    }
    let settings_snapshot =
        crate::filesystem::snapshot_optional_file(&installed.settings.settings_path)?;
    let mut journal = state::InstallJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "uninstall".into(),
        stage: "started".into(),
        generation: installed.generation.clone(),
        old_state: Some(installed.clone()),
    };
    state::write_journal(&installed.install_root, &journal)?;

    let result = (|| {
        operations.shutdown_proxy(&installed);
        operations.unregister_service(&installed)?;
        let retained = settings::restore(&installed.settings)?;
        if !retained.is_empty() {
            println!(
                "retained concurrent Claude settings edits for {}",
                retained.join(", ")
            );
        }
        operations.remove_trust(platform, &installed.certificate)?;
        if !installed.plugin_preexisting {
            let marketplace_dir = installed
                .install_root
                .parent()
                .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?;
            operations.uninstall_plugin(marketplace_dir)?;
        } else {
            restore_direct_gateway_plugin(operations, &installed.install_root)?;
        }
        state::remove_locator_if_matches(&installed.state_path())?;
        journal.stage = "committed".into();
        state::write_journal(&installed.install_root, &journal)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let rollback = rollback_uninstall(operations, &installed, platform, &settings_snapshot);
        return Err(if rollback.is_ok() {
            format!("{error}; restored Claude Desktop protection")
        } else {
            format!(
                "{error}; rollback also failed: {}",
                rollback.expect_err("rollback error was checked")
            )
        });
    }
    let root = installed.install_root.clone();
    if let Err(error) = std::fs::remove_dir_all(&root) {
        println!(
            "warning: Claude Desktop protection is uninstalled, but stale private files remain at {}: {error}",
            root.display()
        );
    }
    println!(
        "uninstalled Claude Desktop protection from {}",
        root.display()
    );
    Ok(())
}

fn rollback_uninstall(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    platform: platform::Platform,
    settings_snapshot: &crate::filesystem::FileSnapshot,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    errors.record(operations.stop_direct_gateway());
    errors.record(crate::filesystem::restore_file_snapshot(settings_snapshot));
    restore_generation_best_effort(operations, installed, platform, &mut errors);
    errors.record(state::remove_file_if_present(&state::journal_path(
        &installed.install_root,
    )));
    errors.finish()
}

fn restart_direct_gateway() -> Result<(), String> {
    let gateway = crate::bootstrap::resolve_plugin_gateway(&Default::default(), GATEWAY_BIND)
        .map_err(|error| error.to_string())?;
    gateway.gateway.acquire().map(|_| ())
}

pub(crate) async fn launch(command: LaunchRequest) -> Result<ExitCode, CliError> {
    launch_with(&SystemOperations, command).await
}

async fn launch_with(
    operations: &dyn DesktopOperations,
    command: LaunchRequest,
) -> Result<ExitCode, CliError> {
    let state_path = state::resolve_state_path(None).map_err(CliError::Install)?;
    let installed = state::read(&state_path).map_err(CliError::Install)?;
    let mut report = doctor_report_with(operations, installed.install_root.parent())
        .map_err(CliError::Install)?;
    if !report.ok && report_allows_sidecar_start(&report) {
        operations
            .start_service(&installed)
            .map_err(CliError::Launch)?;
        operations
            .wait_for_health(&installed)
            .map_err(CliError::Launch)?;
        report = doctor_report_with(operations, installed.install_root.parent())
            .map_err(CliError::Install)?;
    }
    if !report.ok {
        render_doctor(&report);
        return Err(CliError::Launch(
            "Claude Desktop protection is unhealthy; Claude was not launched. Run `nemo-relay doctor --plugin claude-desktop`."
                .into(),
        ));
    }
    let folder = command
        .folder
        .unwrap_or(std::env::current_dir().map_err(CliError::Io)?)
        .canonicalize()
        .map_err(|error| CliError::Launch(format!("failed to resolve Claude folder: {error}")))?;
    if !folder.is_dir() {
        return Err(CliError::Launch(format!(
            "Claude Desktop folder is not a directory: {}",
            folder.display()
        )));
    }
    let url = deep_link(&folder)?;
    operations
        .open_deep_link(
            platform::Platform::parse(&installed.platform).map_err(CliError::Launch)?,
            &url,
        )
        .map_err(CliError::Launch)?;
    Ok(ExitCode::SUCCESS)
}

fn report_allows_sidecar_start(report: &DoctorReport) -> bool {
    report
        .checks
        .iter()
        .all(|check| check.ok || check.name == "sidecar_identity")
}

pub(crate) fn doctor(
    install_dir: Option<PathBuf>,
    json_output: bool,
) -> Result<ExitCode, CliError> {
    doctor_with(&SystemOperations, install_dir.as_deref(), json_output)
}

fn doctor_with(
    operations: &dyn DesktopOperations,
    install_dir: Option<&Path>,
    json_output: bool,
) -> Result<ExitCode, CliError> {
    let report = doctor_report_with(operations, install_dir).map_err(CliError::Install)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| CliError::Install(error.to_string()))?
        );
    } else {
        render_doctor(&report);
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn doctor_report_with(
    operations: &dyn DesktopOperations,
    install_dir: Option<&Path>,
) -> Result<DoctorReport, String> {
    let state_path = state::resolve_state_path(install_dir)?;
    let installed = state::read(&state_path)?;
    let platform = platform::Platform::parse(&installed.platform)?;
    let mut report = DoctorReport {
        schema_version: 1,
        integration: "claude-desktop",
        platform: installed.platform.clone(),
        state_path: state_path.clone(),
        ok: false,
        effective_protection: false,
        checks: Vec::new(),
    };
    report.push(
        "transaction_journal",
        (!state::journal_path(&installed.install_root).exists())
            .then_some("no interrupted install or uninstall operation".into())
            .ok_or_else(|| {
                "an interrupted operation requires `nemo-relay install claude-desktop --force` recovery"
                    .into()
            }),
    );
    report.push(
        "application_identity",
        operations.application_identity(platform),
    );
    report.push(
        "platform_support",
        operations.validate_supported_platform(platform),
    );
    report.push(
        "service_registration",
        operations.service_status(&installed),
    );
    report.push(
        "certificate_files",
        certificate::validate_installed_identity(&installed.install_root, &installed.certificate)
            .map(|_| "root, exact-host leaf, and leaf key form the installed identity".into()),
    );
    report.push(
        "certificate_expiry",
        certificate::expiry_days(&installed.certificate).and_then(|days| {
            if days <= 0 {
                Err("interception certificate is expired; reinstall with --force".into())
            } else if days <= certificate::EXPIRY_WARNING_DAYS {
                Ok(format!(
                    "certificate expires in {days} days; rotate with `nemo-relay install claude-desktop --force`"
                ))
            } else {
                Ok(format!("certificate expires in {days} days"))
            }
        }),
    );
    report.push(
        "certificate_trust",
        operations.trust_status(
            platform,
            &installed.certificate,
            linux_ca_bundle(&installed),
        ),
    );
    report.push(
        "file_permissions",
        private_state_files(&installed).map(|_| "state and leaf key are owner-only".into()),
    );
    report.push(
        "claude_settings",
        settings::matches(&installed.settings).map(|_| {
            "authenticated proxy, fail-closed mode, CA, and base-URL policy are effective".into()
        }),
    );
    report.push(
        "upstream_proxy",
        installed.upstream_proxy.as_ref().map_or_else(
            || Ok("direct public upstream".into()),
            |proxy| {
                settings::validate_upstream_proxy(&proxy.url, proxy.no_proxy.clone())?;
                proxy::upstream_client(Some(proxy))?;
                Ok(format!("chained through {}", proxy.redacted_url()))
            },
        ),
    );
    for check in operations.plugin_checks(install_dir)? {
        report.checks.push(check);
    }
    report.push(
        "sidecar_identity",
        operations.health(&installed).map(|health| {
            format!(
                "generation {} on gateway {} and proxy {}",
                health.generation, health.gateway_url, health.proxy_url
            )
        }),
    );
    report.push(
        "gateway_configuration",
        current_configuration_fingerprint_with(operations, &installed).and_then(|actual| {
            if actual == installed.configuration_fingerprint {
                Ok("persistent gateway configuration fingerprint matches".into())
            } else {
                Err("persistent Relay configuration changed; reinstall with --force".into())
            }
        }),
    );
    Ok(report.finish())
}

fn plugin_checks(install_dir: Option<&Path>) -> Result<Vec<DoctorCheck>, String> {
    let options =
        crate::installation::marketplace::plugin_doctor_options(install_dir.map(Path::to_path_buf));
    let readiness = crate::installation::marketplace::collect_marketplace_readiness(
        CodingAgent::ClaudeCode,
        &options,
        &crate::installation::marketplace::host::RealCommandRunner,
    );
    Ok(readiness
        .checks
        .into_iter()
        .filter(|check| check.name != "claude provider routing")
        .map(|check| DoctorCheck {
            name: format!(
                "plugin_{}",
                check.name.to_ascii_lowercase().replace(' ', "_")
            ),
            ok: check.ok,
            details: check.details,
        })
        .collect())
}

fn render_doctor(report: &DoctorReport) {
    println!("Claude Desktop protection");
    for check in &report.checks {
        println!(
            "{} {:<28} {}",
            if check.ok { "ok" } else { "failed" },
            check.name,
            check.details
        );
    }
    println!(
        "{} effective protection",
        if report.effective_protection {
            "ok"
        } else {
            "failed"
        }
    );
}

pub(crate) async fn run_sidecar(command: SidecarRequest) -> Result<ExitCode, CliError> {
    let installed = state::read(&command.state).map_err(CliError::Launch)?;
    if installed.state_path() != command.state {
        return Err(CliError::Launch(
            "Claude Desktop sidecar state path does not match its install root".into(),
        ));
    }
    certificate::validate_installed_identity(&installed.install_root, &installed.certificate)
        .map_err(CliError::Launch)?;
    let actual = current_configuration_fingerprint(&installed).map_err(CliError::Launch)?;
    if actual != installed.configuration_fingerprint {
        return Err(CliError::Launch(
            "Claude Desktop sidecar configuration fingerprint is stale; reinstall with --force"
                .into(),
        ));
    }
    private_state_files(&installed).map_err(CliError::Launch)?;
    let tls = certificate::server_config(&installed.install_root, &installed.certificate)
        .map_err(CliError::Launch)?;
    let mut resolved = crate::configuration::resolve_persistent_server_config(&Default::default())?;
    let fingerprint = resolved
        .bootstrap_fingerprint
        .clone()
        .ok_or_else(|| CliError::Launch("persistent gateway fingerprint is missing".into()))?;
    if fingerprint != installed.gateway_fingerprint {
        return Err(CliError::Launch(
            "persistent gateway identity changed; reinstall Claude Desktop protection with --force"
                .into(),
        ));
    }
    resolved.gateway.bind = GATEWAY_BIND;
    let dynamic = crate::plugins::lifecycle::active_dynamic_plugin_components(None, &resolved)?;
    let gateway_listener = TcpListener::bind(GATEWAY_BIND).await.map_err(|error| {
        CliError::Launch(format!(
            "refusing to adopt listener at {GATEWAY_BIND}; Claude Desktop gateway bind failed: {error}"
        ))
    })?;
    let proxy_listener = TcpListener::bind(PROXY_BIND).await.map_err(|error| {
        CliError::Launch(format!(
            "refusing to adopt listener at {PROXY_BIND}; Claude Desktop proxy bind failed: {error}"
        ))
    })?;
    let upstream =
        proxy::upstream_client(installed.upstream_proxy.as_ref()).map_err(CliError::Launch)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let runtime = proxy::Runtime::new(installed.clone(), tls, shutdown_tx.clone())
        .map_err(CliError::Launch)?;
    let (gateway_shutdown_tx, gateway_shutdown_rx) = oneshot::channel();
    let mut gateway_task = tokio::spawn(crate::server::serve_claude_desktop_listener_with_dynamic(
        gateway_listener,
        resolved.gateway,
        dynamic,
        fingerprint,
        upstream,
        gateway_shutdown_rx,
    ));
    let mut proxy_task = tokio::spawn(proxy::serve(proxy_listener, runtime));

    let outcome = tokio::select! {
        biased;
        signal = platform_shutdown_signal() => signal,
        changed = shutdown_rx.changed() => changed.map_err(|_| "sidecar control channel closed".to_string()),
        result = &mut gateway_task => Err(task_failure("gateway", result)),
        result = &mut proxy_task => Err(task_failure("proxy", result)),
    };
    let _ = shutdown_tx.send(true);
    let _ = gateway_shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        if !gateway_task.is_finished() {
            let _ = (&mut gateway_task).await;
        }
        if !proxy_task.is_finished() {
            let _ = (&mut proxy_task).await;
        }
    })
    .await;
    outcome.map_err(CliError::Launch)?;
    Ok(ExitCode::SUCCESS)
}

fn task_failure<T: std::fmt::Display>(
    name: &str,
    result: Result<Result<(), T>, tokio::task::JoinError>,
) -> String {
    match result {
        Ok(Ok(())) => format!("Claude Desktop {name} stopped unexpectedly"),
        Ok(Err(error)) => format!("Claude Desktop {name} failed: {error}"),
        Err(error) => format!("Claude Desktop {name} task failed: {error}"),
    }
}

async fn platform_shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| format!("failed to register SIGTERM handler: {error}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|error| format!("failed to wait for Ctrl-C: {error}")),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("failed to wait for service shutdown: {error}"))
    }
}

pub(crate) fn validate_hook_environment() -> Result<(), String> {
    let path = match settings::effective_state_path()? {
        Some(path) => path,
        None => {
            let installed = state::resolve_state_path(None)?;
            if installed.exists() {
                return Err(
                    "Claude Desktop protection is installed but its effective state marker is missing"
                        .into(),
                );
            }
            return Ok(());
        }
    };
    let installed = state::read(&path)?;
    settings::effective_environment_matches(&installed.settings)?;
    let actual = current_configuration_fingerprint(&installed)?;
    if actual != installed.configuration_fingerprint {
        return Err("Claude Desktop Relay configuration fingerprint changed".into());
    }
    proxy::health(&installed, HEALTH_TIMEOUT).map(|_| ())
}

fn persistent_gateway_identity() -> Result<(String, String), String> {
    let resolved = crate::configuration::resolve_persistent_server_config(&Default::default())
        .map_err(|error| error.to_string())?;
    Ok((
        resolved
            .bootstrap_fingerprint
            .ok_or_else(|| "persistent gateway fingerprint is missing".to_string())?,
        resolved.gateway.anthropic_base_url,
    ))
}

fn current_configuration_fingerprint(installed: &state::DesktopState) -> Result<String, String> {
    current_configuration_fingerprint_with(&SystemOperations, installed)
}

fn current_configuration_fingerprint_with(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
) -> Result<String, String> {
    let (gateway, anthropic) = operations.persistent_gateway_identity()?;
    if anthropic.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err("persistent Anthropic upstream is no longer api.anthropic.com".into());
    }
    configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &gateway,
        &installed.certificate.root_sha256,
        installed.upstream_proxy.as_ref(),
    )
}

fn configuration_fingerprint(
    generation: &str,
    relay_binary: &Path,
    gateway_fingerprint: &str,
    root_sha256: &str,
    upstream_proxy: Option<&settings::UpstreamProxy>,
) -> Result<String, String> {
    let relay_bytes = crate::filesystem::bounded::read_bounded_regular_file(
        relay_binary,
        "nemo-relay executable",
    )?;
    let relay_sha256 = digest(&SHA256, &relay_bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let upstream_ca_sha256 = upstream_proxy
        .and_then(|proxy| proxy.ca_bundle.as_deref())
        .map(|path| {
            crate::filesystem::bounded::read_bounded_regular_file(
                path,
                "Claude Desktop corporate proxy CA bundle",
            )
            .map(|bytes| {
                digest(&SHA256, &bytes)
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
        })
        .transpose()?;
    let document = json!({
        "schema": state::STATE_SCHEMA_VERSION,
        "generation": generation,
        "relay_version": env!("CARGO_PKG_VERSION"),
        "relay_binary": relay_binary,
        "relay_binary_sha256": relay_sha256,
        "gateway_fingerprint": gateway_fingerprint,
        "root_sha256": root_sha256,
        "upstream_proxy": upstream_proxy,
        "upstream_ca_sha256": upstream_ca_sha256,
    });
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("failed to encode configuration fingerprint: {error}"))?;
    Ok(digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn wait_for_health(installed: &state::DesktopState) -> Result<(), String> {
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match proxy::health(installed, HEALTH_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "Claude Desktop sidecar did not become healthy: {}",
        last.unwrap_or_else(|| "timed out".into())
    ))
}

fn private_state_files(installed: &state::DesktopState) -> Result<(), String> {
    certificate::leaf_key_is_private(&installed.certificate.leaf_key_der)?;
    certificate::leaf_key_is_private(&installed.state_path())
}

fn linux_ca_bundle(installed: &state::DesktopState) -> Option<&Path> {
    installed
        .settings
        .fields
        .get("NODE_EXTRA_CA_CERTS")?
        .installed
        .as_ref()?
        .as_str()
        .map(Path::new)
}

fn remove_generation(root: &Path, generation: &str) -> Result<(), String> {
    let path = root.join("generations").join(generation);
    if path.parent().and_then(Path::parent) != Some(root) {
        return Err(format!(
            "refusing to remove unexpected generation path {}",
            path.display()
        ));
    }
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

fn deep_link(folder: &Path) -> Result<String, CliError> {
    let folder = folder.to_str().ok_or_else(|| {
        CliError::Launch(format!(
            "Claude Desktop folder is not valid Unicode: {}",
            folder.display()
        ))
    })?;
    Ok(format!(
        "claude://code/new?folder={}",
        utf8_percent_encode(folder, NON_ALPHANUMERIC)
    ))
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/mod_tests.rs"]
mod tests;
