// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! External host operations used by the transactional Claude Desktop lifecycle.

use std::path::{Path, PathBuf};

use crate::agents::CodingAgent;
use crate::installation::{InstallRequest, UninstallRequest};

use super::DoctorCheck;
use super::platform::Platform;
use super::proxy::Health;
use super::state::{CertificateState, DesktopState};

/// Boundary between deterministic lifecycle logic and machine-wide host effects.
///
/// State, settings, certificates, journals, and rollback remain real filesystem operations. Only
/// operations that depend on the running host, a login service, a trust store, a fixed listener, or
/// the Claude plugin manager cross this boundary.
pub(super) trait DesktopOperations {
    fn platform(&self) -> Result<Platform, String>;
    fn validate_supported_platform(&self, platform: Platform) -> Result<String, String>;
    fn application_identity(&self, platform: Platform) -> Result<String, String>;
    fn active_claude_processes(&self, platform: Platform) -> Result<Vec<String>, String>;
    fn ensure_no_foreign_service(
        &self,
        platform: Platform,
        install_root: &Path,
    ) -> Result<(), String>;
    fn relay_binary(&self) -> Result<PathBuf, String>;
    fn persistent_gateway_identity(&self) -> Result<(String, String), String>;
    fn settings_path(&self) -> Result<PathBuf, String>;
    fn plugin_exists(&self, marketplace_dir: &Path) -> bool;
    fn install_plugin(
        &self,
        marketplace_dir: &Path,
        force: bool,
        skip_doctor: bool,
    ) -> Result<(), String>;
    fn uninstall_plugin(&self, marketplace_dir: &Path) -> Result<(), String>;
    fn stop_direct_gateway(&self) -> Result<(), String>;
    fn restart_direct_gateway(&self) -> Result<(), String>;
    fn shutdown_proxy(&self, installed: &DesktopState);
    fn install_trust(
        &self,
        platform: Platform,
        certificate: &CertificateState,
    ) -> Result<(), String>;
    fn remove_trust(
        &self,
        platform: Platform,
        certificate: &CertificateState,
    ) -> Result<(), String>;
    fn register_service(&self, installed: &DesktopState) -> Result<(), String>;
    fn start_service(&self, installed: &DesktopState) -> Result<(), String>;
    fn stop_service(&self, installed: &DesktopState) -> Result<(), String>;
    fn unregister_service(&self, installed: &DesktopState) -> Result<(), String>;
    fn wait_for_health(&self, installed: &DesktopState) -> Result<(), String>;
    fn health(&self, installed: &DesktopState) -> Result<Health, String>;
    fn service_status(&self, installed: &DesktopState) -> Result<String, String>;
    fn trust_status(
        &self,
        platform: Platform,
        certificate: &CertificateState,
        linux_bundle: Option<&Path>,
    ) -> Result<String, String>;
    fn plugin_checks(&self, marketplace_dir: Option<&Path>) -> Result<Vec<DoctorCheck>, String>;
    fn open_deep_link(&self, platform: Platform, url: &str) -> Result<(), String>;
    fn post_install_doctor(&self, marketplace_dir: &Path) -> Result<(), String>;
}

pub(super) struct SystemOperations;

impl DesktopOperations for SystemOperations {
    fn platform(&self) -> Result<Platform, String> {
        Platform::current()
    }

    fn validate_supported_platform(&self, platform: Platform) -> Result<String, String> {
        super::platform::validate_supported_platform(platform)
    }

    fn application_identity(&self, platform: Platform) -> Result<String, String> {
        super::platform::application_identity(platform)
    }

    fn active_claude_processes(&self, platform: Platform) -> Result<Vec<String>, String> {
        super::platform::active_claude_processes(platform)
    }

    fn ensure_no_foreign_service(
        &self,
        platform: Platform,
        install_root: &Path,
    ) -> Result<(), String> {
        super::platform::ensure_no_foreign_service(platform, install_root)
    }

    fn relay_binary(&self) -> Result<PathBuf, String> {
        let executable = crate::bootstrap::current_exe()?;
        Ok(executable.canonicalize().unwrap_or(executable))
    }

    fn persistent_gateway_identity(&self) -> Result<(String, String), String> {
        super::persistent_gateway_identity()
    }

    fn settings_path(&self) -> Result<PathBuf, String> {
        crate::agents::claude::host::claude_settings_path()
    }

    fn plugin_exists(&self, marketplace_dir: &Path) -> bool {
        crate::installation::marketplace::persisted_state_exists(
            CodingAgent::ClaudeCode,
            marketplace_dir,
        )
    }

    fn install_plugin(
        &self,
        marketplace_dir: &Path,
        force: bool,
        skip_doctor: bool,
    ) -> Result<(), String> {
        crate::installation::marketplace::install(
            CodingAgent::ClaudeCode,
            InstallRequest {
                install_dir: Some(marketplace_dir.to_path_buf()),
                force,
                dry_run: false,
                skip_doctor,
            },
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn uninstall_plugin(&self, marketplace_dir: &Path) -> Result<(), String> {
        crate::installation::marketplace::uninstall(
            CodingAgent::ClaudeCode,
            UninstallRequest {
                install_dir: Some(marketplace_dir.to_path_buf()),
                dry_run: false,
            },
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn stop_direct_gateway(&self) -> Result<(), String> {
        crate::bootstrap::state::stop_owned_and_reset(crate::bootstrap::DEFAULT_URL)
    }

    fn restart_direct_gateway(&self) -> Result<(), String> {
        super::restart_direct_gateway()
    }

    fn shutdown_proxy(&self, installed: &DesktopState) {
        let _ = super::proxy::shutdown(installed, super::HEALTH_TIMEOUT);
    }

    fn install_trust(
        &self,
        platform: Platform,
        certificate: &CertificateState,
    ) -> Result<(), String> {
        super::platform::install_trust(platform, certificate, false)
    }

    fn remove_trust(
        &self,
        platform: Platform,
        certificate: &CertificateState,
    ) -> Result<(), String> {
        super::platform::remove_trust(platform, certificate, false)
    }

    fn register_service(&self, installed: &DesktopState) -> Result<(), String> {
        super::platform::register_service(installed, false)
    }

    fn start_service(&self, installed: &DesktopState) -> Result<(), String> {
        super::platform::start_service(installed)
    }

    fn stop_service(&self, installed: &DesktopState) -> Result<(), String> {
        super::platform::stop_service(installed)
    }

    fn unregister_service(&self, installed: &DesktopState) -> Result<(), String> {
        super::platform::unregister_service(installed, false)
    }

    fn wait_for_health(&self, installed: &DesktopState) -> Result<(), String> {
        super::wait_for_health(installed)
    }

    fn health(&self, installed: &DesktopState) -> Result<Health, String> {
        super::proxy::health(installed, super::HEALTH_TIMEOUT)
    }

    fn service_status(&self, installed: &DesktopState) -> Result<String, String> {
        super::platform::service_definition_matches(installed)
    }

    fn trust_status(
        &self,
        platform: Platform,
        certificate: &CertificateState,
        linux_bundle: Option<&Path>,
    ) -> Result<String, String> {
        super::platform::trust_status(platform, certificate, linux_bundle)
    }

    fn plugin_checks(&self, marketplace_dir: Option<&Path>) -> Result<Vec<DoctorCheck>, String> {
        super::plugin_checks(marketplace_dir)
    }

    fn open_deep_link(&self, platform: Platform, url: &str) -> Result<(), String> {
        super::platform::open_deep_link(platform, url)
    }

    fn post_install_doctor(&self, marketplace_dir: &Path) -> Result<(), String> {
        if super::doctor_report_with(self, Some(marketplace_dir))?.ok {
            Ok(())
        } else {
            Err("Claude Desktop doctor checks failed after installation".into())
        }
    }
}
