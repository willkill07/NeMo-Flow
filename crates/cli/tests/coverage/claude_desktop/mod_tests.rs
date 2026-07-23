// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::ffi::OsStr;

use super::*;

struct FakeOperations {
    platform: platform::Platform,
    relay_binary: PathBuf,
    settings_path: PathBuf,
    plugin_present: Cell<bool>,
    active_processes: RefCell<Vec<String>>,
    anthropic_base_url: RefCell<String>,
    healthy: Cell<bool>,
    doctor_healthy: Cell<bool>,
    write_service_logs: Cell<bool>,
    mutate_provider_backup_on_install: Cell<bool>,
    mutate_settings_on_install: Cell<bool>,
    failure: RefCell<Option<String>>,
    calls: RefCell<Vec<String>>,
}

impl FakeOperations {
    fn new(
        platform: platform::Platform,
        relay_binary: PathBuf,
        settings_path: PathBuf,
        plugin_present: bool,
    ) -> Self {
        Self {
            platform,
            relay_binary,
            settings_path,
            plugin_present: Cell::new(plugin_present),
            active_processes: RefCell::new(Vec::new()),
            anthropic_base_url: RefCell::new("https://api.anthropic.com".into()),
            healthy: Cell::new(true),
            doctor_healthy: Cell::new(true),
            write_service_logs: Cell::new(false),
            mutate_provider_backup_on_install: Cell::new(false),
            mutate_settings_on_install: Cell::new(false),
            failure: RefCell::new(None),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn step(&self, name: &str) -> Result<(), String> {
        self.calls.borrow_mut().push(name.into());
        if self.failure.borrow().as_deref() != Some(name) {
            return Ok(());
        }
        self.failure.borrow_mut().take();
        Err(format!("injected {name} failure"))
    }

    fn fail_once(&self, name: &str) {
        *self.failure.borrow_mut() = Some(name.into());
    }

    fn called(&self, name: &str) -> bool {
        self.calls.borrow().iter().any(|call| call == name)
    }

    fn call_count(&self, name: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.as_str() == name)
            .count()
    }
}

impl DesktopOperations for FakeOperations {
    fn platform(&self) -> Result<platform::Platform, String> {
        self.step("platform")?;
        Ok(self.platform)
    }

    fn validate_supported_platform(&self, _platform: platform::Platform) -> Result<String, String> {
        self.step("validate_platform")?;
        Ok(format!("{} test host", self.platform.as_str()))
    }

    fn application_identity(&self, _platform: platform::Platform) -> Result<String, String> {
        self.step("application_identity")?;
        Ok("Claude test application".into())
    }

    fn active_claude_processes(
        &self,
        _platform: platform::Platform,
    ) -> Result<Vec<String>, String> {
        self.step("active_processes")?;
        Ok(self.active_processes.borrow().clone())
    }

    fn ensure_no_foreign_service(
        &self,
        _platform: platform::Platform,
        _install_root: &Path,
    ) -> Result<(), String> {
        self.step("ensure_no_foreign_service")
    }

    fn relay_binary(&self) -> Result<PathBuf, String> {
        self.step("relay_binary")?;
        Ok(self.relay_binary.clone())
    }

    fn persistent_gateway_identity(&self) -> Result<(String, String, usize), String> {
        self.step("gateway_identity")?;
        Ok((
            "test-gateway-fingerprint".into(),
            self.anthropic_base_url.borrow().clone(),
            crate::configuration::DEFAULT_MAX_HOOK_PAYLOAD_BYTES,
        ))
    }

    fn settings_path(&self) -> Result<PathBuf, String> {
        self.step("settings_path")?;
        Ok(self.settings_path.clone())
    }

    fn plugin_exists(&self, _marketplace_dir: &Path) -> bool {
        self.calls.borrow_mut().push("plugin_exists".into());
        self.plugin_present.get()
    }

    fn install_plugin(
        &self,
        _marketplace_dir: &Path,
        _force: bool,
        _skip_doctor: bool,
    ) -> Result<(), String> {
        self.step("install_plugin")?;
        if self.mutate_provider_backup_on_install.get() {
            let backup = crate::filesystem::backup_path(&self.settings_path);
            if let Some(parent) = backup.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(backup, b"{\"rewritten\":true}\n").map_err(|error| error.to_string())?;
        }
        if self.mutate_settings_on_install.get() {
            let mut settings = if self.settings_path.exists() {
                crate::agents::shared::host::read_json_object(&self.settings_path)?
            } else {
                serde_json::Value::Object(serde_json::Map::new())
            };
            let env = settings
                .as_object_mut()
                .expect("test settings are an object")
                .entry("env")
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                .as_object_mut()
                .ok_or_else(|| "test Claude env settings are not an object".to_string())?;
            env.insert(
                "ANTHROPIC_BASE_URL".into(),
                serde_json::Value::String(format!("http://{GATEWAY_BIND}")),
            );
            let mut bytes =
                serde_json::to_vec_pretty(&settings).map_err(|error| error.to_string())?;
            bytes.push(b'\n');
            crate::filesystem::atomic_write_private(&self.settings_path, &bytes)?;
        }
        self.plugin_present.set(true);
        Ok(())
    }

    fn uninstall_plugin(&self, _marketplace_dir: &Path) -> Result<(), String> {
        self.step("uninstall_plugin")?;
        self.plugin_present.set(false);
        Ok(())
    }

    fn stop_direct_gateway(&self) -> Result<(), String> {
        self.step("stop_direct_gateway")
    }

    fn restart_direct_gateway(&self) -> Result<(), String> {
        self.step("restart_direct_gateway")
    }

    fn shutdown_proxy(&self, _installed: &state::DesktopState) {
        self.calls.borrow_mut().push("shutdown_proxy".into());
    }

    fn install_trust(
        &self,
        _platform: platform::Platform,
        _certificate: &state::CertificateState,
    ) -> Result<(), String> {
        self.step("install_trust")
    }

    fn remove_trust(
        &self,
        _platform: platform::Platform,
        _certificate: &state::CertificateState,
    ) -> Result<(), String> {
        self.step("remove_trust")
    }

    fn register_service(&self, _installed: &state::DesktopState) -> Result<(), String> {
        self.step("register_service")
    }

    fn start_service(&self, installed: &state::DesktopState) -> Result<(), String> {
        self.step("start_service")?;
        if self.write_service_logs.get() {
            std::fs::write(installed.install_root.join("sidecar.stdout.log"), b"")
                .map_err(|error| error.to_string())?;
            std::fs::write(
                installed.install_root.join("sidecar.stderr.log"),
                b"sidecar failed",
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn stop_service(&self, _installed: &state::DesktopState) -> Result<(), String> {
        self.step("stop_service")
    }

    fn unregister_service(&self, _installed: &state::DesktopState) -> Result<(), String> {
        self.step("unregister_service")
    }

    fn wait_for_health(&self, _installed: &state::DesktopState) -> Result<(), String> {
        self.step("wait_for_health")?;
        self.healthy.set(true);
        Ok(())
    }

    fn health(&self, installed: &state::DesktopState) -> Result<proxy::Health, String> {
        self.step("health")?;
        if !self.healthy.get() {
            return Err("injected unhealthy sidecar".into());
        }
        Ok(proxy::Health {
            service: "nemo-relay-claude-desktop".into(),
            version: installed.relay_version.clone(),
            generation: installed.generation.clone(),
            configuration_fingerprint: installed.configuration_fingerprint.clone(),
            gateway_url: format!("http://{GATEWAY_BIND}"),
            proxy_url: format!("http://{PROXY_BIND}"),
        })
    }

    fn service_status(&self, _installed: &state::DesktopState) -> Result<String, String> {
        self.step("service_status")?;
        Ok("test login service is registered".into())
    }

    fn trust_status(
        &self,
        _platform: platform::Platform,
        _certificate: &state::CertificateState,
        _linux_bundle: Option<&Path>,
    ) -> Result<String, String> {
        self.step("trust_status")?;
        Ok("test root is trusted".into())
    }

    fn plugin_checks(&self, _marketplace_dir: Option<&Path>) -> Result<Vec<DoctorCheck>, String> {
        self.step("plugin_checks")?;
        Ok(vec![DoctorCheck {
            name: "plugin_generation".into(),
            ok: self.doctor_healthy.get(),
            details: "test plugin generation".into(),
        }])
    }

    fn open_deep_link(&self, _platform: platform::Platform, _url: &str) -> Result<(), String> {
        self.step("open_deep_link")
    }

    fn post_install_doctor(&self, _marketplace_dir: &Path) -> Result<(), String> {
        self.step("post_install_doctor")
    }
}

struct LifecycleFixture {
    _temp: tempfile::TempDir,
    _environment: crate::test_support::EnvScope,
    operations: FakeOperations,
    marketplace_dir: PathBuf,
}

impl LifecycleFixture {
    fn new(platform: platform::Platform, plugin_present: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let config = temp.path().join("config");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let environment = crate::test_support::EnvScope::set(&[
            ("HOME", Some(home.as_os_str())),
            ("USERPROFILE", Some(home.as_os_str())),
            ("XDG_CONFIG_HOME", Some(config.as_os_str())),
            ("HTTPS_PROXY", None),
            ("https_proxy", None),
            ("HTTP_PROXY", None),
            ("http_proxy", None),
            ("ALL_PROXY", None),
            ("all_proxy", None),
            ("NO_PROXY", None),
            ("no_proxy", None),
            ("PROXY_PAC_URL", None),
            ("proxy_pac_url", None),
            ("AUTO_PROXY_URL", None),
            ("auto_proxy_url", None),
            ("ANTHROPIC_BASE_URL", None),
            ("anthropic_base_url", None),
            ("NODE_EXTRA_CA_CERTS", None),
            ("node_extra_ca_certs", None),
        ]);
        let relay_binary = temp.path().join("nemo-relay");
        std::fs::write(&relay_binary, b"test relay executable").unwrap();
        let settings_path = temp.path().join("claude").join("settings.json");
        let marketplace_dir = temp.path().join("marketplace");
        let operations = FakeOperations::new(platform, relay_binary, settings_path, plugin_present);
        Self {
            _temp: temp,
            _environment: environment,
            operations,
            marketplace_dir,
        }
    }

    fn install_request(&self, force: bool, skip_doctor: bool) -> InstallRequest {
        InstallRequest {
            install_dir: Some(self.marketplace_dir.clone()),
            force,
            dry_run: false,
            skip_doctor,
        }
    }

    fn uninstall_request(&self) -> UninstallRequest {
        UninstallRequest {
            install_dir: Some(self.marketplace_dir.clone()),
            dry_run: false,
        }
    }

    fn state_path(&self) -> PathBuf {
        self.marketplace_dir
            .join("claude-desktop")
            .join(state::STATE_FILE_NAME)
    }

    fn installed_state(&self) -> state::DesktopState {
        state::read(&self.state_path()).unwrap()
    }

    fn write_journal(
        &self,
        operation: &str,
        stage: &str,
        generation: &str,
        old_state: Option<state::DesktopState>,
    ) {
        state::write_journal(
            &self.marketplace_dir.join("claude-desktop"),
            &state::InstallJournal {
                schema_version: state::STATE_SCHEMA_VERSION,
                operation: operation.into(),
                stage: stage.into(),
                generation: generation.into(),
                old_state,
            },
        )
        .unwrap();
    }
}

fn assert_platform_settings(platform: platform::Platform, installed: &state::DesktopState) {
    let fields = &installed.settings.fields;
    assert!(fields.contains_key("HTTPS_PROXY"));
    assert!(fields.contains_key("NEMO_RELAY_FAIL_CLOSED"));
    assert!(fields.contains_key("NEMO_RELAY_CLAUDE_DESKTOP_STATE"));
    assert!(fields.contains_key("NO_PROXY"));
    match platform {
        platform::Platform::Linux => {
            assert!(fields.contains_key("NODE_EXTRA_CA_CERTS"));
            assert!(!fields.contains_key("CLAUDE_CODE_CERT_STORE"));
        }
        platform::Platform::MacOs | platform::Platform::Windows => {
            assert!(fields.contains_key("CLAUDE_CODE_CERT_STORE"));
            assert!(!fields.contains_key("NODE_EXTRA_CA_CERTS"));
        }
    }
}

fn assert_successful_lifecycle(platform: platform::Platform) {
    let fixture = LifecycleFixture::new(platform, false);
    install_with(&fixture.operations, fixture.install_request(false, false)).unwrap();
    let installed = fixture.installed_state();
    assert_eq!(installed.platform, platform.as_str());
    assert!(!installed.plugin_preexisting);
    assert_platform_settings(platform, &installed);
    assert!(certificate::certificate_files_exist(&installed.certificate));
    assert!(fixture.operations.called("post_install_doctor"));
    assert!(!state::journal_path(&installed.install_root).exists());

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert!(!fixture.state_path().exists());
    assert!(!installed.settings.settings_path.exists());
    assert!(fixture.operations.called("uninstall_plugin"));
    assert!(!fixture.operations.plugin_present.get());
}

#[test]
fn deep_link_percent_encodes_folder_exactly() {
    let link = deep_link(Path::new("/tmp/folder with spaces")).unwrap();
    assert_eq!(
        link,
        "claude://code/new?folder=%2Ftmp%2Ffolder%20with%20spaces"
    );
}

#[test]
fn desktop_ports_are_fixed_loopback_endpoints() {
    assert_eq!(GATEWAY_BIND.to_string(), "127.0.0.1:47632");
    assert_eq!(PROXY_BIND.to_string(), "127.0.0.1:47633");
}

#[test]
fn hook_and_mcp_environments_are_optional_before_install_and_fail_closed_after_install() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    assert!(hook_gateway().unwrap().is_none());
    assert!(mcp_gateway().unwrap().is_none());

    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let error = match hook_gateway() {
        Err(error) => error,
        Ok(_) => panic!("installed protection without an effective state marker must fail"),
    };
    assert!(error.contains("effective state marker is missing"));
    let error = match mcp_gateway() {
        Err(error) => error,
        Ok(_) => panic!("installed protection without an effective state marker must fail"),
    };
    assert!(error.contains("effective state marker is missing"));
}

#[test]
fn doctor_json_exposes_effective_protection_and_named_checks() {
    let mut report = DoctorReport {
        schema_version: 1,
        integration: "claude-desktop",
        platform: "linux".into(),
        state_path: PathBuf::from("/tmp/state.json"),
        ok: false,
        effective_protection: false,
        checks: Vec::new(),
    };
    report.push("sidecar_identity", Ok("generation matches".into()));
    let value = serde_json::to_value(report.finish()).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["integration"], "claude-desktop");
    assert_eq!(value["effective_protection"], true);
    assert_eq!(value["checks"][0]["name"], "sidecar_identity");
}

#[test]
fn post_install_verification_accepts_only_its_current_install_journal() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal("install", "verifying", &installed.generation, None);

    assert!(transaction_journal_status(&installed, false).is_err());
    assert_eq!(
        transaction_journal_status(&installed, true).unwrap(),
        "current installation generation is being verified"
    );

    fixture.write_journal("install", "verifying", "different-generation", None);
    assert!(transaction_journal_status(&installed, true).is_err());
}

#[test]
fn transactional_install_and_uninstall_are_consistent_on_all_platforms() {
    for platform in [
        platform::Platform::MacOs,
        platform::Platform::Windows,
        platform::Platform::Linux,
    ] {
        assert_successful_lifecycle(platform);
    }
}

#[test]
fn force_upgrade_preserves_original_plugin_ownership() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let first = fixture.installed_state();

    install_with(&fixture.operations, fixture.install_request(true, true)).unwrap();
    let second = fixture.installed_state();
    assert_ne!(first.generation, second.generation);
    assert!(!second.plugin_preexisting);
    assert!(!first.certificate.root_pem.exists());
    assert!(fixture.operations.called("stop_service"));

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert!(fixture.operations.called("uninstall_plugin"));
}

#[test]
fn preexisting_terminal_plugin_returns_to_direct_gateway_on_uninstall() {
    let fixture = LifecycleFixture::new(platform::Platform::Windows, true);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    assert!(fixture.installed_state().plugin_preexisting);
    let stops_before = fixture.operations.call_count("stop_direct_gateway");

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert!(fixture.operations.called("restart_direct_gateway"));
    assert_eq!(
        fixture.operations.call_count("stop_direct_gateway"),
        stops_before + 1
    );
    assert!(!fixture.operations.called("uninstall_plugin"));
    assert!(fixture.operations.plugin_present.get());
}

#[test]
fn preexisting_terminal_plugin_preserves_its_provider_backup_exactly() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, true);
    let settings = br#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:47632"}}"#;
    let provider_backup = b"{\n  \"provider-backup-sentinel\": true\n}\n";
    std::fs::create_dir_all(fixture.operations.settings_path.parent().unwrap()).unwrap();
    std::fs::write(&fixture.operations.settings_path, settings).unwrap();
    let backup_path = crate::filesystem::backup_path(&fixture.operations.settings_path);
    std::fs::write(&backup_path, provider_backup).unwrap();
    fixture
        .operations
        .mutate_provider_backup_on_install
        .set(true);

    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    assert_eq!(std::fs::read(&backup_path).unwrap(), provider_backup);

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert_eq!(std::fs::read(&backup_path).unwrap(), provider_backup);
}

#[test]
fn failed_desktop_install_restores_the_provider_backup_exactly() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, true);
    let settings = br#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:47632"}}"#;
    let provider_backup = b"{ \"provider-backup-sentinel\" : true }\n";
    std::fs::create_dir_all(fixture.operations.settings_path.parent().unwrap()).unwrap();
    std::fs::write(&fixture.operations.settings_path, settings).unwrap();
    let backup_path = crate::filesystem::backup_path(&fixture.operations.settings_path);
    std::fs::write(&backup_path, provider_backup).unwrap();
    fixture
        .operations
        .mutate_provider_backup_on_install
        .set(true);
    fixture.operations.fail_once("post_install_doctor");

    let error =
        install_with(&fixture.operations, fixture.install_request(false, false)).unwrap_err();

    assert!(error.contains("injected post_install_doctor failure"));
    assert_eq!(std::fs::read(&backup_path).unwrap(), provider_backup);
    assert_eq!(
        std::fs::read(&fixture.operations.settings_path).unwrap(),
        settings
    );
}

#[test]
fn uninstall_repairs_a_missing_preexisting_terminal_plugin() {
    let fixture = LifecycleFixture::new(platform::Platform::Windows, true);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    fixture.operations.plugin_present.set(false);
    let installs_before = fixture.operations.call_count("install_plugin");

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();

    assert_eq!(
        fixture.operations.call_count("install_plugin"),
        installs_before + 1
    );
    assert!(fixture.operations.plugin_present.get());
    assert!(fixture.operations.called("restart_direct_gateway"));
}

#[test]
fn install_failure_rolls_back_settings_trust_service_and_plugin() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    fixture.operations.write_service_logs.set(true);
    fixture.operations.fail_once("post_install_doctor");
    let error =
        install_with(&fixture.operations, fixture.install_request(false, false)).unwrap_err();
    assert!(error.contains("injected post_install_doctor failure"));
    assert!(error.contains("restored the previous Claude Desktop generation"));
    assert!(!fixture.state_path().exists());
    assert!(!fixture.operations.settings_path.exists());
    assert!(fixture.operations.called("unregister_service"));
    assert!(fixture.operations.called("remove_trust"));
    assert!(fixture.operations.called("uninstall_plugin"));
    assert!(!fixture.operations.plugin_present.get());
    assert!(!fixture.marketplace_dir.join("claude-desktop").exists());
}

#[test]
fn force_upgrade_failure_reapplies_protection_after_plugin_reinstall() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.operations.mutate_settings_on_install.set(true);
    fixture.operations.fail_once("post_install_doctor");

    let error =
        install_with(&fixture.operations, fixture.install_request(true, false)).unwrap_err();

    assert!(error.contains("injected post_install_doctor failure"));
    assert!(error.contains("restored the previous Claude Desktop generation"));
    settings::matches(&installed.settings).unwrap();
    let restored =
        crate::agents::shared::host::read_json_object(&installed.settings.settings_path).unwrap();
    assert!(restored["env"].get("ANTHROPIC_BASE_URL").is_none());
    assert_eq!(restored["env"]["HTTPS_PROXY"], installed.proxy_url());
}

#[test]
fn service_registration_failure_attempts_unregistration_before_cleanup() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    fixture.operations.fail_once("register_service");

    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();

    assert!(error.contains("injected register_service failure"));
    assert!(fixture.operations.called("unregister_service"));
    assert!(!fixture.marketplace_dir.join("claude-desktop").exists());
}

#[test]
fn uninstall_failure_restores_the_protected_generation() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.operations.fail_once("remove_trust");

    let error = uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap_err();
    assert!(error.contains("injected remove_trust failure"));
    assert!(error.contains("restored Claude Desktop protection"));
    assert!(fixture.state_path().exists());
    assert!(installed.settings.settings_path.exists());
    assert!(fixture.operations.called("register_service"));
    assert!(fixture.operations.called("install_trust"));

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert!(!fixture.state_path().exists());
}

#[test]
fn uninstall_refuses_running_claude_and_unexpected_install_roots() {
    let fixture = LifecycleFixture::new(platform::Platform::Windows, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    fixture
        .operations
        .active_processes
        .borrow_mut()
        .push("Claude.exe".into());
    assert!(
        uninstall_with(&fixture.operations, fixture.uninstall_request())
            .unwrap_err()
            .contains("still running")
    );
    fixture.operations.active_processes.borrow_mut().clear();

    let mut installed = fixture.installed_state();
    let unexpected_root = fixture._temp.path().join("unexpected");
    std::fs::create_dir_all(&unexpected_root).unwrap();
    installed.install_root = unexpected_root;
    let certificate_root = installed
        .install_root
        .join("generations")
        .join(&installed.generation);
    installed.certificate.root_der = certificate_root.join("root-ca.der");
    installed.certificate.root_pem = certificate_root.join("root-ca.pem");
    installed.certificate.leaf_der = certificate_root.join("api.anthropic.com.der");
    installed.certificate.leaf_key_der = certificate_root.join("api.anthropic.com-key.der");
    let mut bytes = serde_json::to_vec_pretty(&installed).unwrap();
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&installed.state_path(), &bytes).unwrap();
    state::write_locator(&installed.state_path()).unwrap();
    assert!(
        uninstall_with(
            &fixture.operations,
            UninstallRequest {
                install_dir: None,
                dry_run: false,
            },
        )
        .unwrap_err()
        .contains("unexpected install root")
    );
}

#[test]
fn uninstall_retains_concurrent_changes_to_relay_managed_settings() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    let mut settings =
        crate::agents::shared::host::read_json_object(&installed.settings.settings_path).unwrap();
    settings["env"]["HTTPS_PROXY"] = serde_json::Value::String("https://new.example".into());
    let mut bytes = serde_json::to_vec_pretty(&settings).unwrap();
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&installed.settings.settings_path, &bytes).unwrap();

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    let restored =
        crate::agents::shared::host::read_json_object(&installed.settings.settings_path).unwrap();
    assert_eq!(restored["env"]["HTTPS_PROXY"], "https://new.example");
}

#[test]
fn preflight_rejects_running_claude_and_custom_anthropic_gateway() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    fixture
        .operations
        .active_processes
        .borrow_mut()
        .push("Claude".into());
    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("close Claude Desktop"));

    fixture.operations.active_processes.borrow_mut().clear();
    *fixture.operations.anthropic_base_url.borrow_mut() = "https://gateway.example".into();
    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("does not yet support a custom Anthropic gateway"));
}

#[test]
fn failed_linux_ca_composition_recovers_the_preparation_journal() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    std::fs::create_dir_all(fixture.operations.settings_path.parent().unwrap()).unwrap();
    std::fs::write(
        &fixture.operations.settings_path,
        r#"{"env":{"NODE_EXTRA_CA_CERTS":"/missing/claude-ca.pem"}}"#,
    )
    .unwrap();

    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("failed to resolve NODE_EXTRA_CA_CERTS"));
    assert!(error.contains("restored the previous Claude Desktop generation"));
    assert!(!fixture.state_path().exists());
    assert!(!state::journal_path(&fixture.marketplace_dir.join("claude-desktop")).exists());
    assert!(!fixture.marketplace_dir.join("claude-desktop").exists());
}

#[test]
fn task_failure_preserves_failure_origin() {
    assert_eq!(
        task_failure::<String>("proxy", Ok(Ok(()))),
        "Claude Desktop proxy stopped unexpectedly"
    );
    assert_eq!(
        task_failure("gateway", Ok(Err("network"))),
        "Claude Desktop gateway failed: network"
    );
    let join_error = tokio::runtime::Runtime::new().unwrap().block_on(async {
        tokio::spawn(async { panic!("test panic") })
            .await
            .unwrap_err()
    });
    assert!(task_failure::<String>("proxy", Err(join_error)).contains("task failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_runs_the_real_gateway_and_authenticated_proxy_until_shutdown() {
    let _port_guard = FIXED_PORT_TEST_LOCK.lock().await;
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    let (gateway_fingerprint, anthropic_base_url, max_hook_payload_bytes) =
        persistent_gateway_identity().unwrap();
    assert_eq!(
        anthropic_base_url.trim_end_matches('/'),
        "https://api.anthropic.com"
    );
    assert_eq!(
        max_hook_payload_bytes,
        crate::configuration::DEFAULT_MAX_HOOK_PAYLOAD_BYTES
    );
    installed.gateway_fingerprint = gateway_fingerprint;
    installed.configuration_fingerprint = configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.upstream_proxy.as_ref(),
    )
    .unwrap();
    state::write(&installed).unwrap();

    let sidecar = tokio::spawn(run_sidecar(SidecarRequest {
        state: fixture.state_path(),
    }));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let health_state = installed.clone();
        let healthy = tokio::task::spawn_blocking(move || {
            proxy::health(&health_state, Duration::from_millis(200)).is_ok()
        })
        .await
        .unwrap();
        if healthy {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real Claude Desktop sidecar did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let shutdown_state = installed.clone();
    tokio::task::spawn_blocking(move || proxy::shutdown(&shutdown_state, Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), sidecar)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn sidecar_rejects_relocated_or_stale_installed_state() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let relocated_state = fixture.installed_state();
    let relocated = relocated_state.install_root.join("relocated-state.json");
    let mut bytes = serde_json::to_vec_pretty(&relocated_state).unwrap();
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&relocated, &bytes).unwrap();
    assert!(
        run_sidecar(SidecarRequest { state: relocated })
            .await
            .unwrap_err()
            .to_string()
            .contains("state path does not match")
    );

    let mut installed = fixture.installed_state();
    installed.configuration_fingerprint = "stale".into();
    state::write(&installed).unwrap();
    assert!(
        run_sidecar(SidecarRequest {
            state: fixture.state_path(),
        })
        .await
        .unwrap_err()
        .to_string()
        .contains("fingerprint is stale")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_operations_delegate_to_the_real_host_adapters() {
    let _port_guard = FIXED_PORT_TEST_LOCK.lock().await;
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    let operations = SystemOperations;
    let current = operations.platform().unwrap();

    let _ = operations.validate_supported_platform(current);
    let _ = operations.application_identity(current);
    let _ = operations.active_claude_processes(current);
    let _ = operations.ensure_no_foreign_service(current, &installed.install_root);
    assert!(operations.relay_binary().unwrap().is_file());
    assert!(operations.persistent_gateway_identity().is_ok());
    assert!(
        operations
            .settings_path()
            .unwrap()
            .ends_with("settings.json")
    );
    assert!(!operations.plugin_exists(&fixture.marketplace_dir));
    assert!(
        operations
            .trust_status(
                platform::Platform::Linux,
                &installed.certificate,
                Some(&installed.certificate.root_pem),
            )
            .is_ok()
    );
    operations
        .install_trust(platform::Platform::Linux, &installed.certificate)
        .unwrap();
    operations
        .remove_trust(platform::Platform::Linux, &installed.certificate)
        .unwrap();

    let mut invalid = installed.clone();
    invalid.platform = "invalid".into();
    assert!(operations.register_service(&invalid).is_err());
    assert!(operations.start_service(&invalid).is_err());
    assert!(operations.stop_service(&invalid).is_err());
    assert!(operations.unregister_service(&invalid).is_err());
    assert!(operations.service_status(&invalid).is_err());

    let tls = certificate::server_config(&installed.install_root, &installed.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = proxy::Runtime::new(installed.clone(), tls, shutdown_tx).unwrap();
    let listener = TcpListener::bind(PROXY_BIND).await.unwrap();
    let proxy_task = tokio::spawn(proxy::serve(listener, runtime));
    assert!(
        operations
            .health(&installed)
            .unwrap_err()
            .contains("gateway")
    );
    operations.shutdown_proxy(&installed);
    proxy_task.await.unwrap().unwrap();

    assert!(
        operations
            .post_install_doctor(&fixture.marketplace_dir)
            .is_err()
    );
    assert!(operations.plugin_checks(None).is_ok());
}

#[test]
fn configuration_fingerprint_tracks_binary_proxy_and_ca_content() {
    let temp = tempfile::tempdir().unwrap();
    let relay = temp.path().join("relay");
    let ca = temp.path().join("ca.pem");
    std::fs::write(&relay, b"relay one").unwrap();
    std::fs::write(&ca, b"ca one").unwrap();
    let proxy = settings::UpstreamProxy {
        url: "https://proxy.example:8443/".into(),
        no_proxy: Some("localhost".into()),
        ca_bundle: Some(ca.clone()),
    };
    let first =
        configuration_fingerprint("generation", &relay, "gateway", "root", Some(&proxy)).unwrap();
    std::fs::write(&relay, b"relay two").unwrap();
    let second =
        configuration_fingerprint("generation", &relay, "gateway", "root", Some(&proxy)).unwrap();
    std::fs::write(&ca, b"ca two").unwrap();
    let third =
        configuration_fingerprint("generation", &relay, "gateway", "root", Some(&proxy)).unwrap();
    assert_ne!(first, second);
    assert_ne!(second, third);
}

#[test]
fn generation_removal_is_scoped_and_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("claude-desktop");
    let generation = root.join("generations").join("one");
    std::fs::create_dir_all(&generation).unwrap();
    std::fs::write(generation.join("certificate.pem"), b"certificate").unwrap();
    remove_generation(&root, "one").unwrap();
    remove_generation(&root, "one").unwrap();
    assert!(!generation.exists());
}

#[test]
fn linux_ca_bundle_reads_the_installed_field_only() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    assert_eq!(
        linux_ca_bundle(&installed),
        installed
            .settings
            .fields
            .get("NODE_EXTRA_CA_CERTS")
            .unwrap()
            .installed
            .as_ref()
            .unwrap()
            .as_str()
            .map(Path::new)
    );
}

#[test]
fn deep_link_rejects_non_unicode_folder() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let folder = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
        assert!(
            deep_link(folder)
                .unwrap_err()
                .to_string()
                .contains("Unicode")
        );
    }
}

#[test]
fn dry_run_is_explicit_and_does_not_mutate_installation_state() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    let mut install = fixture.install_request(false, true);
    install.dry_run = true;
    install_with(&fixture.operations, install).unwrap();
    assert!(!fixture.state_path().exists());

    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut uninstall = fixture.uninstall_request();
    uninstall.dry_run = true;
    uninstall_with(&fixture.operations, uninstall).unwrap();
    assert!(fixture.state_path().exists());
}

#[tokio::test]
async fn public_entrypoints_preserve_cli_error_categories() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let mut request = fixture.install_request(false, true);
    request.dry_run = true;
    assert_eq!(install(request).unwrap(), ExitCode::SUCCESS);

    assert!(matches!(
        uninstall(fixture.uninstall_request()),
        Err(CliError::Install(_))
    ));
    assert!(matches!(
        doctor(Some(fixture.marketplace_dir.clone()), true),
        Err(CliError::Install(_))
    ));
    assert!(matches!(
        launch(LaunchRequest { folder: None }).await,
        Err(CliError::Install(_))
    ));
}

#[test]
fn repeated_install_requires_force() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("already installed"));
}

#[test]
fn interrupted_install_recovery_removes_the_uncommitted_generation() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal("install", "sidecar_healthy", &installed.generation, None);

    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::Linux,
    )
    .unwrap();
    assert!(!fixture.state_path().exists());
    assert!(fixture.operations.called("unregister_service"));
    assert!(fixture.operations.called("remove_trust"));
    assert!(fixture.operations.called("uninstall_plugin"));
}

#[test]
fn preparation_recovery_handles_new_and_preexisting_generations() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal("install", "preparing", &installed.generation, None);
    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::MacOs,
    )
    .unwrap();
    assert!(!fixture.state_path().exists());
    drop(fixture);

    let fixture = LifecycleFixture::new(platform::Platform::Windows, true);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal(
        "install",
        "preparing",
        "uncommitted-generation",
        Some(installed.clone()),
    );
    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::Windows,
    )
    .unwrap();
    assert_eq!(fixture.installed_state().generation, installed.generation);
    assert!(fixture.operations.called("install_plugin"));
    assert!(fixture.operations.called("install_trust"));
}

#[test]
fn interrupted_uninstall_is_restored_or_finished_by_journal_stage() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal(
        "uninstall",
        "started",
        &installed.generation,
        Some(installed.clone()),
    );
    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::MacOs,
    )
    .unwrap();
    assert!(fixture.state_path().exists());
    assert!(!state::journal_path(&installed.install_root).exists());
    assert!(fixture.operations.called("stop_direct_gateway"));

    fixture.write_journal(
        "uninstall",
        "committed",
        &installed.generation,
        Some(installed.clone()),
    );
    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::MacOs,
    )
    .unwrap();
    assert!(!installed.install_root.exists());
}

#[test]
fn interrupted_operation_rejects_platform_and_generation_mismatch() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    installed.platform = "windows".into();
    fixture.write_journal(
        "install",
        "sidecar_healthy",
        &installed.generation,
        Some(installed.clone()),
    );
    assert!(
        recover_interrupted_operation(
            &fixture.operations,
            &installed.install_root,
            &fixture.state_path(),
            platform::Platform::MacOs,
        )
        .unwrap_err()
        .contains("different operating system")
    );

    installed.platform = "macos".into();
    fixture.write_journal(
        "install",
        "sidecar_healthy",
        "different-generation",
        Some(installed.clone()),
    );
    assert!(
        recover_interrupted_operation(
            &fixture.operations,
            &installed.install_root,
            &fixture.state_path(),
            platform::Platform::MacOs,
        )
        .unwrap_err()
        .contains("refusing to recover journal generation")
    );
}

#[test]
fn interrupted_operation_rejects_unknown_or_incomplete_journals() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal(
        "upgrade-from-the-future",
        "started",
        &installed.generation,
        Some(installed.clone()),
    );
    let error = recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &fixture.state_path(),
        platform::Platform::Linux,
    )
    .unwrap_err();
    assert!(error.contains("invalid operation metadata"), "{error}");

    fixture.write_journal("uninstall", "started", &installed.generation, None);
    assert!(
        recover_interrupted_operation(
            &fixture.operations,
            &installed.install_root,
            &fixture.state_path(),
            platform::Platform::Linux,
        )
        .unwrap_err()
        .contains("no prior generation")
    );
}

#[test]
fn doctor_and_launch_use_the_same_effective_protection_contract() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    assert!(report.ok);
    assert!(report.effective_protection);
    assert!(report.checks.iter().all(|check| check.ok));
    assert_eq!(
        doctor_with(&fixture.operations, Some(&fixture.marketplace_dir), true).unwrap(),
        ExitCode::SUCCESS
    );
    assert_eq!(
        doctor_with(&fixture.operations, Some(&fixture.marketplace_dir), false).unwrap(),
        ExitCode::SUCCESS
    );

    fixture.operations.healthy.set(false);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(launch_with(
            &fixture.operations,
            LaunchRequest {
                folder: Some(fixture._temp.path().to_path_buf()),
            },
        ))
        .unwrap();
    assert!(fixture.operations.called("start_service"));
    assert!(fixture.operations.called("open_deep_link"));
}

#[test]
fn doctor_and_launch_fail_closed_on_unhealthy_protection_or_bad_folder() {
    let fixture = LifecycleFixture::new(platform::Platform::Windows, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    fixture.operations.doctor_healthy.set(false);
    fixture.operations.healthy.set(false);
    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    assert!(!report.ok);
    assert_eq!(
        doctor_with(&fixture.operations, Some(&fixture.marketplace_dir), false).unwrap(),
        ExitCode::FAILURE
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let starts_before_launch = fixture.operations.call_count("start_service");
    let error = runtime
        .block_on(launch_with(
            &fixture.operations,
            LaunchRequest {
                folder: Some(fixture._temp.path().to_path_buf()),
            },
        ))
        .unwrap_err();
    assert!(error.to_string().contains("protection is unhealthy"));
    assert_eq!(
        fixture.operations.call_count("start_service"),
        starts_before_launch,
        "launch must not start a service while a static protection check is unhealthy"
    );
    assert!(!fixture.operations.called("open_deep_link"));

    fixture.operations.doctor_healthy.set(true);
    fixture.operations.healthy.set(true);
    let error = runtime
        .block_on(launch_with(
            &fixture.operations,
            LaunchRequest {
                folder: Some(fixture._temp.path().join("missing")),
            },
        ))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to resolve Claude folder")
    );

    let file = fixture._temp.path().join("not-a-directory");
    std::fs::write(&file, b"file").unwrap();
    let error = runtime
        .block_on(launch_with(
            &fixture.operations,
            LaunchRequest { folder: Some(file) },
        ))
        .unwrap_err();
    assert!(error.to_string().contains("folder is not a directory"));
}

#[test]
fn doctor_reports_expiry_journal_files_proxy_and_fingerprint_independently() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    installed.certificate.not_after = "2020-01-01".into();
    installed.configuration_fingerprint = "changed".into();
    installed.upstream_proxy = Some(settings::UpstreamProxy {
        url: "socks5://proxy.example:1080".into(),
        no_proxy: None,
        ca_bundle: None,
    });
    std::fs::remove_file(&installed.certificate.leaf_key_der).unwrap();
    state::write(&installed).unwrap();
    fixture.write_journal("install", "sidecar_healthy", &installed.generation, None);

    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    for name in [
        "transaction_journal",
        "certificate_files",
        "certificate_expiry",
        "file_permissions",
        "upstream_proxy",
        "gateway_configuration",
    ] {
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == name && !check.ok),
            "expected failed {name} check: {:?}",
            report.checks
        );
    }
}

#[test]
fn doctor_warns_before_certificate_expiry_without_marking_protection_unhealthy() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    installed.certificate.not_after =
        (chrono::Utc::now().date_naive() + chrono::Duration::days(10)).to_string();
    state::write(&installed).unwrap();

    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    let expiry = report
        .checks
        .iter()
        .find(|check| check.name == "certificate_expiry")
        .unwrap();
    assert!(expiry.ok);
    assert!(expiry.details.contains("rotate with"));
    assert!(report.ok);
}

#[test]
fn rollback_error_collection_preserves_every_failure() {
    let mut errors = RollbackErrors::default();
    errors.record(Err("trust rollback failed".into()));
    errors.record(Ok(()));
    errors.record(Err("service rollback failed".into()));
    assert_eq!(
        errors.finish().unwrap_err(),
        "trust rollback failed; service rollback failed"
    );
}

#[test]
fn fresh_install_cleanup_preserves_unknown_files() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let install_root = fixture.marketplace_dir.join("claude-desktop");
    std::fs::create_dir_all(install_root.join("generations")).unwrap();
    std::fs::write(install_root.join("sidecar.stdout.log"), b"known log").unwrap();
    std::fs::write(install_root.join("foreign-file"), b"preserve me").unwrap();

    assert!(remove_fresh_install_root(&install_root).is_err());
    assert!(install_root.join("foreign-file").exists());
    assert!(!install_root.join("sidecar.stdout.log").exists());
    assert!(install_root.exists());
}
