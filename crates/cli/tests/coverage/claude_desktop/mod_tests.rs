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
    generate_hook_on_install: Cell<bool>,
    generated_hook_command: RefCell<Option<String>>,
    occupy_first_started_endpoint: Cell<bool>,
    handoff_health_failure: Cell<bool>,
    occupied_endpoint: RefCell<Option<std::net::TcpListener>>,
    failures: RefCell<Vec<String>>,
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
            generate_hook_on_install: Cell::new(false),
            generated_hook_command: RefCell::new(None),
            occupy_first_started_endpoint: Cell::new(false),
            handoff_health_failure: Cell::new(false),
            occupied_endpoint: RefCell::new(None),
            failures: RefCell::new(Vec::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn step(&self, name: &str) -> Result<(), String> {
        self.calls.borrow_mut().push(name.into());
        if self.failures.borrow().first().map(String::as_str) != Some(name) {
            return Ok(());
        }
        self.failures.borrow_mut().remove(0);
        Err(format!("injected {name} failure"))
    }

    fn fail_once(&self, name: &str) {
        self.failures.borrow_mut().push(name.into());
    }

    fn fail_in_order(&self, names: &[&str]) {
        self.failures
            .borrow_mut()
            .extend(names.iter().map(|name| (*name).to_string()));
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

    fn service_identity(&self, platform: platform::Platform) -> Result<Option<String>, String> {
        self.step("service_identity")?;
        Ok((platform == platform::Platform::Windows).then(|| "S-1-5-21-1000".into()))
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
        marketplace_dir: &Path,
        _force: bool,
        _skip_doctor: bool,
    ) -> Result<(), String> {
        self.step("install_plugin")?;
        if self.generate_hook_on_install.get() {
            let command = crate::hooks::persistent_hook_forward_command(
                &self.relay_binary,
                CodingAgent::ClaudeCode,
                &marketplace_dir.join("plugins/nemo-relay-plugin/.nemo-relay-generation"),
                "test-plugin-generation",
            )?;
            *self.generated_hook_command.borrow_mut() = Some(command);
        }
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
                serde_json::Value::String(format!("http://{LEGACY_PROXY_BIND}")),
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
        if self.occupy_first_started_endpoint.replace(false) {
            let listener = std::net::TcpListener::bind(installed.bind)
                .map_err(|error| format!("failed to simulate endpoint handoff race: {error}"))?;
            *self.occupied_endpoint.borrow_mut() = Some(listener);
            self.handoff_health_failure.set(true);
        }
        if self.write_service_logs.get() {
            std::fs::write(installed.install_root.join("proxy.stdout.log"), b"")
                .map_err(|error| error.to_string())?;
            std::fs::write(
                installed.install_root.join("proxy.stderr.log"),
                b"proxy failed",
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
        if self.handoff_health_failure.replace(false) {
            return Err("simulated endpoint handoff race".into());
        }
        self.healthy.set(true);
        Ok(())
    }

    fn health(&self, installed: &state::DesktopState) -> Result<proxy::Health, String> {
        self.step("health")?;
        if !self.healthy.get() {
            return Err("injected unhealthy proxy".into());
        }
        Ok(proxy::Health {
            service: "nemo-relay-agent-proxy".into(),
            version: installed.relay_version.clone(),
            generation: installed.generation.clone(),
            configuration_fingerprint: installed.configuration_fingerprint.clone(),
            gateway_url: format!("https://{}", installed.bind),
            proxy_url: format!("https://{}", installed.bind),
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
            .join("agent-proxy")
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
            &self.marketplace_dir.join("agent-proxy"),
            &state::InstallJournal {
                schema_version: state::STATE_SCHEMA_VERSION,
                operation: operation.into(),
                stage: stage.into(),
                generation: generation.into(),
                old_state,
                settings_snapshot: None,
                provider_backup_snapshot: None,
                marketplace_snapshot: None,
                settings_result_snapshot: None,
                provider_backup_result_snapshot: None,
                marketplace_result_snapshot: None,
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
fn coding_agent_proxy_uses_one_dynamic_loopback_endpoint() {
    assert!(LEGACY_PROXY_BIND.ip().is_loopback());
    assert_ne!(LEGACY_PROXY_BIND, PROXY_BIND);
    let selected = select_proxy_bind().unwrap();
    assert!(selected.ip().is_loopback());
    assert_ne!(selected.port(), 0);
    let first_user = proxy_port_candidates(1_000).collect::<Vec<_>>();
    let second_user = proxy_port_candidates(1_001).collect::<Vec<_>>();
    assert_eq!(first_user.len(), usize::from(USER_PORT_PROBE_COUNT));
    assert!(
        first_user.iter().all(|port| {
            (USER_PORT_BASE..USER_PORT_BASE + USER_PORT_SPAN as u16).contains(port)
        })
    );
    assert_ne!(first_user[0], second_user[0]);
}

#[test]
fn dynamic_proxy_port_candidates_never_include_the_legacy_listener() {
    let user_key = (0..u64::from(USER_PORT_SPAN))
        .find(|user_key| {
            let offset =
                ((user_key.wrapping_mul(2_654_435_761)) % u64::from(USER_PORT_SPAN)) as u16;
            USER_PORT_BASE + offset == LEGACY_PROXY_BIND.port()
        })
        .expect("one user-derived offset must map to the legacy port");

    let candidates = proxy_port_candidates(user_key).collect::<Vec<_>>();

    assert_eq!(candidates.len(), usize::from(USER_PORT_PROBE_COUNT));
    assert!(!candidates.contains(&LEGACY_PROXY_BIND.port()));
}

#[test]
fn dynamic_proxy_port_selection_advances_past_a_collision() {
    let (user_key, first_port, _reservation) = (0..u64::from(USER_PORT_SPAN))
        .find_map(|user_key| {
            let first_port = proxy_port_candidates(user_key).next().unwrap();
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, first_port))
                .ok()
                .map(|listener| (user_key, first_port, listener))
        })
        .expect("a candidate port must be available for the collision test");

    let selected = select_proxy_bind_for_user(user_key).unwrap();

    assert_eq!(selected.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(selected.port(), first_port);
    assert!(proxy_port_candidates(user_key).any(|port| port == selected.port()));
}

#[test]
fn dynamic_proxy_port_selection_falls_back_after_all_candidates_collide() {
    let (user_key, reservations) = (0..u64::from(USER_PORT_SPAN))
        .find_map(|user_key| {
            let mut reservations = Vec::new();
            for port in proxy_port_candidates(user_key) {
                match std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                    Ok(listener) => reservations.push(listener),
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => return None,
                    Err(error) => panic!("failed to reserve candidate port {port}: {error}"),
                }
            }
            Some((user_key, reservations))
        })
        .expect("a complete candidate range must be available for the fallback test");
    let candidates = proxy_port_candidates(user_key).collect::<Vec<_>>();

    let selected = select_proxy_bind_for_user(user_key).unwrap();

    assert_eq!(selected.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(selected.port(), 0);
    assert!(!candidates.contains(&selected.port()));
    assert_eq!(reservations.len(), usize::from(USER_PORT_PROBE_COUNT));
}

#[test]
fn fresh_service_reselects_and_retargets_after_bind_handoff_race() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    fixture.operations.occupy_first_started_endpoint.set(true);

    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();

    let installed = fixture.installed_state();
    let occupied = fixture
        .operations
        .occupied_endpoint
        .borrow()
        .as_ref()
        .unwrap()
        .local_addr()
        .unwrap();
    assert_ne!(installed.bind, occupied);
    assert_eq!(fixture.operations.call_count("start_service"), 2);
    assert_eq!(fixture.operations.call_count("wait_for_health"), 3);
    assert_eq!(fixture.operations.call_count("stop_service"), 1);
    assert_eq!(fixture.operations.call_count("register_service"), 2);
    settings::matches(&installed.settings).unwrap();
    let proxy_url = installed.proxy_url();
    assert_eq!(
        installed
            .settings
            .fields
            .get("HTTPS_PROXY")
            .and_then(|field| field.installed.as_ref())
            .and_then(Value::as_str),
        Some(proxy_url.as_str())
    );
}

#[test]
fn fresh_claude_enrollment_retargets_owned_settings_after_handoff_race() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    fixture.operations.occupy_first_started_endpoint.set(true);
    let request = fixture.install_request(false, true);

    let enrollment =
        enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();

    let installed = fixture.installed_state();
    let occupied = fixture
        .operations
        .occupied_endpoint
        .borrow()
        .as_ref()
        .unwrap()
        .local_addr()
        .unwrap();
    assert_ne!(installed.bind, occupied);
    assert_eq!(
        enrollment.gateway_url,
        format!("https://{}", installed.bind)
    );
    assert_eq!(fixture.operations.call_count("start_service"), 2);
    assert_eq!(fixture.operations.call_count("wait_for_health"), 2);
    settings::matches(&installed.settings).unwrap();
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
    report.push("proxy_identity", Ok("generation matches".into()));
    let value = serde_json::to_value(report.finish()).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["integration"], "claude-desktop");
    assert_eq!(value["effective_protection"], true);
    assert_eq!(value["checks"][0]["name"], "proxy_identity");
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
    assert!(!first.certificate.root_pem.exists());
    assert!(fixture.operations.called("stop_service"));

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();
    assert!(fixture.operations.called("uninstall_plugin"));
}

#[test]
fn preexisting_legacy_plugin_is_rejected_without_mutation() {
    let fixture = LifecycleFixture::new(platform::Platform::Windows, true);
    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("does not migrate it in place"), "{error}");
    assert!(fixture.operations.plugin_present.get());
    assert!(!fixture.state_path().exists());
}

#[test]
fn preexisting_legacy_plugin_rejection_preserves_provider_files_exactly() {
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

    let error =
        install_with(&fixture.operations, fixture.install_request(false, true)).unwrap_err();
    assert!(error.contains("old Relay binary"), "{error}");
    assert_eq!(std::fs::read(&backup_path).unwrap(), provider_backup);
    assert_eq!(
        std::fs::read(&fixture.operations.settings_path).unwrap(),
        settings
    );
}

#[test]
fn failed_desktop_install_restores_the_provider_backup_exactly() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
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
    assert!(!fixture.operations.plugin_present.get());
    assert!(!fixture.marketplace_dir.join("agent-proxy").exists());
    assert_ne!(
        state::resolve_state_path(None).unwrap(),
        fixture.state_path(),
        "rollback retained the pre-plugin state locator"
    );
}

#[test]
fn failed_install_rollback_retains_its_recovery_journal() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    fixture
        .operations
        .fail_in_order(&["post_install_doctor", "remove_trust"]);

    let error =
        install_with(&fixture.operations, fixture.install_request(false, false)).unwrap_err();

    assert!(error.contains("rollback also failed"), "{error}");
    assert!(
        state::journal_path(&fixture.marketplace_dir.join("agent-proxy")).exists(),
        "failed rollback erased its only durable recovery record"
    );
    recover_interrupted_operation(
        &fixture.operations,
        &fixture.marketplace_dir.join("agent-proxy"),
        &fixture.state_path(),
        platform::Platform::Linux,
    )
    .unwrap();
    assert!(!fixture.state_path().exists());
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
    assert!(!fixture.marketplace_dir.join("agent-proxy").exists());
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
fn failed_uninstall_rollback_retains_its_recovery_journal() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture
        .operations
        .fail_in_order(&["remove_trust", "register_service"]);

    let error = uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap_err();

    assert!(error.contains("rollback also failed"), "{error}");
    assert!(
        state::journal_path(&installed.install_root).exists(),
        "failed rollback erased its only durable recovery record"
    );
    recover_interrupted_operation(
        &fixture.operations,
        &installed.install_root,
        &installed.state_path(),
        platform::Platform::MacOs,
    )
    .unwrap();
    assert!(!state::journal_path(&installed.install_root).exists());
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
    installed.certificate.ca_key_der = certificate_root.join("root-ca-key.der");
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
    assert!(error.contains("does not support a custom Anthropic upstream"));
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
    assert!(!state::journal_path(&fixture.marketplace_dir.join("agent-proxy")).exists());
    assert!(!fixture.marketplace_dir.join("agent-proxy").exists());
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
async fn proxy_service_runs_managed_engine_and_authenticated_proxy_until_shutdown() {
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
        &installed.user_config_dir,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )
    .unwrap();
    state::write(&installed).unwrap();
    let unrelated_service_environment = fixture._temp.path().join("service-environment-config");
    std::fs::create_dir_all(&unrelated_service_environment).unwrap();
    fixture._environment.update(&[(
        "XDG_CONFIG_HOME",
        Some(unrelated_service_environment.as_os_str()),
    )]);

    let proxy_service = tokio::spawn(run_proxy_service(ProxyServiceRequest {
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
            "real coding-agent proxy did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let shutdown_state = installed.clone();
    tokio::task::spawn_blocking(move || proxy::shutdown(&shutdown_state, Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), proxy_service)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        ExitCode::SUCCESS
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn running_proxy_rejects_routes_after_state_permissions_are_relaxed() {
    use std::os::unix::fs::PermissionsExt;

    let _port_guard = FIXED_PORT_TEST_LOCK.lock().await;
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    let (gateway_fingerprint, _, _) = persistent_gateway_identity().unwrap();
    installed.gateway_fingerprint = gateway_fingerprint;
    installed.configuration_fingerprint = configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &installed.user_config_dir,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )
    .unwrap();
    state::write(&installed).unwrap();

    let proxy_service = tokio::spawn(run_proxy_service(ProxyServiceRequest {
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
        assert!(Instant::now() < deadline, "proxy did not become healthy");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    std::fs::set_permissions(fixture.state_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    let health_state = installed.clone();
    let error =
        tokio::task::spawn_blocking(move || proxy::health(&health_state, Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap_err();
    assert!(error.contains("rejected authenticated request"), "{error}");

    let shutdown_state = installed.clone();
    tokio::task::spawn_blocking(move || proxy::shutdown(&shutdown_state, Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), proxy_service)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn proxy_service_rejects_relocated_or_stale_installed_state() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let relocated_state = fixture.installed_state();
    let relocated = relocated_state.install_root.join("relocated-state.json");
    let mut bytes = serde_json::to_vec_pretty(&relocated_state).unwrap();
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&relocated, &bytes).unwrap();
    assert!(
        run_proxy_service(ProxyServiceRequest { state: relocated })
            .await
            .unwrap_err()
            .to_string()
            .contains("state path does not match")
    );

    let mut installed = fixture.installed_state();
    installed.configuration_fingerprint = "stale".into();
    state::write(&installed).unwrap();
    assert!(
        run_proxy_service(ProxyServiceRequest {
            state: fixture.state_path(),
        })
        .await
        .unwrap_err()
        .to_string()
        .contains("fingerprint is stale")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn proxy_service_and_doctor_reject_a_shared_generation_directory() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    let (gateway_fingerprint, _, _) = persistent_gateway_identity().unwrap();
    installed.gateway_fingerprint = gateway_fingerprint;
    installed.configuration_fingerprint = configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &installed.user_config_dir,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )
    .unwrap();
    state::write(&installed).unwrap();
    let generation = installed
        .install_root
        .join("generations")
        .join(&installed.generation);
    std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o750)).unwrap();

    let error = run_proxy_service(ProxyServiceRequest {
        state: fixture.state_path(),
    })
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("must have owner-only mode 700"), "{error}");

    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    let permissions = report
        .checks
        .iter()
        .find(|check| check.name == "file_permissions")
        .unwrap();
    assert!(!permissions.ok);
    assert!(
        permissions
            .details
            .contains("must have owner-only mode 700")
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
    let listener = TcpListener::bind(installed.bind).await.unwrap();
    let proxy_task = tokio::spawn(proxy::serve(listener, runtime));
    assert!(operations.health(&installed).is_ok());
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
    let user_config_dir = temp.path().join("config");
    let mut enrollments = std::collections::BTreeMap::new();
    let first = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        None,
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    std::fs::write(&relay, b"relay two").unwrap();
    let second = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        None,
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    std::fs::write(&ca, b"ca two").unwrap();
    let third = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        None,
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    assert_ne!(first, second);
    assert_ne!(second, third);

    let agent_ca = temp.path().join("agent-ca.pem");
    std::fs::write(&agent_ca, b"agent ca one").unwrap();
    enrollments.insert(
        "codex".into(),
        state::AgentEnrollment {
            username: "codex".into(),
            token: "secret".into(),
            installed_at: "now".into(),
            upstream_proxy: Some(settings::UpstreamProxy {
                url: "https://codex-proxy.example:8443/".into(),
                no_proxy: None,
                ca_bundle: Some(agent_ca.clone()),
            }),
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    let fourth = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        None,
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    std::fs::write(&agent_ca, b"agent ca two").unwrap();
    let fifth = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        None,
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    assert_ne!(third, fourth);
    assert_ne!(fourth, fifth);
    let sixth = configuration_fingerprint(
        "generation",
        &relay,
        &user_config_dir,
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        Some("S-1-5-21-1000"),
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    assert_ne!(fifth, sixth);
    let seventh = configuration_fingerprint(
        "generation",
        &relay,
        &temp.path().join("different-config"),
        "gateway",
        "root",
        LEGACY_PROXY_BIND,
        Some("S-1-5-21-1000"),
        Some(&proxy),
        &enrollments,
    )
    .unwrap();
    assert_ne!(sixth, seventh);
}

#[test]
fn runtime_binary_identity_hashes_once_and_detects_metadata_changes() {
    let temp = tempfile::tempdir().unwrap();
    let relay = temp.path().join("relay");
    std::fs::write(&relay, b"relay executable").unwrap();

    let identity = RelayBinaryIdentity::capture(&relay).unwrap();
    assert_eq!(identity.sha256, relay_binary_sha256(&relay).unwrap());
    identity.verify(&relay).unwrap();

    std::fs::write(&relay, b"changed relay executable").unwrap();
    assert!(identity.verify(&relay).unwrap_err().contains("changed"));
}

#[test]
fn generation_removal_is_scoped_and_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("agent-proxy");
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
fn desktop_only_install_generates_and_validates_shared_claude_hook_delivery() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    fixture.operations.generate_hook_on_install.set(true);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();

    assert!(enrollment(CodingAgent::ClaudeCode).unwrap().is_some());
    let shared = claude_plugin_enrollment().unwrap().unwrap();
    assert_eq!(
        shared.gateway_url,
        format!("https://{}", fixture.installed_state().bind)
    );
    assert!(shared.authorization.starts_with("Basic "));
    let command = fixture
        .operations
        .generated_hook_command
        .borrow()
        .clone()
        .expect("Desktop installation generated the shared Claude hook");
    assert!(command.contains("hook-forward claude"));
    assert!(command.contains(&shared.gateway_url));
    verify_hook_enrollment_health_with(&fixture.operations, CodingAgent::ClaudeCode, &shared)
        .unwrap();
}

#[test]
fn claude_code_and_desktop_share_one_configuration_enrollment() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let before = fixture.installed_state();
    let before_proxy = before.proxy_url();

    enroll_agent_with(
        &fixture.operations,
        CodingAgent::ClaudeCode,
        &fixture.install_request(false, true),
    )
    .unwrap();

    let installed = fixture.installed_state();
    assert!(installed.claude_code_installed);
    assert!(installed.claude_desktop_installed);
    assert_eq!(
        installed.enrollments.keys().collect::<Vec<_>>(),
        vec![&"claude"]
    );
    assert_eq!(installed.proxy_url(), before_proxy);
    settings::matches(&installed.settings).unwrap();
}

#[test]
fn desktop_reuses_the_existing_claude_configuration_enrollment() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
    let before = fixture.installed_state();
    let before_proxy = before.proxy_url();

    install_with(&fixture.operations, request).unwrap();

    let installed = fixture.installed_state();
    assert!(installed.claude_code_installed);
    assert!(installed.claude_desktop_installed);
    assert_eq!(
        installed.enrollments.keys().collect::<Vec<_>>(),
        vec![&"claude"]
    );
    assert_eq!(installed.proxy_url(), before_proxy);
    settings::matches(&installed.settings).unwrap();
}

#[test]
fn hermes_host_setup_uses_the_explicit_proxy_state_root() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Hermes, &request).unwrap();

    let explicit = enrollment_at(CodingAgent::Hermes, Some(&fixture.marketplace_dir))
        .unwrap()
        .unwrap();
    let unrelated = tempfile::tempdir().unwrap();
    assert!(
        enrollment_at(CodingAgent::Hermes, Some(unrelated.path()))
            .unwrap()
            .is_none()
    );

    let config = fixture._temp.path().join("home/.hermes/config.yaml");
    crate::agents::hermes::install_persistent(
        &config,
        &std::env::current_exe().unwrap(),
        Some(&fixture.marketplace_dir),
    )
    .unwrap();
    let proxy_env = std::fs::read_to_string(config.parent().unwrap().join(".env")).unwrap();
    assert!(proxy_env.contains(&explicit.proxy_url));
}

#[test]
fn claude_code_enrollment_installs_native_proxy_settings() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);

    let enrollment =
        enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
    let installed = fixture.installed_state();

    assert!(enrollment.proxy_url.contains("nemo-relay-claude"));
    assert!(!installed.settings.fields.is_empty());
    settings::matches(&installed.settings).unwrap();
    let settings =
        crate::agents::shared::host::read_json_object(&installed.settings.settings_path).unwrap();
    let env = settings["env"].as_object().unwrap();
    assert_eq!(
        env.get("HTTPS_PROXY").and_then(Value::as_str),
        Some(enrollment.proxy_url.as_str())
    );
    assert!(!env.contains_key("ANTHROPIC_BASE_URL"));
    assert_eq!(
        env.get("CLAUDE_CODE_CERT_STORE").and_then(Value::as_str),
        Some("bundled,system")
    );
    assert!(!fixture.operations.called("stop_service"));
}

#[test]
fn first_agent_enrollment_does_not_stop_an_unregistered_service() {
    for platform in [platform::Platform::Windows, platform::Platform::Linux] {
        let fixture = LifecycleFixture::new(platform, false);
        let request = fixture.install_request(false, true);

        enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();

        assert!(!fixture.operations.called("stop_service"));
    }
}

#[test]
fn adding_an_agent_rotates_a_narrow_first_enrollment_ca_for_host_expansion() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
    let claude_only = fixture.installed_state();
    assert_eq!(
        certificate::permitted_dns_hosts(&claude_only.certificate).unwrap(),
        vec!["api.anthropic.com"]
    );

    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();
    let expanded = fixture.installed_state();
    assert_ne!(expanded.generation, claude_only.generation);
    assert_eq!(
        certificate::permitted_dns_hosts(&expanded.certificate).unwrap(),
        vec!["api.anthropic.com", "api.openai.com", "chatgpt.com"]
    );
    assert!(!claude_only.certificate.root_pem.exists());
}

#[test]
fn host_expansion_preserves_each_agents_corporate_route() {
    for added_agent in [CodingAgent::Codex, CodingAgent::Hermes] {
        let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
        let request = fixture.install_request(false, true);
        enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
        let mut claude_only = fixture.installed_state();
        let claude_route = settings::UpstreamProxy {
            url: "https://claude-proxy.example:8443/".into(),
            no_proxy: Some("localhost".into()),
            ca_bundle: None,
        };
        claude_only
            .enrollments
            .get_mut("claude")
            .unwrap()
            .upstream_proxy = Some(claude_route.clone());
        claude_only.upstream_proxy = Some(claude_route.clone());
        state::write(&claude_only).unwrap();

        enroll_agent_with(&fixture.operations, added_agent, &request).unwrap();
        let expanded = fixture.installed_state();

        assert_eq!(
            expanded.enrollments["claude"].upstream_proxy,
            Some(claude_route)
        );
        assert_eq!(
            expanded.enrollments[added_agent.install_arg()].upstream_proxy,
            None
        );
    }
}

#[test]
fn linux_codex_uses_a_stable_composed_ca_bundle_and_removes_it_with_ownership() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();

    let mut installed = fixture.installed_state();
    let source = fixture.marketplace_dir.join("existing-codex-ca.pem");
    std::fs::write(&source, b"existing corporate root\n").unwrap();
    let enrollment = installed.enrollments.get_mut("codex").unwrap();
    enrollment.client_ca_bundle_source = Some(source.clone());
    enrollment.client_ca_bundle_variable = Some("SSL_CERT_FILE".into());
    sync_codex_ca_bundle(&installed).unwrap();

    let stable = codex_ca_bundle_path(&installed.install_root);
    let root = std::fs::read(&installed.certificate.root_pem).unwrap();
    let bundle = std::fs::read(&stable).unwrap();
    assert!(bundle.starts_with(b"existing corporate root\n"));
    assert!(bundle.ends_with(&root));
    let notices = codex_ca_uninstall_notices(
        CodingAgent::Codex,
        platform::Platform::Linux,
        &installed.install_root,
        &installed.enrollments["codex"],
    );
    assert!(notices[0].contains(&stable.display().to_string()));
    assert!(notices[1].contains("SSL_CERT_FILE"));
    assert!(notices[1].contains(&source.display().to_string()));

    installed.enrollments.remove("codex");
    sync_codex_ca_bundle(&installed).unwrap();
    assert!(!stable.exists());
}

#[test]
fn host_install_failure_removes_a_fresh_proxy_enrollment() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);

    let error = enroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Codex,
        &request,
        &crate::agents::SetupSnapshot::Test,
        || Err::<(), _>(CliError::Install("injected host install failure".into())),
    )
    .unwrap_err();

    assert!(error.to_string().contains("injected host install failure"));
    assert!(!fixture.state_path().exists());
    assert!(fixture.operations.called("unregister_service"));
}

#[test]
fn host_install_failure_restores_a_forced_proxy_refresh_exactly() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let initial = fixture.install_request(false, true);
    enroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Codex,
        &initial,
        &crate::agents::SetupSnapshot::Test,
        || Ok::<_, CliError>(()),
    )
    .unwrap();
    let state_before = std::fs::read(fixture.state_path()).unwrap();

    let refresh = fixture.install_request(true, true);
    let error = enroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Codex,
        &refresh,
        &crate::agents::SetupSnapshot::Test,
        || Err::<(), _>(CliError::Install("injected replacement failure".into())),
    )
    .unwrap_err();

    assert!(error.to_string().contains("injected replacement failure"));
    assert_eq!(std::fs::read(fixture.state_path()).unwrap(), state_before);
}

#[test]
fn durable_agent_journal_recovers_a_crash_after_proxy_rotation() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let initial = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &initial).unwrap();
    let previous = fixture.installed_state();
    let state_before = std::fs::read(fixture.state_path()).unwrap();
    let mut journal = AgentTransactionJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "preparing-proxy".into(),
        agent: CodingAgent::Codex.install_arg().into(),
        install_root: previous.install_root.clone(),
        state_path: previous.state_path(),
        previous_state: Some(previous),
        setup_snapshot: crate::agents::SetupSnapshot::Test,
        setup_result_snapshot: None,
        marketplace_snapshot: None,
        marketplace_result_snapshot: None,
    };
    write_agent_transaction(&journal).unwrap();

    let mut interrupted = fixture.installed_state();
    interrupted.generation = "interrupted-generation".into();
    interrupted.certificate =
        certificate::generate(&interrupted.install_root, &interrupted.generation).unwrap();
    interrupted.configuration_fingerprint = "interrupted-configuration".into();
    state::write(&interrupted).unwrap();
    journal.stage = "proxy-active".into();
    write_agent_transaction(&journal).unwrap();
    assert_ne!(std::fs::read(fixture.state_path()).unwrap(), state_before);

    recover_pending_agent_transaction(&fixture.operations).unwrap();

    assert_eq!(std::fs::read(fixture.state_path()).unwrap(), state_before);
    assert!(!agent_transaction_path().unwrap().exists());
}

#[test]
fn committed_agent_install_finishes_retirement_instead_of_rolling_back() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let initial = fixture.install_request(false, true);
    enroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Codex,
        &initial,
        &crate::agents::SetupSnapshot::Test,
        || Ok::<_, CliError>(()),
    )
    .unwrap();
    let mut previous = fixture.installed_state();
    certificate::rewrite_host_constraints_for_test(
        &mut previous.certificate,
        &[certificate::INTERCEPTED_HOST],
    )
    .unwrap();
    state::write(&previous).unwrap();

    fixture.operations.fail_once("remove_trust");
    let error = enroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Codex,
        &fixture.install_request(true, true),
        &crate::agents::SetupSnapshot::Test,
        || Ok::<_, CliError>(()),
    )
    .unwrap_err();

    assert!(error.to_string().contains("remove_trust"));
    let committed = read_agent_transaction().unwrap().unwrap();
    assert_eq!(committed.stage, "committed");
    let active_generation = fixture.installed_state().generation;
    assert_ne!(active_generation, previous.generation);

    recover_pending_agent_transaction(&fixture.operations).unwrap();

    assert_eq!(fixture.installed_state().generation, active_generation);
    assert!(!agent_transaction_path().unwrap().exists());
    assert!(
        !previous
            .install_root
            .join("generations")
            .join(previous.generation)
            .exists()
    );
}

#[test]
fn committed_final_agent_uninstall_retires_generation_on_recovery() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();
    let previous = fixture.installed_state();
    let mut journal = AgentTransactionJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "uninstall".into(),
        stage: "host-removed".into(),
        agent: CodingAgent::Codex.install_arg().into(),
        install_root: previous.install_root.clone(),
        state_path: previous.state_path(),
        previous_state: Some(previous.clone()),
        setup_snapshot: crate::agents::SetupSnapshot::Test,
        setup_result_snapshot: None,
        marketplace_snapshot: None,
        marketplace_result_snapshot: None,
    };
    write_agent_transaction(&journal).unwrap();
    unenroll_agent_locked(
        &fixture.operations,
        CodingAgent::Codex,
        &fixture.uninstall_request(),
    )
    .unwrap();
    journal.stage = "committed".into();
    write_agent_transaction(&journal).unwrap();

    assert!(!fixture.state_path().exists());
    assert!(
        previous
            .install_root
            .join("generations")
            .join(&previous.generation)
            .exists()
    );

    recover_pending_agent_transaction(&fixture.operations).unwrap();

    assert!(!agent_transaction_path().unwrap().exists());
    assert!(!previous.install_root.exists());
}

#[test]
fn batch_retirement_keeps_the_active_generation_and_removes_its_predecessor() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    enroll_agent_with(
        &fixture.operations,
        CodingAgent::Codex,
        &fixture.install_request(false, true),
    )
    .unwrap();
    let previous = fixture.installed_state();
    let mut active = previous.clone();
    active.generation = "batch-active-generation".into();
    active.certificate = certificate::generate(&active.install_root, &active.generation).unwrap();
    active.configuration_fingerprint = "batch-active-fingerprint".into();
    state::write(&active).unwrap();

    finalize_batch_resource_retirements(&[DeferredProxyRetirement {
        state: previous.clone(),
    }])
    .unwrap();

    assert!(
        !previous
            .install_root
            .join("generations")
            .join(previous.generation)
            .exists()
    );
    assert!(
        active
            .install_root
            .join("generations")
            .join(active.generation)
            .exists()
    );
}

#[test]
fn batch_retirement_removes_every_generation_after_final_uninstall() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    enroll_agent_with(
        &fixture.operations,
        CodingAgent::Codex,
        &fixture.install_request(false, true),
    )
    .unwrap();
    let first = fixture.installed_state();
    let mut second = first.clone();
    second.generation = "batch-intermediate-generation".into();
    second.certificate = certificate::generate(&second.install_root, &second.generation).unwrap();
    std::fs::remove_file(first.state_path()).unwrap();

    finalize_batch_resource_retirements(&[
        DeferredProxyRetirement {
            state: first.clone(),
        },
        DeferredProxyRetirement { state: second },
    ])
    .unwrap();

    assert!(!first.install_root.exists());
}

#[test]
fn batch_resource_retirement_guard_is_scoped() {
    assert!(!batch_resource_retirement_deferred());
    {
        let _guard = defer_batch_resource_retirement(|_| Ok(()));
        assert!(batch_resource_retirement_deferred());
    }
    assert!(!batch_resource_retirement_deferred());
}

#[test]
fn interrupted_agent_recovery_stops_when_service_stop_fails() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();
    let previous = fixture.installed_state();
    let journal = AgentTransactionJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "proxy-active".into(),
        agent: CodingAgent::Codex.install_arg().into(),
        install_root: previous.install_root.clone(),
        state_path: previous.state_path(),
        previous_state: Some(previous.clone()),
        setup_snapshot: crate::agents::SetupSnapshot::Test,
        setup_result_snapshot: None,
        marketplace_snapshot: None,
        marketplace_result_snapshot: None,
    };
    write_agent_transaction(&journal).unwrap();
    fixture.operations.fail_once("stop_service");

    let error = recover_pending_agent_transaction(&fixture.operations).unwrap_err();

    assert!(error.contains("stop_service"));
    assert!(agent_transaction_path().unwrap().exists());
    assert_eq!(fixture.installed_state().generation, previous.generation);
}

#[test]
fn explicit_uninstall_root_cannot_remove_a_different_active_enrollment() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Hermes, &request).unwrap();
    let host_removed = Cell::new(false);
    let wrong_root = tempfile::tempdir().unwrap();
    let uninstall = UninstallRequest {
        install_dir: Some(wrong_root.path().to_path_buf()),
        dry_run: false,
    };

    let error = unenroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::Hermes,
        &uninstall,
        Some(&crate::agents::SetupSnapshot::Test),
        || {
            host_removed.set(true);
            Ok::<_, CliError>(())
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("matching --install-dir"), "{error}");
    assert!(!host_removed.get());
    assert!(fixture.state_path().exists());
}

#[test]
fn explicit_doctor_root_cannot_diagnose_a_different_active_enrollment() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Hermes, &request).unwrap();
    let wrong_root = tempfile::tempdir().unwrap();

    let error = diagnose_enrollment_at(CodingAgent::Hermes, Some(wrong_root.path())).unwrap_err();

    assert!(error.contains("rerun doctor with the matching --install-dir"));
    assert!(error.contains(&fixture.state_path().display().to_string()));
}

#[test]
fn doctor_without_an_explicit_root_uses_the_active_locator() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::Hermes, &request).unwrap();

    assert_eq!(
        resolved_marketplace_install_dir(None).unwrap(),
        fixture.marketplace_dir
    );
}

#[test]
fn proxy_unenrollment_failure_restores_the_previous_shared_state() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();
    let state_before = std::fs::read(fixture.state_path()).unwrap();
    fixture.operations.fail_once("register_service");

    let error = unenroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::ClaudeCode,
        &fixture.uninstall_request(),
        Some(&crate::agents::SetupSnapshot::Test),
        || Ok::<_, CliError>(()),
    )
    .unwrap_err();

    assert!(error.to_string().contains("register_service"));
    assert_eq!(std::fs::read(fixture.state_path()).unwrap(), state_before);
    settings::matches(&fixture.installed_state().settings).unwrap();
}

#[test]
fn removing_the_last_claude_surface_removes_the_shared_configuration() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();
    enroll_agent_with(&fixture.operations, CodingAgent::Codex, &request).unwrap();

    unenroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::ClaudeCode,
        &fixture.uninstall_request(),
        Some(&crate::agents::SetupSnapshot::Test),
        || Ok::<_, CliError>(()),
    )
    .unwrap();

    let installed = fixture.installed_state();
    assert!(installed.enrollments.contains_key("codex"));
    assert!(!installed.enrollments.contains_key("claude"));
    assert!(installed.settings.fields.is_empty());
    assert!(!installed.claude_code_installed);
    assert!(!installed.claude_desktop_installed);
}

#[test]
fn code_uninstall_retains_the_desktop_surface_and_shared_configuration() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    let request = fixture.install_request(false, true);
    install_with(&fixture.operations, request.clone()).unwrap();
    enroll_agent_with(&fixture.operations, CodingAgent::ClaudeCode, &request).unwrap();

    unenroll_agent_transactionally_with(
        &fixture.operations,
        CodingAgent::ClaudeCode,
        &fixture.uninstall_request(),
        Some(&crate::agents::SetupSnapshot::Test),
        || Ok::<_, CliError>(()),
    )
    .unwrap();

    let installed = fixture.installed_state();
    assert!(!installed.claude_code_installed);
    assert!(installed.claude_desktop_installed);
    assert!(installed.enrollments.contains_key("claude"));
    assert!(!installed.settings.fields.is_empty());
    settings::matches(&installed.settings).unwrap();
}

#[test]
fn desktop_uninstall_retains_shared_claude_plugin_and_settings() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    installed.claude_code_installed = true;
    state::write(&installed).unwrap();
    let uninstall_calls = fixture.operations.call_count("uninstall_plugin");

    uninstall_with(&fixture.operations, fixture.uninstall_request()).unwrap();

    let retained = fixture.installed_state();
    assert_eq!(
        retained.enrollments.keys().cloned().collect::<Vec<_>>(),
        vec!["claude"]
    );
    assert!(!retained.settings.fields.is_empty());
    assert!(retained.claude_code_installed);
    assert!(!retained.claude_desktop_installed);
    assert_eq!(
        fixture.operations.call_count("uninstall_plugin"),
        uninstall_calls
    );
    assert!(fixture.operations.plugin_present.get());
    settings::matches(&retained.settings).unwrap();
}

#[test]
fn interrupted_install_recovery_removes_the_uncommitted_generation() {
    let fixture = LifecycleFixture::new(platform::Platform::Linux, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let installed = fixture.installed_state();
    fixture.write_journal("install", "proxy_healthy", &installed.generation, None);

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

    let fixture = LifecycleFixture::new(platform::Platform::Windows, false);
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
fn committed_partial_uninstall_recovery_retains_shared_proxy_state() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut before = fixture.installed_state();
    before.enrollments.insert(
        "codex".into(),
        state::AgentEnrollment {
            username: "nemo-relay-codex".into(),
            token: "codex-secret".into(),
            installed_at: "now".into(),
            upstream_proxy: None,
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    let mut active = before.clone();
    active.enrollments.remove("claude");
    active.claude_desktop_installed = false;
    active.settings = Default::default();
    state::write(&active).unwrap();
    fixture.write_journal(
        "uninstall",
        "committed_retained",
        &active.generation,
        Some(before),
    );

    recover_interrupted_operation(
        &fixture.operations,
        &active.install_root,
        &fixture.state_path(),
        platform::Platform::MacOs,
    )
    .unwrap();

    assert!(active.install_root.exists());
    assert_eq!(
        fixture
            .installed_state()
            .enrollments
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["codex"]
    );
    assert!(!state::journal_path(&active.install_root).exists());
}

#[test]
fn interrupted_operation_rejects_platform_and_generation_mismatch() {
    let fixture = LifecycleFixture::new(platform::Platform::MacOs, false);
    install_with(&fixture.operations, fixture.install_request(false, true)).unwrap();
    let mut installed = fixture.installed_state();
    installed.platform = "windows".into();
    installed.service_identity = Some("S-1-5-21-1000".into());
    fixture.write_journal(
        "install",
        "proxy_healthy",
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
    installed.service_identity = None;
    fixture.write_journal(
        "install",
        "proxy_healthy",
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
    std::fs::remove_file(&installed.certificate.ca_key_der).unwrap();
    state::write(&installed).unwrap();
    fixture.write_journal("install", "proxy_healthy", &installed.generation, None);
    std::fs::write(agent_transaction_path().unwrap(), "{}").unwrap();

    let report = doctor_report_with(&fixture.operations, Some(&fixture.marketplace_dir)).unwrap();
    for name in [
        "transaction_journal",
        "shared_transaction_journals",
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
fn doctor_warns_for_near_expiry_and_rejects_tampered_expiry_metadata() {
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
    assert!(!report.ok);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "certificate_files" && !check.ok)
    );
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
    let install_root = fixture.marketplace_dir.join("agent-proxy");
    std::fs::create_dir_all(install_root.join("generations")).unwrap();
    std::fs::write(install_root.join("proxy.stdout.log"), b"known log").unwrap();
    std::fs::write(install_root.join("foreign-file"), b"preserve me").unwrap();

    assert!(remove_fresh_install_root(&install_root).is_err());
    assert!(install_root.join("foreign-file").exists());
    assert!(!install_root.join("proxy.stdout.log").exists());
    assert!(install_root.exists());
}
