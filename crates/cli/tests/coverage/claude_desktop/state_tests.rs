// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;

use super::*;

fn test_state(root: &Path) -> DesktopState {
    let certificate_root = root.join("generations").join("generation");
    DesktopState {
        schema_version: STATE_SCHEMA_VERSION,
        generation: "generation".into(),
        installed_at: "2026-01-01T00:00:00Z".into(),
        relay_version: "0.7.0".into(),
        relay_binary: root.join("nemo-relay"),
        install_root: root.to_path_buf(),
        user_config_dir: root.join("config"),
        platform: "linux".into(),
        service_identity: None,
        bind: super::super::PROXY_BIND,
        proxy_username: "relay".into(),
        proxy_token: "secret".into(),
        upstream_proxy: None,
        gateway_fingerprint: "gateway".into(),
        max_hook_payload_bytes: crate::configuration::DEFAULT_MAX_HOOK_PAYLOAD_BYTES,
        configuration_fingerprint: "configuration".into(),
        certificate: CertificateState {
            root_der: certificate_root.join("root-ca.der"),
            root_pem: certificate_root.join("root-ca.pem"),
            ca_key_der: certificate_root.join("root-ca-key.der"),
            ca_key_handle: None,
            ca_signer_kind: "file-pkcs8".into(),
            root_sha1: "aa".repeat(20),
            root_sha256: "aa".repeat(32),
            host_set_sha256: super::super::certificate::intercepted_host_set_sha256(),
            root_common_name: "NeMo Relay Agent Proxy generation".into(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2028-01-01T00:00:00Z".into(),
        },
        settings: SettingsPatch::default(),
        claude_code_installed: false,
        claude_desktop_installed: false,
        enrollments: Default::default(),
    }
}

#[test]
fn state_and_journal_round_trip_with_private_storage() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("claude-desktop");
    ensure_private_directory(&root).unwrap();
    let state = test_state(&root);

    assert_eq!(state.state_path(), root.join(STATE_FILE_NAME));
    assert_eq!(
        state.proxy_url(),
        format!("https://relay:secret@{}", super::super::PROXY_BIND)
    );
    write(&state).unwrap();
    let loaded = read(&state.state_path()).unwrap();
    assert_eq!(loaded.generation, state.generation);

    let journal = InstallJournal {
        schema_version: STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "prepared".into(),
        generation: state.generation.clone(),
        old_state: Some(state),
        settings_snapshot: None,
        provider_backup_snapshot: None,
        marketplace_snapshot: None,
        settings_result_snapshot: None,
        provider_backup_result_snapshot: None,
        marketplace_result_snapshot: None,
    };
    write_journal(&root, &journal).unwrap();
    let loaded = read_journal(&root).unwrap();
    assert_eq!(loaded.operation, "install");
    assert_eq!(loaded.stage, "prepared");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join(STATE_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn shared_claude_proxy_url_uses_the_single_claude_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = test_state(temp.path());
    state.enrollments.insert(
        "claude".into(),
        AgentEnrollment {
            username: "code".into(),
            token: "code-token".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            upstream_proxy: None,
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    assert_eq!(
        state.proxy_url(),
        format!("https://code:code-token@{}", state.bind)
    );
}

#[test]
fn state_validation_rejects_invalid_json_schema_and_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("claude-desktop");
    ensure_private_directory(&root).unwrap();
    let path = root.join(STATE_FILE_NAME);

    std::fs::write(&path, b"not json").unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("invalid coding-agent proxy state")
    );

    let mut state = test_state(&root);
    state.schema_version += 1;
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("unsupported coding-agent proxy state schema")
    );

    state.schema_version = STATE_SCHEMA_VERSION;
    state.install_root = temp.path().join("different");
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("differs from selected root")
    );

    state.install_root = root.clone();
    state.user_config_dir = PathBuf::from("relative-config");
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("non-absolute user configuration directory")
    );

    state.user_config_dir = root.join("config");
    state.generation = "../outside".into();
    write_private_json(&path, &state).unwrap();
    assert!(read(&path).unwrap_err().contains("invalid generation"));

    state.generation = "generation".into();
    state.platform = "windows".into();
    write_private_json(&path, &state).unwrap();
    assert!(read(&path).unwrap_err().contains("persisted user SID"));

    state.service_identity = Some("DOMAIN\\User".into());
    write_private_json(&path, &state).unwrap();
    assert!(read(&path).unwrap_err().contains("persisted user SID"));

    state.service_identity = Some("S-1-5-21-1000".into());
    assert!(read_after_write(&path, &state).is_ok());

    state.platform = "linux".into();
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("non-Windows coding-agent proxy state")
    );
    state.service_identity = None;
    state.bind = super::super::LEGACY_PROXY_BIND;
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("invalid loopback listener")
    );

    state.bind = "[::1]:39751".parse().unwrap();
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("invalid loopback listener")
    );

    state.bind = super::super::PROXY_BIND;
    let mut missing_bind = serde_json::to_value(&state).unwrap();
    missing_bind.as_object_mut().unwrap().remove("bind");
    write_private_json(&path, &missing_bind).unwrap();
    let error = read(&path).unwrap_err();
    assert!(error.contains("missing field"));
    assert!(error.contains("bind"));

    state.certificate.root_der = temp.path().join("foreign.der");
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("differs from installed generation")
    );
}

fn read_after_write(path: &Path, state: &DesktopState) -> Result<DesktopState, String> {
    write_private_json(path, state)?;
    read(path)
}

#[cfg(unix)]
#[test]
fn private_directory_validation_rejects_symlinks_foreign_access_and_non_directories() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("private");
    ensure_private_directory(&directory).unwrap();
    validate_private_directory(&directory).unwrap();

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        validate_private_directory(&directory)
            .unwrap_err()
            .contains("must have owner-only mode 700")
    );

    let file = temp.path().join("file");
    std::fs::write(&file, b"not a directory").unwrap();
    assert!(
        validate_private_directory(&file)
            .unwrap_err()
            .contains("not a non-symlinked")
    );

    let symlink = temp.path().join("link");
    std::os::unix::fs::symlink(&directory, &symlink).unwrap();
    assert!(
        validate_private_directory(&symlink)
            .unwrap_err()
            .contains("not a non-symlinked")
    );
}

#[test]
fn journal_validation_rejects_invalid_json_schema_and_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("claude-desktop");
    ensure_private_directory(&root).unwrap();
    let path = journal_path(&root);

    std::fs::write(&path, b"not json").unwrap();
    assert!(
        read_journal(&root)
            .unwrap_err()
            .contains("invalid coding-agent proxy journal")
    );

    let mut journal = InstallJournal {
        schema_version: STATE_SCHEMA_VERSION + 1,
        operation: "install".into(),
        stage: "prepared".into(),
        generation: "generation".into(),
        old_state: None,
        settings_snapshot: None,
        provider_backup_snapshot: None,
        marketplace_snapshot: None,
        settings_result_snapshot: None,
        provider_backup_result_snapshot: None,
        marketplace_result_snapshot: None,
    };
    write_private_json(&path, &journal).unwrap();
    assert!(
        read_journal(&root)
            .unwrap_err()
            .contains("unsupported coding-agent proxy journal schema")
    );

    journal.schema_version = STATE_SCHEMA_VERSION;
    journal.operation = "upgrade".into();
    write_private_json(&path, &journal).unwrap();
    assert!(
        read_journal(&root)
            .unwrap_err()
            .contains("invalid operation metadata")
    );

    journal.operation = "uninstall".into();
    journal.generation.clear();
    write_private_json(&path, &journal).unwrap();
    assert!(
        read_journal(&root)
            .unwrap_err()
            .contains("invalid operation metadata")
    );
}

#[test]
fn locator_round_trip_selects_and_removes_only_the_owned_path() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    std::fs::create_dir_all(&home).unwrap();
    let environment = crate::test_support::EnvScope::set(&[
        ("HOME", Some(home.as_os_str())),
        ("USERPROFILE", Some(home.as_os_str())),
        ("XDG_CONFIG_HOME", Some(config.as_os_str())),
    ]);
    let first = temp.path().join("first").join(STATE_FILE_NAME);
    let second = temp.path().join("second").join(STATE_FILE_NAME);

    assert!(write_locator(Path::new("relative/state.json")).is_err());
    write_locator(&first).unwrap();
    assert_eq!(resolve_state_path(None).unwrap(), first);
    let unrelated_config = temp.path().join("unrelated-config");
    environment.update(&[("XDG_CONFIG_HOME", Some(unrelated_config.as_os_str()))]);
    assert_eq!(resolve_state_path(None).unwrap(), first);
    remove_locator_if_matches(&second).unwrap();
    assert_eq!(resolve_state_path(None).unwrap(), first);
    remove_locator_if_matches(&first).unwrap();
    assert!(!locator_path().unwrap().exists());

    crate::filesystem::atomic_write_private(&locator_path().unwrap(), b"relative\n").unwrap();
    assert!(
        read_locator()
            .unwrap_err()
            .contains("does not contain an absolute path")
    );
    crate::filesystem::atomic_write_private(&locator_path().unwrap(), b"\xff").unwrap();
    assert!(read_locator().unwrap_err().contains("not valid UTF-8"));
}

#[test]
fn active_user_configuration_comes_from_enrollment_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let original_config = temp.path().join("original-config");
    let changed_config = temp.path().join("changed-config");
    let root = temp.path().join("agent-proxy");
    std::fs::create_dir_all(&home).unwrap();
    ensure_private_directory(&root).unwrap();
    let environment = crate::test_support::EnvScope::set(&[
        ("HOME", Some(home.as_os_str())),
        ("USERPROFILE", Some(home.as_os_str())),
        ("XDG_CONFIG_HOME", Some(original_config.as_os_str())),
    ]);
    let mut installed = test_state(&root);
    installed.user_config_dir = original_config.join("nemo-relay");
    write(&installed).unwrap();
    write_locator(&installed.state_path()).unwrap();

    environment.update(&[("XDG_CONFIG_HOME", Some(changed_config.as_os_str()))]);

    assert_eq!(
        active_user_config_dir().unwrap(),
        original_config.join("nemo-relay")
    );
}

#[test]
fn install_paths_are_absolute_and_explicit_selection_ignores_locator() {
    let temp = tempfile::tempdir().unwrap();
    let _cwd = crate::test_support::CwdTestScope::enter(temp.path());
    let relative = install_root(Some(Path::new("relative")));
    assert!(relative.is_absolute());
    assert_eq!(
        relative,
        std::fs::canonicalize(temp.path())
            .unwrap()
            .join("relative")
            .join("agent-proxy")
    );

    let explicit = temp.path().join("explicit");
    assert_eq!(
        selected_state_path(Some(&explicit)),
        explicit.join("agent-proxy").join(STATE_FILE_NAME)
    );
    assert_eq!(
        resolve_state_path(Some(&explicit)).unwrap(),
        explicit.join("agent-proxy").join(STATE_FILE_NAME)
    );
}

#[test]
fn removal_is_idempotent_and_reports_non_file_targets() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("state");
    std::fs::write(&file, b"state").unwrap();
    remove_file_if_present(&file).unwrap();
    remove_file_if_present(&file).unwrap();
    assert!(remove_file_if_present(temp.path()).is_err());
}

#[test]
fn unowned_install_roots_must_be_empty_real_directories() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    ensure_unowned_root_available(&missing).unwrap();

    let empty = temp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    ensure_unowned_root_available(&empty).unwrap();
    ensure_private_directory(&empty).unwrap();

    std::fs::write(empty.join("foreign"), b"foreign").unwrap();
    assert!(
        ensure_unowned_root_available(&empty)
            .unwrap_err()
            .contains("non-empty unowned")
    );
    assert!(ensure_private_directory(&empty.join("foreign")).is_err());

    #[cfg(unix)]
    {
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&empty, &link).unwrap();
        assert!(ensure_unowned_root_available(&link).is_err());
        assert!(ensure_private_directory(&link).is_err());
    }
}

#[test]
fn default_install_root_uses_the_marketplace_parent() {
    let temp = tempfile::tempdir().unwrap();
    let _environment = crate::test_support::EnvScope::set(&[
        ("XDG_CONFIG_HOME", Some(temp.path().as_os_str())),
        ("HOME", Some(OsStr::new("/nonexistent-test-home"))),
    ]);
    assert!(install_root(None).ends_with("agent-proxy"));
}

#[test]
fn legacy_listener_detection_rejects_relay_but_not_a_foreign_service() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config");
    let install = temp.path().join("marketplace");
    let _environment = crate::test_support::EnvScope::set(&[
        ("XDG_CONFIG_HOME", Some(config.as_os_str())),
        ("HOME", Some(temp.path().as_os_str())),
    ]);

    ensure_no_legacy_state_with_health(
        Some(&install),
        crate::gateway::client::RelayHealth::Foreign,
    )
    .unwrap();
    let error = ensure_no_legacy_state_with_health(
        Some(&install),
        crate::gateway::client::RelayHealth::Compatible,
    )
    .unwrap_err();
    assert!(
        error.contains(crate::bootstrap::LEGACY_FIXED_URL),
        "{error}"
    );
    assert!(error.contains("<old-nemo-relay> uninstall all"), "{error}");
}
