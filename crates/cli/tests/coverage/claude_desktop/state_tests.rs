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
        platform: "linux".into(),
        proxy_username: "relay".into(),
        proxy_token: "secret".into(),
        upstream_proxy: None,
        gateway_fingerprint: "gateway".into(),
        configuration_fingerprint: "configuration".into(),
        certificate: CertificateState {
            root_der: certificate_root.join("root-ca.der"),
            root_pem: certificate_root.join("root-ca.pem"),
            leaf_der: certificate_root.join("api.anthropic.com.der"),
            leaf_key_der: certificate_root.join("api.anthropic.com-key.der"),
            root_sha1: "aa".repeat(20),
            root_sha256: "aa".repeat(32),
            root_common_name: "test root".into(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2028-01-01T00:00:00Z".into(),
        },
        settings: SettingsPatch::default(),
        plugin_preexisting: false,
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
        format!("http://relay:secret@{}", super::super::PROXY_BIND)
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
fn state_validation_rejects_invalid_json_schema_and_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("claude-desktop");
    ensure_private_directory(&root).unwrap();
    let path = root.join(STATE_FILE_NAME);

    std::fs::write(&path, b"not json").unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("invalid Claude Desktop state")
    );

    let mut state = test_state(&root);
    state.schema_version += 1;
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("unsupported Claude Desktop state schema")
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
    state.generation = "../outside".into();
    write_private_json(&path, &state).unwrap();
    assert!(read(&path).unwrap_err().contains("invalid generation"));

    state.generation = "generation".into();
    state.certificate.root_der = temp.path().join("foreign.der");
    write_private_json(&path, &state).unwrap();
    assert!(
        read(&path)
            .unwrap_err()
            .contains("differs from installed generation")
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
            .contains("invalid Claude Desktop journal")
    );

    let mut journal = InstallJournal {
        schema_version: STATE_SCHEMA_VERSION + 1,
        operation: "install".into(),
        stage: "prepared".into(),
        generation: "generation".into(),
        old_state: None,
    };
    write_private_json(&path, &journal).unwrap();
    assert!(
        read_journal(&root)
            .unwrap_err()
            .contains("unsupported Claude Desktop journal schema")
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
    let config = temp.path().join("config");
    let _environment =
        crate::test_support::EnvScope::set(&[("XDG_CONFIG_HOME", Some(config.as_os_str()))]);
    let first = temp.path().join("first").join(STATE_FILE_NAME);
    let second = temp.path().join("second").join(STATE_FILE_NAME);

    assert!(write_locator(Path::new("relative/state.json")).is_err());
    write_locator(&first).unwrap();
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
            .join("claude-desktop")
    );

    let explicit = temp.path().join("explicit");
    assert_eq!(
        selected_state_path(Some(&explicit)),
        explicit.join("claude-desktop").join(STATE_FILE_NAME)
    );
    assert_eq!(
        resolve_state_path(Some(&explicit)).unwrap(),
        explicit.join("claude-desktop").join(STATE_FILE_NAME)
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
    assert!(install_root(None).ends_with("claude-desktop"));
}
