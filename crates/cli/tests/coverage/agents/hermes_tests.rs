// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;
use crate::agents::CodingAgent;

fn paths(root: &Path) -> PersistentPaths {
    PersistentPaths::for_config(root.join("config.yaml")).unwrap()
}

fn enrollment(root: &Path) -> crate::claude_desktop::AgentProxyEnrollment {
    let root_ca_pem = root.join("root-ca.pem");
    std::fs::write(
        &root_ca_pem,
        "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    crate::claude_desktop::AgentProxyEnrollment {
        gateway_url: "https://127.0.0.1:41327".into(),
        authorization: "Basic dGVzdDp0ZXN0".into(),
        proxy_url: "https://hermes:secret@127.0.0.1:41327".into(),
        root_ca_pem,
        max_hook_payload_bytes: 1024,
        generation: "generation-a".into(),
        configuration_fingerprint: "configuration-a".into(),
    }
}

#[test]
fn doctor_provider_mode_requires_exact_native_base_url_evidence() {
    assert_eq!(
        configured_observability_mode(
            &json!({
                "model": {"provider": "openai", "base_url": "https://api.openai.com/v1"}
            }),
            true
        ),
        "managed_proxy"
    );
    for config in [
        json!({"model": {"provider": "openai"}}),
        json!({"model": {"provider": "anthropic"}}),
        json!({"model": {"provider": "openai", "base_url": "https://compatible.example/v1"}}),
        json!({"model": {"provider": "openai", "base_url": "http://api.openai.com/v1"}}),
        json!({"model": {"provider": "openai", "base_url": "https://api.openai.com:8443/v1"}}),
        json!({"model": {"provider": "openai", "base_url": "https://user:secret@api.openai.com/v1"}}),
        json!({"model": {"provider": "openai", "base_url": "https://api.openai.com/v1?route=other"}}),
        json!({"model": {"provider": "openai", "base_url": "https://api.openai.com/v1#other"}}),
        json!({"model": {"provider": "openai", "base_url": "https://api.openai.com/arbitrary"}}),
    ] {
        assert_eq!(
            configured_observability_mode(&config, true),
            "hook_only_degraded"
        );
    }
    assert_eq!(
        configured_observability_mode(
            &json!({
                "model": {"provider": "openai", "base_url": "https://api.openai.com/v1"}
            }),
            false,
        ),
        "hook_only_degraded"
    );
}

#[test]
fn user_config_path_uses_hermes_home_or_platform_home() {
    let default_home = Path::new("/users/relay");
    assert_eq!(
        super::super::config::user_config_path_with_override(default_home, None),
        default_home.join(".hermes/config.yaml")
    );
    assert_eq!(
        super::super::config::user_config_path_with_override(
            default_home,
            Some("/tmp/hermes".into())
        ),
        PathBuf::from("/tmp/hermes/config.yaml")
    );
}

#[test]
fn persistent_config_installs_only_hooks_and_preserves_unrelated_state() {
    let relay = Path::new("/opt/nemo-relay");
    let generation = Path::new("/tmp/generation");
    let command = super::super::config::persistent_hook_command_for_platform(
        relay, generation, "token", false,
    );
    let existing = r#"
model:
  provider: custom
mcp_servers:
  unrelated:
    command: other
hooks:
  custom:
    - command: keep-me
"#;

    let patched =
        persistent_config(Some(existing), relay, &command, generation, "token", &[]).unwrap();

    assert_eq!(patched["mcp_servers"]["unrelated"]["command"], "other");
    assert!(patched["mcp_servers"].get("nemo-relay").is_none());
    assert_eq!(patched["hooks"]["custom"][0]["command"], "keep-me");
    for event in CodingAgent::Hermes.hook_events() {
        assert_eq!(
            patched.pointer(&format!("/hooks/{event}/0/command")),
            Some(&json!(command))
        );
    }
}

#[test]
fn persistent_config_cleanup_removes_owned_legacy_mcp_entry() {
    let relay = Path::new("/opt/nemo-relay");
    let generation = Path::new("/tmp/generation");
    let command = super::super::config::persistent_hook_command_for_platform(
        relay, generation, "token", false,
    );
    let existing = serde_yaml::to_string(&json!({
        "mcp_servers": {
            "nemo-relay": {
                "command": relay,
                "args": ["mcp"],
                "env": {
                    "NEMO_RELAY_GATEWAY_BIND": crate::bootstrap::LEGACY_FIXED_BIND,
                    crate::installation::generation::LEGACY_MCP_GENERATION_FILE_ENV: generation,
                    crate::installation::generation::LEGACY_MCP_GENERATION_TOKEN_ENV: "token"
                }
            },
            "unrelated": {"command": "keep"}
        }
    }))
    .unwrap();

    let patched =
        persistent_config(Some(&existing), relay, &command, generation, "token", &[]).unwrap();

    assert!(patched["mcp_servers"].get("nemo-relay").is_none());
    assert_eq!(patched["mcp_servers"]["unrelated"]["command"], "keep");
}

#[test]
fn install_refuses_legacy_mcp_state_without_mutating_it() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    let original = serde_yaml::to_string(&json!({
        "mcp_servers": {
            "nemo-relay": {
                "command": "/opt/nemo-relay",
                "args": ["mcp"]
            }
        }
    }))
    .unwrap();
    std::fs::write(&paths.config, &original).unwrap();
    let enrolled = enrollment(temp.path());

    let error = install_persistent_with_generation(
        paths.clone(),
        Path::new("/opt/nemo-relay"),
        &[],
        None,
        Some(&enrolled),
        None,
        std::time::SystemTime::UNIX_EPOCH,
        crate::filesystem::atomic_write_private,
    )
    .unwrap_err();

    assert!(error.to_string().contains("does not migrate it in place"));
    assert!(
        error
            .to_string()
            .contains(&paths.config.display().to_string())
    );
    assert_eq!(std::fs::read_to_string(paths.config).unwrap(), original);
}

#[test]
fn dotenv_generation_preserves_unrelated_fields_and_records_original_values() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    std::fs::write(
        &paths.env,
        "CUSTOM=keep\nHTTPS_PROXY=http://old-proxy\nNO_PROXY=corp.internal,localhost,api.openai.com\nno_proxy=build.internal,127.0.0.1\n",
    )
    .unwrap();
    let enrollment = enrollment(temp.path());

    let prepared = prepare_proxy_environment(&paths, &enrollment).unwrap();
    assert!(prepared.dotenv.contains("CUSTOM=keep\n"));
    assert!(
        prepared
            .dotenv
            .contains("HTTPS_PROXY=https://hermes:secret@127.0.0.1:41327")
    );
    assert!(
        prepared
            .dotenv
            .contains("NO_PROXY=corp.internal,build.internal")
    );
    assert!(
        prepared
            .dotenv
            .contains("no_proxy=corp.internal,build.internal")
    );
    for name in [
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "AWS_CA_BUNDLE",
    ] {
        assert!(
            prepared
                .dotenv
                .contains(&format!("{name}={}", paths.ca_bundle.to_string_lossy())),
            "{name} must point at the composed Relay and corporate CA bundle"
        );
    }
    let state: ProxyEnvState = serde_json::from_slice(&prepared.state).unwrap();
    assert_eq!(
        state.previous["HTTPS_PROXY"].as_deref(),
        Some("http://old-proxy")
    );
    assert_eq!(
        state.previous["NO_PROXY"].as_deref(),
        Some("corp.internal,localhost,api.openai.com")
    );
    assert_eq!(
        state.previous["no_proxy"].as_deref(),
        Some("build.internal,127.0.0.1")
    );
    assert!(
        String::from_utf8(prepared.ca_bundle)
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
}

#[test]
fn dotenv_rejects_duplicate_managed_fields() {
    let error =
        parse_dotenv_values("HTTPS_PROXY=http://one\nexport HTTPS_PROXY=http://two\nCUSTOM=keep\n")
            .unwrap_err()
            .to_string();
    assert!(error.contains("duplicate managed field HTTPS_PROXY"));
}

#[test]
fn dotenv_restore_removes_generated_values_and_restores_previous_values() {
    let raw = "CUSTOM=keep\nHTTPS_PROXY=http://generated\nNO_PROXY=localhost\n";
    let restored = replace_dotenv_optional_values(
        raw,
        &BTreeMap::from([
            ("HTTPS_PROXY".into(), Some("http://old".into())),
            ("NO_PROXY".into(), None),
        ]),
    )
    .unwrap();
    assert!(restored.contains("CUSTOM=keep\n"));
    assert!(restored.contains("HTTPS_PROXY=http://old\n"));
    assert!(!restored.contains("NO_PROXY="));
}

#[test]
fn dotenv_restore_preserves_post_enrollment_managed_field_edits() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    std::fs::write(
        &paths.env,
        "CUSTOM=keep\nHTTPS_PROXY=http://corporate-old\nNO_PROXY=corp.old\n",
    )
    .unwrap();
    let enrollment = enrollment(temp.path());
    let prepared = prepare_proxy_environment(&paths, &enrollment).unwrap();
    std::fs::write(&paths.env_state, prepared.state).unwrap();
    std::fs::write(
        &paths.env,
        prepared
            .dotenv
            .replace("NO_PROXY=corp.old", "NO_PROXY=corp.new"),
    )
    .unwrap();

    let restored = restored_proxy_environment(&paths)
        .unwrap()
        .flatten()
        .unwrap();

    assert!(restored.contains("CUSTOM=keep\n"));
    assert!(restored.contains("HTTPS_PROXY=http://corporate-old\n"));
    assert!(restored.contains("NO_PROXY=corp.new\n"));
    assert!(!restored.contains(&enrollment.proxy_url));
}

#[test]
fn uninstall_aborts_and_rolls_back_around_a_concurrent_dotenv_writer() {
    let temp = tempfile::tempdir().unwrap();
    let _environment = crate::test_support::EnvScope::set(
        &PROXY_ENV_NAMES
            .iter()
            .map(|name| (*name, None))
            .collect::<Vec<_>>(),
    );
    let paths = paths(temp.path());
    std::fs::write(&paths.env, "CUSTOM=before\n").unwrap();
    let enrolled = enrollment(temp.path());
    install_persistent_with_generation(
        paths.clone(),
        Path::new("/opt/nemo-relay"),
        &[],
        None,
        Some(&enrolled),
        None,
        std::time::SystemTime::UNIX_EPOCH,
        crate::filesystem::atomic_write_private,
    )
    .unwrap();
    let installed_config = std::fs::read(&paths.config).unwrap();
    let installed_generation = std::fs::read(&paths.generation).unwrap();

    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let completed = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_path = paths.env.clone();
    let writer_release = release.clone();
    let writer_completed = completed.clone();
    let writer = std::thread::spawn(move || {
        writer_release.wait();
        let mut raw = std::fs::read_to_string(&writer_path).unwrap();
        raw.push_str("EXTERNAL_DURING_UNINSTALL=preserve\n");
        std::fs::write(&writer_path, raw).unwrap();
        writer_completed.wait();
    });
    let error = uninstall_persistent_with_hook(
        paths.clone(),
        crate::filesystem::atomic_write_private,
        || {
            release.wait();
            completed.wait();
        },
    )
    .unwrap_err();
    writer.join().unwrap();

    assert!(
        error
            .to_string()
            .contains("changed while Relay was preparing")
    );
    assert!(
        std::fs::read_to_string(&paths.env)
            .unwrap()
            .contains("EXTERNAL_DURING_UNINSTALL=preserve")
    );
    assert_eq!(std::fs::read(&paths.config).unwrap(), installed_config);
    assert_eq!(
        std::fs::read(&paths.generation).unwrap(),
        installed_generation
    );
}

#[test]
fn proxy_environment_verification_detects_stale_dotenv() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    let enrollment = enrollment(temp.path());
    let prepared = prepare_proxy_environment(&paths, &enrollment).unwrap();
    std::fs::write(&paths.env_state, prepared.state).unwrap();
    std::fs::write(&paths.ca_bundle, prepared.ca_bundle).unwrap();
    std::fs::write(&paths.env, prepared.dotenv.replace("secret", "stale")).unwrap();

    let error = verify_proxy_environment(&paths, &enrollment).unwrap_err();
    assert!(error.contains("differs from enrolled proxy state"));
}

#[test]
fn enrollment_inputs_are_captured_from_the_durable_hermes_dotenv() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    std::fs::write(
        &paths.env,
        "HTTPS_PROXY=https://corporate.example:8443\nNO_PROXY=corp.internal\nREQUESTS_CA_BUNDLE=/etc/corporate-ca.pem\n",
    )
    .unwrap();

    let environment = proxy_environment(&paths.config).unwrap();

    assert_eq!(
        environment["HTTPS_PROXY"],
        json!("https://corporate.example:8443")
    );
    assert_eq!(environment["NO_PROXY"], json!("corp.internal"));
    assert_eq!(
        environment["REQUESTS_CA_BUNDLE"],
        json!("/etc/corporate-ca.pem")
    );
}

#[test]
fn proxy_environment_refresh_updates_the_ca_and_preserves_original_values() {
    let temp = tempfile::tempdir().unwrap();
    let _environment = crate::test_support::EnvScope::set(
        &PROXY_ENV_NAMES
            .iter()
            .map(|name| (*name, None))
            .collect::<Vec<_>>(),
    );
    let paths = paths(temp.path());
    std::fs::write(
        &paths.env,
        "CUSTOM=keep\nHTTPS_PROXY=http://corporate-proxy\n",
    )
    .unwrap();
    let initial = enrollment(temp.path());
    refresh_proxy_environment(&paths.config, &initial).unwrap();

    let replacement_root = temp.path().join("replacement-root.pem");
    std::fs::write(
        &replacement_root,
        "-----BEGIN CERTIFICATE-----\nreplacement\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let replacement = crate::claude_desktop::AgentProxyEnrollment {
        proxy_url: "http://hermes:new-secret@127.0.0.1:49991".into(),
        root_ca_pem: replacement_root,
        ..initial
    };
    refresh_proxy_environment(&paths.config, &replacement).unwrap();

    let state: ProxyEnvState =
        serde_json::from_str(&std::fs::read_to_string(&paths.env_state).unwrap()).unwrap();
    assert_eq!(
        state.previous["HTTPS_PROXY"].as_deref(),
        Some("http://corporate-proxy")
    );
    assert_eq!(
        state.generated["HTTPS_PROXY"],
        "http://hermes:new-secret@127.0.0.1:49991"
    );
    assert!(
        std::fs::read_to_string(&paths.env)
            .unwrap()
            .contains("CUSTOM=keep\n")
    );
    assert!(
        std::fs::read(&paths.ca_bundle)
            .unwrap()
            .ends_with(&std::fs::read(&replacement.root_ca_pem).unwrap())
    );
}

#[test]
fn proxy_environment_rotation_retains_original_ca_sources() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    let corporate_bundle = temp.path().join("corporate-bundle.pem");
    let node_extra = temp.path().join("node-extra.pem");
    std::fs::write(&corporate_bundle, b"CORPORATE-ROOT\n").unwrap();
    std::fs::write(&node_extra, b"NODE-EXTRA-ROOT\n").unwrap();
    std::fs::write(
        &paths.env,
        format!(
            "REQUESTS_CA_BUNDLE={}\nNODE_EXTRA_CA_CERTS={}\n",
            corporate_bundle.display(),
            node_extra.display()
        ),
    )
    .unwrap();

    let initial = enrollment(temp.path());
    refresh_proxy_environment(&paths.config, &initial).unwrap();
    let initial_bundle = std::fs::read(&paths.ca_bundle).unwrap();
    assert!(
        initial_bundle
            .windows(b"CORPORATE-ROOT".len())
            .any(|window| window == b"CORPORATE-ROOT")
    );
    assert!(
        initial_bundle
            .windows(b"NODE-EXTRA-ROOT".len())
            .any(|window| window == b"NODE-EXTRA-ROOT")
    );

    let replacement_root = temp.path().join("replacement-root.pem");
    std::fs::write(
        &replacement_root,
        "-----BEGIN CERTIFICATE-----\nreplacement\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let replacement = crate::claude_desktop::AgentProxyEnrollment {
        root_ca_pem: replacement_root,
        generation: "generation-b".into(),
        ..initial
    };
    refresh_proxy_environment(&paths.config, &replacement).unwrap();

    let rotated_bundle = std::fs::read(&paths.ca_bundle).unwrap();
    for marker in [
        b"CORPORATE-ROOT".as_slice(),
        b"NODE-EXTRA-ROOT".as_slice(),
        b"replacement".as_slice(),
    ] {
        assert!(
            rotated_bundle
                .windows(marker.len())
                .any(|window| window == marker),
            "missing retained CA marker {}",
            String::from_utf8_lossy(marker)
        );
    }
}

#[test]
fn proxy_environment_verification_rejects_a_stale_ca_bundle() {
    let temp = tempfile::tempdir().unwrap();
    let _environment = crate::test_support::EnvScope::set(
        &PROXY_ENV_NAMES
            .iter()
            .map(|name| (*name, None))
            .collect::<Vec<_>>(),
    );
    let paths = paths(temp.path());
    let enrollment = enrollment(temp.path());
    let prepared = prepare_proxy_environment(&paths, &enrollment).unwrap();
    std::fs::write(&paths.env_state, prepared.state).unwrap();
    std::fs::write(&paths.env, prepared.dotenv).unwrap();
    std::fs::write(&paths.ca_bundle, b"stale CA").unwrap();

    let error = verify_proxy_environment(&paths, &enrollment).unwrap_err();
    assert!(error.contains("does not contain the enrolled proxy CA"));
}

#[test]
fn persistent_paths_include_proxy_environment_ownership_files() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths(temp.path());
    assert_eq!(paths.all().len(), 6);
    assert!(paths.all().contains(&paths.env));
    assert!(paths.all().contains(&paths.env_state));
    assert!(paths.all().contains(&paths.ca_bundle));
}
