// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

#[test]
fn no_proxy_sanitization_removes_anthropic_bypasses_only() {
    assert_eq!(
        sanitize_no_proxy(
            "localhost .anthropic.com,example.com api.anthropic.com:443,.com,api.anthropic.com:80"
        ),
        "localhost,example.com,api.anthropic.com:80"
    );
}

#[test]
fn upstream_proxy_validation_rejects_deferred_schemes() {
    let error = validate_upstream_proxy("socks5://proxy.example:1080", None).unwrap_err();
    assert!(error.contains("HTTP(S)"));
    assert!(validate_upstream_proxy("https://user:pass@proxy.example:8443", None).is_ok());
}

#[test]
fn field_restore_preserves_concurrent_edits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    crate::agents::shared::host::write_json(
        &path,
        &json!({"env": {"HTTPS_PROXY": "http://corporate.example:8080", "OTHER": "kept"}}),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let prepared = prepare_with_process_env(
        &path,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &Map::new(),
    )
    .unwrap();
    assert_eq!(
        prepared
            .upstream_proxy
            .as_ref()
            .map(|proxy| proxy.url.as_str()),
        Some("http://corporate.example:8080/")
    );
    apply(&prepared).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mut edited = crate::agents::shared::host::read_json_object(&path).unwrap();
    edited["env"]["HTTPS_PROXY"] = json!("http://concurrent.example:9090");
    edited["unrelated"] = json!({"preserved": true});
    crate::agents::shared::host::write_json(&path, &edited).unwrap();
    let retained = restore(&prepared.patch).unwrap();

    let restored = crate::agents::shared::host::read_json_object(&path).unwrap();
    assert!(retained.contains(&"HTTPS_PROXY".to_string()));
    assert_eq!(
        restored["env"]["HTTPS_PROXY"],
        json!("http://concurrent.example:9090")
    );
    assert_eq!(restored["env"]["OTHER"], json!("kept"));
    assert_eq!(restored["unrelated"]["preserved"], json!(true));
    assert!(restored["env"].get("NEMO_RELAY_FAIL_CLOSED").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn exact_restore_reinstates_managed_base_url_and_no_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let original = json!({
        "theme": "dark",
        "env": {
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:47632",
            "NO_PROXY": "localhost,.anthropic.com,example.com"
        }
    });
    crate::agents::shared::host::write_json(&path, &original).unwrap();
    let prepared = prepare_with_process_env(
        &path,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "linux",
        None,
        &Map::new(),
    )
    .unwrap();
    assert!(prepared.value["env"].get("ANTHROPIC_BASE_URL").is_none());
    assert_eq!(
        prepared.value["env"]["NO_PROXY"],
        json!("localhost,example.com")
    );
    apply(&prepared).unwrap();
    restore(&prepared.patch).unwrap();
    assert_eq!(
        crate::agents::shared::host::read_json_object(&path).unwrap(),
        original
    );
}

#[test]
fn preparation_rejects_custom_gateway_and_conflicting_proxy_case_variants() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    crate::agents::shared::host::write_json(
        &path,
        &json!({"env": {"ANTHROPIC_BASE_URL": "https://gateway.example"}}),
    )
    .unwrap();
    let error = prepare_with_process_env(
        &path,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &Map::new(),
    )
    .unwrap_err();
    assert!(error.contains("custom Anthropic gateway"));

    let env = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "http://one.example:8080",
        "https_proxy": "http://two.example:8080"
    }))
    .unwrap();
    assert!(unique_case_insensitive_string(&env, "HTTPS_PROXY").is_err());

    let canonical_base_url = serde_json::from_value::<Map<String, Value>>(json!({
        "anthropic_base_url": "https://API.ANTHROPIC.COM:443/"
    }))
    .unwrap();
    prepare_with_process_env(
        &temp.path().join("canonical-settings.json"),
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("canonical-state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &canonical_base_url,
    )
    .unwrap();

    let inherited_base_url = serde_json::from_value::<Map<String, Value>>(json!({
        "anthropic_base_url": "http://127.0.0.1:47632"
    }))
    .unwrap();
    let error = prepare_with_process_env(
        &temp.path().join("empty-settings.json"),
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &inherited_base_url,
    )
    .unwrap_err();
    assert!(error.contains("inherited ANTHROPIC_BASE_URL"));
}

#[test]
fn inherited_case_variant_proxy_and_no_proxy_are_overridden_and_restored() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let process_env = serde_json::from_value::<Map<String, Value>>(json!({
        "https_proxy": "http://corporate.example:8080",
        "no_proxy": "localhost,.anthropic.com,example.com"
    }))
    .unwrap();
    let relay_proxy = "http://nemo-relay:secret@127.0.0.1:47633";
    let prepared = prepare_with_process_env(
        &path,
        relay_proxy,
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &process_env,
    )
    .unwrap();

    assert_eq!(prepared.value["env"]["HTTPS_PROXY"], json!(relay_proxy));
    assert_eq!(prepared.value["env"]["https_proxy"], json!(relay_proxy));
    assert_eq!(
        prepared.value["env"]["NO_PROXY"],
        json!("localhost,example.com")
    );
    assert_eq!(
        prepared.value["env"]["no_proxy"],
        json!("localhost,example.com")
    );
    assert_eq!(
        prepared.value["env"]["CLAUDE_CODE_CERT_STORE"],
        json!("bundled,system")
    );
    assert_eq!(
        prepared
            .upstream_proxy
            .as_ref()
            .map(|proxy| proxy.url.as_str()),
        Some("http://corporate.example:8080/")
    );

    apply(&prepared).unwrap();
    restore(&prepared.patch).unwrap();
    assert!(!path.exists());
}

#[test]
fn macos_upstream_proxy_carries_an_explicit_custom_ca_into_the_sidecar() {
    let temp = tempfile::tempdir().unwrap();
    let settings = temp.path().join("settings.json");
    let custom_ca = temp.path().join("corporate-ca.pem");
    std::fs::write(&custom_ca, "test certificate material").unwrap();
    let process_env = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "https://proxy.example:8443",
        "NODE_EXTRA_CA_CERTS": custom_ca
    }))
    .unwrap();
    let prepared = prepare_with_process_env(
        &settings,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &process_env,
    )
    .unwrap();
    assert_eq!(
        prepared.upstream_proxy.and_then(|proxy| proxy.ca_bundle),
        Some(custom_ca.canonicalize().unwrap())
    );
}

#[test]
fn upstream_proxy_errors_do_not_expose_basic_credentials() {
    let error = validate_upstream_proxy(
        "https://sensitive-user:sensitive-password@proxy.example/path",
        None,
    )
    .unwrap_err();
    assert!(!error.contains("sensitive-user"), "{error}");
    assert!(!error.contains("sensitive-password"), "{error}");
}

#[test]
fn linux_ca_bundle_composes_existing_material_before_relay_root() {
    let temp = tempfile::tempdir().unwrap();
    let existing = temp.path().join("existing.pem");
    std::fs::write(&existing, "EXISTING\n").unwrap();
    let combined = temp.path().join("combined.pem");
    compose_linux_ca_bundle(
        &combined,
        "-----BEGIN CERTIFICATE-----\nRELAY\n-----END CERTIFICATE-----\n",
        existing.to_str(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(combined).unwrap(),
        "EXISTING\n-----BEGIN CERTIFICATE-----\nRELAY\n-----END CERTIFICATE-----\n"
    );
}

#[test]
fn policy_rejects_case_variant_base_url_and_anthropic_no_proxy_bypass() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let prepared = prepare_with_process_env(
        &path,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &Map::new(),
    )
    .unwrap();
    let mut env = prepared.value["env"].as_object().unwrap().clone();
    assert!(validate_environment_policy(&env, &prepared.patch).is_ok());

    env.insert(
        "anthropic_base_url".into(),
        json!("https://api.anthropic.com"),
    );
    assert!(validate_environment_policy(&env, &prepared.patch).is_ok());
    env.insert(
        "anthropic_base_url".into(),
        json!("https://gateway.example"),
    );
    assert!(validate_environment_policy(&env, &prepared.patch).is_err());
    env.remove("anthropic_base_url");
    env.insert("no_proxy".into(), json!(".anthropic.com"));
    assert!(validate_environment_policy(&env, &prepared.patch).is_err());
}

#[test]
fn upstream_proxy_redaction_handles_credentials_and_invalid_urls() {
    let proxy = UpstreamProxy {
        url: "https://sensitive-user:sensitive-password@proxy.example:8443".into(),
        no_proxy: None,
        ca_bundle: None,
    };
    let redacted = proxy.redacted_url();
    assert!(redacted.contains("***"));
    assert!(!redacted.contains("sensitive-user"));
    assert!(!redacted.contains("sensitive-password"));

    let invalid = UpstreamProxy {
        url: "not a URL".into(),
        ..proxy
    };
    assert_eq!(invalid.redacted_url(), "<invalid>");
}

#[test]
fn preparation_rejects_non_string_gateway_unknown_platform_and_automatic_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let relay = "http://nemo-relay:secret@127.0.0.1:47633";
    crate::agents::shared::host::write_json(&path, &json!({"env": {"ANTHROPIC_BASE_URL": 47632}}))
        .unwrap();
    assert!(
        prepare_with_process_env(
            &path,
            relay,
            &temp.path().join("state.json"),
            &temp.path().join("root.pem"),
            "macos",
            None,
            &Map::new(),
        )
        .unwrap_err()
        .contains("must be a string")
    );

    crate::agents::shared::host::write_json(&path, &json!({})).unwrap();
    assert!(
        prepare_with_process_env(
            &path,
            relay,
            &temp.path().join("state.json"),
            &temp.path().join("root.pem"),
            "freebsd",
            None,
            &Map::new(),
        )
        .unwrap_err()
        .contains("unsupported Claude Desktop platform")
    );

    let automatic = serde_json::from_value::<Map<String, Value>>(json!({
        "PROXY_PAC_URL": "https://proxy.example/proxy.pac"
    }))
    .unwrap();
    assert!(
        resolve_upstream_proxy(&Map::new(), &automatic, relay, None)
            .unwrap_err()
            .contains("automatic proxy")
    );
}

#[test]
fn relay_proxy_reuses_the_persisted_upstream_route() {
    let relay = "http://nemo-relay:secret@127.0.0.1:47633";
    let process = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": relay
    }))
    .unwrap();
    let prior = UpstreamProxy {
        url: "http://corporate.example:8080/".into(),
        no_proxy: Some("localhost".into()),
        ca_bundle: None,
    };
    assert_eq!(
        resolve_upstream_proxy(&Map::new(), &process, relay, Some(&prior)).unwrap(),
        Some(prior.clone())
    );

    let settings = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": relay
    }))
    .unwrap();
    let different_process = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "http://different.example:8080"
    }))
    .unwrap();
    assert_eq!(
        resolve_upstream_proxy(&settings, &different_process, relay, Some(&prior)).unwrap(),
        Some(prior)
    );
}

#[test]
fn upstream_proxy_resolution_rejects_ambiguous_layer_and_fallback_conflicts() {
    let relay = "http://nemo-relay:secret@127.0.0.1:47633";
    let settings = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "http://settings-user:settings-password@settings.example:8080"
    }))
    .unwrap();
    let process = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "http://process-user:process-password@process.example:8080"
    }))
    .unwrap();
    let error = resolve_upstream_proxy(&settings, &process, relay, None).unwrap_err();
    assert!(error.contains("conflicting HTTPS_PROXY"), "{error}");
    for secret in [
        "settings-user",
        "settings-password",
        "process-user",
        "process-password",
    ] {
        assert!(!error.contains(secret), "{error}");
    }

    let fallbacks = serde_json::from_value::<Map<String, Value>>(json!({
        "ALL_PROXY": "http://all.example:8080",
        "HTTP_PROXY": "http://http.example:8080"
    }))
    .unwrap();
    assert!(
        resolve_upstream_proxy(&fallbacks, &Map::new(), relay, None)
            .unwrap_err()
            .contains("ALL_PROXY and HTTP_PROXY conflict")
    );

    let settings = serde_json::from_value::<Map<String, Value>>(json!({
        "NO_PROXY": "localhost"
    }))
    .unwrap();
    let process = serde_json::from_value::<Map<String, Value>>(json!({
        "NO_PROXY": "example.com"
    }))
    .unwrap();
    assert!(
        layered_environment_string(&settings, &process, "NO_PROXY")
            .unwrap_err()
            .contains("conflicting NO_PROXY")
    );
}

#[test]
fn explicit_https_proxy_disambiguates_lower_priority_proxy_variables() {
    let relay = "http://nemo-relay:secret@127.0.0.1:47633";
    let process = serde_json::from_value::<Map<String, Value>>(json!({
        "HTTPS_PROXY": "https://https.example:8443",
        "ALL_PROXY": "http://all.example:8080",
        "HTTP_PROXY": "http://http.example:8080"
    }))
    .unwrap();
    let selected = resolve_upstream_proxy(&Map::new(), &process, relay, None)
        .unwrap()
        .unwrap();
    assert_eq!(selected.url, "https://https.example:8443/");

    let matching = serde_json::from_value::<Map<String, Value>>(json!({
        "ALL_PROXY": "http://fallback.example:8080",
        "HTTP_PROXY": "http://fallback.example:8080"
    }))
    .unwrap();
    assert_eq!(
        resolve_upstream_proxy(&Map::new(), &matching, relay, None)
            .unwrap()
            .unwrap()
            .url,
        "http://fallback.example:8080/"
    );
}

#[test]
fn matches_detects_mutation_and_public_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let prepared = prepare_with_process_env(
        &path,
        "http://nemo-relay:secret@127.0.0.1:47633",
        &temp.path().join("state.json"),
        &temp.path().join("root.pem"),
        "macos",
        None,
        &Map::new(),
    )
    .unwrap();
    apply(&prepared).unwrap();
    let mut value = crate::agents::shared::host::read_json_object(&path).unwrap();
    value["env"]["NEMO_RELAY_FAIL_CLOSED"] = json!("0");
    crate::agents::shared::host::write_json(&path, &value).unwrap();
    assert!(matches(&prepared.patch).unwrap_err().contains("mismatched"));

    apply_installed(&prepared.patch).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches(&prepared.patch)
                .unwrap_err()
                .contains("outside the owner")
        );
    }
}

#[test]
fn effective_environment_and_state_marker_match_the_installed_patch() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("settings.json");
    let state = temp.path().join("state.json");
    let proxy = "http://nemo-relay:secret@127.0.0.1:47633";
    let prepared = prepare_with_process_env(
        &path,
        proxy,
        &state,
        &temp.path().join("root.pem"),
        "macos",
        None,
        &Map::new(),
    )
    .unwrap();
    let state_text = state.as_os_str();
    let _environment = crate::test_support::EnvScope::set(&[
        ("HTTPS_PROXY", Some(std::ffi::OsStr::new(proxy))),
        ("NO_PROXY", Some(std::ffi::OsStr::new(""))),
        ("NEMO_RELAY_FAIL_CLOSED", Some(std::ffi::OsStr::new("1"))),
        ("NEMO_RELAY_CLAUDE_DESKTOP_STATE", Some(state_text)),
        (
            "CLAUDE_CODE_CERT_STORE",
            Some(std::ffi::OsStr::new("bundled,system")),
        ),
        ("ANTHROPIC_BASE_URL", None),
        ("NODE_EXTRA_CA_CERTS", None),
    ]);
    assert_eq!(effective_state_path().unwrap(), Some(state));
    effective_environment_matches(&prepared.patch).unwrap();
}

#[test]
fn ca_bundle_resolution_and_normalization_reject_unsafe_inputs() {
    let temp = tempfile::tempdir().unwrap();
    assert!(
        resolve_ca_bundle("relative.pem")
            .unwrap_err()
            .contains("absolute")
    );
    assert!(
        resolve_ca_bundle(temp.path().to_str().unwrap())
            .unwrap_err()
            .contains("regular file")
    );
    assert_eq!(
        normalize_no_proxy(" localhost, example.com  api.internal "),
        "localhost,example.com,api.internal"
    );
    assert_eq!(
        sanitize_no_proxy("api.anthropic.com:not-a-port example.com"),
        "api.anthropic.com:not-a-port,example.com"
    );
}

#[test]
fn malformed_env_shapes_are_rejected_and_empty_env_is_removed() {
    assert!(env_object(&json!({"env": "not-an-object"})).is_err());
    let mut scalar = json!("not-an-object");
    assert!(set_env_object(&mut scalar, Map::new()).is_err());
    let mut object = json!({"env": {"OLD": "value"}, "theme": "dark"});
    set_env_object(&mut object, Map::new()).unwrap();
    assert!(object.get("env").is_none());
    assert_eq!(object["theme"], json!("dark"));
}
