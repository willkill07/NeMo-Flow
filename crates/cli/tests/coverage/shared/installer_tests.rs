// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use base64::Engine;
use std::path::Path;

use reqwest::header::HeaderMap;
use serde_json::Value;

use crate::agents::CodingAgent;

#[test]
fn hook_payload_reader_normalizes_blank_input_and_accepts_the_exact_limit() {
    assert_eq!(read_hook_payload_from(" \n\t".as_bytes(), 3).unwrap(), "{}");
    assert_eq!(
        read_hook_payload_from("1234".as_bytes(), 4).unwrap(),
        "1234"
    );
}

#[test]
fn hook_payload_reader_rejects_oversized_invalid_and_unreadable_input() {
    let oversized = read_hook_payload_from("12345".as_bytes(), 4)
        .unwrap_err()
        .to_string();
    assert!(oversized.contains("exceeds the 4-byte limit"));

    let invalid = read_hook_payload_from([0xff].as_slice(), 1)
        .unwrap_err()
        .to_string();
    assert!(invalid.contains("not valid UTF-8"));

    struct FailingReader;
    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic hook input failure"))
        }
    }
    assert!(
        read_hook_payload_from(FailingReader, 4)
            .unwrap_err()
            .to_string()
            .contains("synthetic hook input failure")
    );
}

#[test]
fn hook_payload_reader_has_an_end_to_end_deadline() {
    struct SlowReader;
    impl std::io::Read for SlowReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(0)
        }
    }

    let error = read_hook_payload_with_timeout(SlowReader, 4, std::time::Duration::from_millis(10))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not closed"), "{error}");
}

#[test]
fn hook_response_statuses_preserve_guardrail_rejections_and_fail_closed_errors() {
    let rejection = handle_hook_forward_status(
        reqwest::StatusCode::FORBIDDEN,
        r#"{"error":{"type":"nemo_relay_guardrail_rejected","reason":"policy denied"}}"#.into(),
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(rejection.contains("policy denied"), "{rejection}");

    let fallback = handle_hook_forward_status(
        reqwest::StatusCode::BAD_REQUEST,
        r#"{"error":{"type":"nemo_relay_guardrail_rejected","message":"fallback"}}"#.into(),
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(fallback.contains("fallback"), "{fallback}");

    let error = handle_hook_forward_status(
        reqwest::StatusCode::BAD_GATEWAY,
        "not a guardrail response".into(),
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("HTTP 502"), "{error}");
}

#[test]
fn windows_hook_decoder_rejects_unsafe_odd_and_trailing_argument_envelopes() {
    const SEPARATOR: &str = " -NoLogo -NoProfile -NonInteractive -EncodedCommand ";
    #[cfg(windows)]
    let launcher = windows_powershell_path().unwrap();
    #[cfg(not(windows))]
    let launcher = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe".to_string();

    assert!(decode_windows_hook_command(&format!("powershell.exe{SEPARATOR}QQ==")).is_none());
    assert!(decode_windows_hook_command(&format!("{launcher}{SEPARATOR}QQ==")).is_none());

    let script = "$ErrorActionPreference='Stop'; & 'relay' ; if ($null -eq $LASTEXITCODE) { exit 1 }; exit $LASTEXITCODE";
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    assert!(decode_windows_hook_command(&format!("{launcher}{SEPARATOR}{encoded}")).is_none());
}

#[test]
fn merge_hooks_is_idempotent_and_preserves_existing_entries() {
    let existing = json!({
        "hooks": {
            "Stop": [{ "hooks": [{ "type": "command", "command": "existing" }] }]
        }
    });
    let generated = generated_hooks(CodingAgent::ClaudeCode, "nemo-relay hook-forward claude");
    let once = merge_hooks(existing, generated.clone()).unwrap();
    let twice = merge_hooks(once.clone(), generated).unwrap();
    assert_eq!(once, twice);
    assert_eq!(twice["hooks"]["Stop"].as_array().unwrap().len(), 2);
    assert_eq!(
        twice["hooks"]["UserPromptExpansion"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn merge_hooks_rejects_malformed_shapes() {
    let generated = generated_hooks(CodingAgent::Codex, "cmd");
    assert!(merge_hooks(json!([]), generated.clone()).is_err());
    assert!(merge_hooks(json!({ "hooks": [] }), generated.clone()).is_err());
    assert!(merge_hooks(json!({ "hooks": { "Stop": {} } }), generated).is_err());
    assert!(merge_hooks(json!({}), json!({ "hooks": [] })).is_err());
}

#[test]
fn helper_formatting_and_headers_cover_optional_paths() {
    assert!(event_matches_tools("PermissionRequest"));
    assert!(!event_matches_tools("SessionStart"));

    let headers = gateway_headers(
        Some("profile"),
        Some(r#"{"team":"obs"}"#),
        Some(GatewayMode::Passthrough),
    )
    .unwrap();
    assert_eq!(
        headers
            .get("x-nemo-relay-gateway-mode")
            .and_then(|value| value.to_str().ok()),
        Some("passthrough")
    );
    assert!(
        insert_header(
            &mut HeaderMap::new(),
            "x-nemo-relay-config-profile",
            Some("bad\nvalue")
        )
        .is_err()
    );

    let headers = gateway_headers(None, None, None).unwrap();
    assert!(headers.is_empty());
}

#[test]
fn generated_hook_dispatch_covers_all_agents() {
    for agent in [
        CodingAgent::ClaudeCode,
        CodingAgent::Codex,
        CodingAgent::Hermes,
    ] {
        assert!(generated_hooks(agent, "cmd")["hooks"].is_object());
    }
    let relay = Path::new("/opt/NeMo Relay's & tools/nemo-relay");
    let generation = Path::new("/opt/NeMo Relay's & tools/.nemo-relay-generation");
    let posix = persistent_hook_forward_command_for_platform(
        relay,
        CodingAgent::Codex,
        generation,
        "test-generation",
        false,
    );
    assert!(posix.contains("hook-forward codex"));
    assert!(posix.contains("--generation-file"));
    assert!(posix.contains("--generation-token test-generation"));
    assert!(posix.ends_with("--fail-closed"));

    let windows = persistent_hook_forward_command_for_platform(
        relay,
        CodingAgent::ClaudeCode,
        generation,
        "test-generation",
        true,
    );
    let (launcher, encoded) = windows.rsplit_once(' ').unwrap();
    assert_eq!(
        launcher,
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand"
    );
    assert!(
        !encoded.is_empty()
            && encoded
                .chars()
                .all(|character| character.is_ascii_alphanumeric()
                    || matches!(character, '+' | '/' | '='))
    );
    assert_eq!(
        decode_windows_hook_command(&windows).unwrap(),
        vec![
            relay.display().to_string(),
            "hook-forward".into(),
            "claude".into(),
            "--gateway-url".into(),
            crate::bootstrap::LEGACY_FIXED_URL.into(),
            "--generation-file".into(),
            generation.display().to_string(),
            "--generation-token".into(),
            "test-generation".into(),
            "--fail-closed".into(),
        ]
    );
    assert!(decode_windows_hook_command("powershell.exe -EncodedCommand invalid").is_none());
    assert!(
        decode_windows_hook_command(
            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand invalid payload"
        )
        .is_none()
    );
    let oversized = format!(
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {}",
        "A".repeat(8_000)
    );
    assert!(decode_windows_hook_command(&oversized).is_none());

    let oversized_path = format!("C:/{}nemo-relay.exe", "long/".repeat(2_000));
    let error = encoded_windows_hook_command(
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        Path::new(&oversized_path),
        &["hook-forward".into(), "codex".into()],
    )
    .unwrap_err();
    assert!(error.contains("exceeds the 8000-character safety limit"));
    assert!(error.contains("shorten the Relay or plugin installation path"));
}

#[test]
fn codex_generation_uses_exactly_the_supported_hook_schema() {
    let generated = generated_hooks(CodingAgent::Codex, "cmd");
    let events = generated["hooks"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        events,
        std::collections::BTreeSet::from([
            "PermissionRequest",
            "PostCompact",
            "PostToolUse",
            "PreCompact",
            "PreToolUse",
            "SessionStart",
            "Stop",
            "SubagentStart",
            "SubagentStop",
            "UserPromptSubmit",
        ])
    );
    for unsupported in ["PostToolUseFailure", "Notification", "SessionEnd"] {
        assert!(generated["hooks"].get(unsupported).is_none());
    }
}

#[test]
fn packaged_hook_configs_are_valid_json() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/coding-agents");
    for path in [
        root.join("claude-code/.claude-plugin/plugin.json"),
        root.join("codex/.codex-plugin/plugin.json"),
    ] {
        let raw = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str::<Value>(&raw)
            .unwrap_or_else(|error| panic!("{} is invalid JSON: {error}", path.display()));
    }
}

#[test]
fn source_plugins_do_not_publish_unfenced_hook_commands() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/coding-agents");
    for host in ["claude-code", "codex"] {
        assert!(
            !root.join(host).join("hooks").join("hooks.json").exists(),
            "{host} source assets must not publish a hook command without an installer-owned generation fence"
        );
    }
}

#[test]
fn packaged_plugin_manifests_use_stable_plugin_name_and_version() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/coding-agents");
    let claude_path = root.join("claude-code/.claude-plugin/plugin.json");
    let claude =
        serde_json::from_str::<Value>(&std::fs::read_to_string(&claude_path).unwrap()).unwrap();
    assert_eq!(claude["name"], json!("nemo-relay-plugin"));
    assert_eq!(claude["version"], json!(env!("CARGO_PKG_VERSION")));
    assert!(claude.get("hooks").is_none());
    assert!(claude.get("mcpServers").is_none());

    let codex_path = root.join("codex/.codex-plugin/plugin.json");
    let codex =
        serde_json::from_str::<Value>(&std::fs::read_to_string(&codex_path).unwrap()).unwrap();
    assert_eq!(codex["name"], json!("nemo-relay-plugin"));
    assert_eq!(codex["version"], json!(env!("CARGO_PKG_VERSION")));
    assert!(codex.get("hooks").is_none());
    assert!(codex.get("mcpServers").is_none());

    for path in [
        root.join("../../.agents/plugins/marketplace.json"),
        root.join("../../.claude-plugin/marketplace.json"),
    ] {
        assert!(
            !path.exists(),
            "repository source marketplace {} must not advertise a plugin without an installer-owned generation fence",
            path.display()
        );
    }
}

#[test]
fn packaged_plugin_helpers_are_present() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/coding-agents");
    for path in [
        root.join("claude-code/.claude-plugin/plugin.json"),
        root.join("codex/.codex-plugin/plugin.json"),
    ] {
        let metadata = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{} missing: {error}", path.display()));
        assert!(metadata.is_file(), "{} is not a file", path.display());
    }
}
