// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI-level gateway coverage tests.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

fn gateway_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nemo-relay")
}

const ACTIVE_GENERATION_TOKEN: &str = "active-generation";

fn write_active_generation(temp: &std::path::Path) -> std::path::PathBuf {
    let generation = temp.join("plugin/.nemo-relay-generation");
    std::fs::create_dir_all(generation.parent().unwrap()).unwrap();
    std::fs::write(&generation, format!("{ACTIVE_GENERATION_TOKEN}\n")).unwrap();
    generation
}

fn toml_basic_string(value: &str) -> String {
    let escaped = value
        .chars()
        .map(|character| match character {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            '\n' => "\\n".to_string(),
            '\t' => "\\t".to_string(),
            '\r' => "\\r".to_string(),
            '\u{08}' => "\\b".to_string(),
            '\u{0c}' => "\\f".to_string(),
            '\u{00}'..='\u{1f}' | '\u{7f}' => {
                format!("\\u{:04X}", character as u32)
            }
            character => character.to_string(),
        })
        .collect::<String>();
    format!("\"{escaped}\"")
}

fn write_jsonl_logging_config(temp: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let config_path = temp.join("logging.toml");
    let log_path = temp.join("operational.jsonl");
    std::fs::write(
        &config_path,
        format!(
            r#"[logging]
level = "info"
stderr_format = "jsonl"

[[logging.sinks]]
path = {}
level = "info"
format = "jsonl"
queue_capacity = 64
"#,
            toml_basic_string(log_path.to_string_lossy().as_ref())
        ),
    )
    .unwrap();
    (config_path, log_path)
}

fn read_jsonl_records(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn write_dynamic_plugin_manifest(dir: &std::path::Path, plugin_id: &str) {
    write_dynamic_plugin_manifest_with_options(dir, plugin_id, &["plugin_worker"], None);
}

fn write_dynamic_plugin_manifest_with_options(
    dir: &std::path::Path,
    plugin_id: &str,
    capabilities: &[&str],
    signature_ref: Option<&str>,
) {
    std::fs::create_dir_all(dir).unwrap();
    let artifact_body = format!("def register():\n    return {plugin_id:?}\n");
    std::fs::write(dir.join("plugin.py"), &artifact_body).unwrap();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(artifact_body.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let capabilities = capabilities
        .iter()
        .map(|capability| toml_basic_string(capability))
        .collect::<Vec<_>>()
        .join(", ");
    let signature_line = signature_ref
        .map(|signature_ref| format!("signature = {}\n", toml_basic_string(signature_ref)))
        .unwrap_or_default();
    std::fs::write(
        dir.join("relay-plugin.toml"),
        format!(
            r#"manifest_version = 1

[plugin]
id = {plugin_id}
kind = "worker"

[compat]
relay = "0.5"
worker_protocol = "grpc-v1"

[defaults]
enabled = false

[capabilities]
items = [{capabilities}]

[source]
artifact = "plugin.py"

[integrity]
sha256 = {digest}
{signature_line}

[load]
runtime = "command"
entrypoint = "plugin.py"
"#,
            capabilities = capabilities,
            signature_line = signature_line,
            digest = toml_basic_string(&digest),
            plugin_id = toml_basic_string(plugin_id),
        ),
    )
    .unwrap();
}

fn write_python_dynamic_plugin_manifest(dir: &std::path::Path, plugin_id: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let artifact_body = "def main():\n    return None\n";
    std::fs::write(dir.join("plugin.py"), artifact_body).unwrap();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(artifact_body.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    std::fs::write(
        dir.join("relay-plugin.toml"),
        format!(
            r#"manifest_version = 1

[plugin]
id = {plugin_id}
kind = "worker"

[compat]
relay = "0.5"
worker_protocol = "grpc-v1"

[defaults]
enabled = false

[capabilities]
items = ["plugin_worker"]

[source]
manifest_root = "."
artifact = "plugin.py"

[integrity]
sha256 = {digest}

[load]
runtime = "python"
entrypoint = "plugin:main"
"#,
            plugin_id = toml_basic_string(plugin_id),
            digest = toml_basic_string(&digest),
        ),
    )
    .unwrap();
}

fn write_detached_ed25519_signature(dir: &std::path::Path, signature_name: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let artifact = std::fs::read(dir.join("plugin.py")).unwrap();
    let pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate ed25519 keypair");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse ed25519 keypair");
    let signature = key_pair.sign(&artifact);
    let signature_text = format!(
        "ed25519:{}\n",
        base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
    );
    std::fs::write(dir.join(signature_name), signature_text).unwrap();
    format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref())
    )
}

fn generate_ed25519_public_key() -> String {
    let pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate ed25519 keypair");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse ed25519 keypair");
    format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref())
    )
}

#[test]
fn toml_basic_string_escapes_toml_control_characters() {
    assert_eq!(
        toml_basic_string("a\\b\"c\nd\te\rf\u{08}g\u{0c}h\u{01}\u{7f}"),
        "\"a\\\\b\\\"c\\nd\\te\\rf\\bg\\fh\\u0001\\u007F\""
    );
}

#[test]
fn cli_help_exits_successfully() {
    let output = Command::new(gateway_bin()).arg("--help").output().unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Unified local coding-agent proxy"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("plugin-config"));
}

#[test]
fn cli_version_exits_successfully() {
    let output = Command::new(gateway_bin())
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("nemo-relay "));
}

#[test]
fn cli_jsonl_logging_records_successful_command_lifecycle_without_leaking_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let (config_path, log_path) = write_jsonl_logging_config(temp.path());
    let secret = "NEMO_RELAY_SECRET_SENTINEL_7a91";
    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .env("NEMO_RELAY_TEST_SECRET", secret)
        .args(["--log-config-path"])
        .arg(&config_path)
        .args(["agents", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(!contents.contains(secret));
    let records = read_jsonl_records(&log_path);
    for event in [
        "logging_initialized",
        "command_started",
        "diagnostics_completed",
        "command_completed",
        "logging_shutdown_started",
    ] {
        assert!(
            records.iter().any(|record| record["event"] == event),
            "missing {event}: {records:?}"
        );
    }
    let positions = [
        "logging_initialized",
        "command_started",
        "diagnostics_completed",
        "command_completed",
        "logging_shutdown_started",
    ]
    .map(|event| {
        records
            .iter()
            .position(|record| record["event"] == event)
            .expect("lifecycle event was asserted above")
    });
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "unexpected successful command lifecycle order: {records:?}"
    );
    assert!(
        records
            .iter()
            .all(|record| { record["level"] != "debug" && record["level"] != "trace" })
    );
}

#[test]
fn cli_logs_final_failure_before_shutdown_and_preserves_user_error() {
    let temp = tempfile::tempdir().unwrap();
    let (config_path, log_path) = write_jsonl_logging_config(temp.path());
    let secret = "NEMO_RELAY_ARGV_SECRET_SENTINEL_2c48";
    let catalog = temp.path().join(format!("{secret}.json"));
    std::fs::write(&catalog, format!(r#"{{"secret":"{secret}"}}"#)).unwrap();
    let output = Command::new(gateway_bin())
        .args(["--log-config-path"])
        .arg(&config_path)
        .args(["model-pricing", "validate"])
        .arg(&catalog)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid model pricing catalog"));
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(!contents.contains(secret));
    let records = read_jsonl_records(&log_path);
    let failed = records
        .iter()
        .position(|record| record["event"] == "command_failed")
        .expect("command_failed record");
    let shutdown = records
        .iter()
        .position(|record| record["event"] == "logging_shutdown_started")
        .expect("logging_shutdown_started record");
    assert!(failed < shutdown);
    assert_eq!(records[failed]["target"], "nemo_relay.cli");
    assert_eq!(records[failed]["level"], "error");
    assert_eq!(records[failed]["fields"]["command"], "model_pricing");
}

#[test]
fn ordinary_cli_launch_does_not_hide_invalid_environment_values() {
    let output = Command::new(gateway_bin())
        .env_remove("NEMO_RELAY_MCP_GENERATION_FILE")
        .env_remove("NEMO_RELAY_MCP_GENERATION")
        .env(
            "NEMO_RELAY_MAX_HOOK_PAYLOAD_BYTES",
            "${NEMO_RELAY_MAX_HOOK_PAYLOAD_BYTES}",
        )
        .args(["agents", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid digit found in string"));
}

#[test]
fn cli_config_help_describes_user_and_system_policy_scopes() {
    let output = Command::new(gateway_bin())
        .args(["config", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("persistent Relay policy"));
    assert!(stdout.contains("--system"));
    assert!(!stdout.contains("Hermes-scoped reset"));
}

#[derive(Clone, Copy)]
enum FakeBootstrapProof {
    Missing,
    Wrong,
}

fn run_fake_bootstrap_listener(proof: FakeBootstrapProof) -> (Output, Vec<String>) {
    let temp = tempfile::tempdir().unwrap();
    let generation = write_active_generation(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stopped = stopped.clone();
    let server_requests = requests.clone();
    let server = thread::spawn(move || {
        while !server_stopped.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("fake bootstrap listener failed: {error}"),
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = read_http_request(&mut stream);
            server_requests.lock().unwrap().push(request.clone());
            if request.starts_with("GET /healthz ") {
                write_fake_bootstrap_health(&mut stream, proof);
            } else {
                write_fake_hook_response(&mut stream);
            }
        }
    });

    let mut command = Command::new(gateway_bin());
    command.args([
        "hook-forward",
        "codex",
        "--gateway-url",
        &format!("http://{address}"),
    ]);
    command
        .arg("--generation-file")
        .arg(&generation)
        .arg("--generation-token")
        .arg(ACTIVE_GENERATION_TOKEN);
    let mut child = command
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("XDG_RUNTIME_DIR", temp.path().join("runtime"))
        .env("TMPDIR", temp.path())
        .env("NEMO_RELAY_FAIL_CLOSED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"session_id\":\"challenge\",\"hook_event_name\":\"SessionStart\"}")
        .unwrap();
    let output = wait_child_with_output(child);
    stopped.store(true, Ordering::Relaxed);
    server.join().unwrap();
    let requests = Arc::try_unwrap(requests).unwrap().into_inner().unwrap();
    (output, requests)
}

fn fake_bootstrap_proof_header(proof: FakeBootstrapProof) -> String {
    match proof {
        FakeBootstrapProof::Missing => String::new(),
        FakeBootstrapProof::Wrong => {
            "X-NeMo-Relay-Bootstrap-Proof: hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000\r\n".into()
        }
    }
}

fn write_fake_bootstrap_health(stream: &mut std::net::TcpStream, proof: FakeBootstrapProof) {
    let proof_header = fake_bootstrap_proof_header(proof);
    let body = format!(
        r#"{{"status":"ok","service":"nemo-relay","version":"{}","bootstrap_protocol":2,"instance_id":"test-instance"}}"#,
        env!("CARGO_PKG_VERSION")
    );
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\n{proof_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
}

fn write_fake_hook_response(stream: &mut impl Write) {
    let body = r#"{"continue":true}"#;
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

#[test]
fn cli_codex_hook_rejects_compatible_json_without_bootstrap_proof() {
    let (output, requests) = run_fake_bootstrap_listener(FakeBootstrapProof::Missing);
    assert!(!output.status.success());
    assert!(requests.iter().all(|request| !request.starts_with("POST ")));
}

#[test]
fn cli_codex_hook_rejects_an_invalid_bootstrap_proof() {
    let (output, requests) = run_fake_bootstrap_listener(FakeBootstrapProof::Wrong);
    assert!(!output.status.success());
    assert!(requests.iter().all(|request| !request.starts_with("POST ")));
}

fn wait_child_with_output(mut child: Child) -> Output {
    fn read_pipe(
        pipe: Option<impl Read + Send + 'static>,
    ) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = match pipe {
                Some(mut pipe) => {
                    let mut bytes = Vec::new();
                    pipe.read_to_end(&mut bytes).map(|_| bytes)
                }
                None => Ok(Vec::new()),
            };
            let _ = sender.send(result);
        });
        receiver
    }

    let stdout = read_pipe(child.stdout.take());
    let stderr = read_pipe(child.stderr.take());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child process did not exit within 10 seconds");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let stdout = stdout
        .recv_timeout(remaining())
        .expect("child stdout remained open after process exit")
        .unwrap();
    let stderr = stderr
        .recv_timeout(remaining())
        .expect("child stderr remained open after process exit")
        .unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn cli_agents_json_emits_supported_agent_shapes() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["agents", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let agents = parsed.as_array().unwrap();
    assert!(agents.iter().any(|agent| agent["name"] == "codex"));
    assert!(agents.iter().all(|agent| agent["status"].is_string()));
}

#[test]
fn cli_doctor_json_emits_versioned_report() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(&cwd).unwrap();
    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["doctor", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert!(parsed["environment"].is_object());
    assert!(parsed["configuration"].is_object());
    assert!(parsed["agents"].is_array());
}

#[test]
fn cli_plugins_validate_json_emits_versioned_success_output() {
    let temp = tempfile::tempdir().unwrap();
    let plugin_dir = temp.path().join("plugins").join("acme");
    write_dynamic_plugin_manifest(&plugin_dir, "acme.cli-json");

    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "validate"])
        .arg(&plugin_dir)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["command"], "plugins validate");
    assert_eq!(parsed["data"]["target_kind"], "path");
    assert_eq!(parsed["data"]["resolved_plugin_id"], "acme.cli-json");
    assert_eq!(parsed["data"]["valid"], true);
    assert_eq!(parsed["data"]["policy_state"], "valid");
    assert_eq!(parsed["data"]["startup_class"], "optional");
    assert_eq!(parsed["data"]["attestation_mode"], "integrity_only");
}

#[test]
fn cli_plugins_validate_rejects_malformed_python_entrypoints_by_path_and_id() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    let config_dir = cwd.join(".nemo-relay");
    let plugin_id = "acme.invalid-python-entrypoint";
    std::fs::create_dir_all(&config_dir).unwrap();
    write_python_dynamic_plugin_manifest(&plugin_dir, plugin_id);
    std::fs::write(
        config_dir.join("plugins.toml"),
        format!(
            "[[plugins.dynamic]]\nmanifest = {}\n",
            toml_basic_string(plugin_dir.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let manifest_path = plugin_dir.join("relay-plugin.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    std::fs::write(
        manifest_path,
        manifest.replace("entrypoint = \"plugin:main\"", "entrypoint = \"plugin\""),
    )
    .unwrap();

    for target in [
        plugin_dir.to_string_lossy().into_owned(),
        plugin_id.to_owned(),
    ] {
        let output = Command::new(gateway_bin())
            .current_dir(&cwd)
            .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
            .env("HOME", temp.path())
            .args(["plugins", "validate", &target, "--json"])
            .output()
            .unwrap();

        assert!(
            !output.status.success(),
            "malformed Python entrypoint unexpectedly validated for {target}"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(parsed["command"], "plugins validate");
        assert!(
            parsed["error"]["message"]
                .as_str()
                .unwrap()
                .contains("module:function form"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn cli_plugins_list_json_emits_empty_versioned_success_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .current_dir(temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .env_remove("NEMO_RELAY_PLUGIN_CONFIG_PATH")
        .args(["plugins", "list", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["command"], "plugins list");
    assert_eq!(parsed["data"], serde_json::json!([]));
}

#[test]
fn cli_plugins_inspect_json_missing_plugin_emits_not_found_error() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "inspect", "missing.plugin", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["command"], "plugins inspect");
    assert_eq!(parsed["error"]["code"], "not_found");
    assert_eq!(parsed["error"]["kind"], "not_found");
}

#[test]
fn cli_plugins_list_all_json_includes_tombstoned_records() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    std::fs::create_dir_all(&cwd).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.tombstoned");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let remove = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "remove", "acme.tombstoned"])
        .output()
        .unwrap();
    assert!(
        remove.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&remove.stderr)
    );

    let list = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "list", "--all", "--json"])
        .output()
        .unwrap();

    assert!(
        list.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["command"], "plugins list");
    assert_eq!(parsed["data"][0]["id"], "acme.tombstoned");
    assert_eq!(parsed["data"][0]["tombstoned"], true);
    assert_eq!(parsed["data"][0]["runtime_state"], "tombstoned");
    assert_eq!(parsed["data"][0]["policy_state"], "valid");
    assert_eq!(parsed["data"][0]["startup_class"], "optional");
    assert_eq!(parsed["data"][0]["attestation_mode"], "integrity_only");
}

#[test]
fn cli_plugins_validate_json_reports_blocked_policy_for_path_target() {
    let temp = tempfile::tempdir().unwrap();
    let plugin_dir = temp.path().join("plugins").join("acme");
    let xdg = temp.path().join("xdg");
    let user_config_dir = xdg.join("nemo-relay");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.cli-blocked-path");
    std::fs::write(
        user_config_dir.join("plugins.toml"),
        r#"
[plugins.policy.defaults]
allowed = false
"#,
    )
    .unwrap();

    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .args(["plugins", "validate"])
        .arg(&plugin_dir)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["target_kind"], "path");
    assert_eq!(parsed["data"]["valid"], false);
    assert_eq!(parsed["data"]["policy_state"], "invalid");
    assert_eq!(parsed["data"]["startup_class"], "optional");
    assert_eq!(parsed["data"]["attestation_mode"], "integrity_only");
    assert!(
        parsed["data"]["errors"][0]
            .as_str()
            .unwrap()
            .contains("blocked by host policy")
    );
}

#[test]
fn cli_plugins_validate_json_reports_verified_signature_for_path_target() {
    let temp = tempfile::tempdir().unwrap();
    let plugin_dir = temp.path().join("plugins").join("acme");
    let xdg = temp.path().join("xdg");
    let user_config_dir = xdg.join("nemo-relay");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    write_dynamic_plugin_manifest_with_options(
        &plugin_dir,
        "acme.cli-signed-path",
        &["plugin_worker"],
        Some("plugin.py.sig"),
    );
    let trusted_public_key = write_detached_ed25519_signature(&plugin_dir, "plugin.py.sig");
    std::fs::write(
        user_config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[plugins.policy.defaults]\n",
                "attestation = \"signature_required\"\n",
                "trusted_public_keys = [{}]\n"
            ),
            toml_basic_string(&trusted_public_key)
        ),
    )
    .unwrap();

    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .args(["plugins", "validate"])
        .arg(&plugin_dir)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["valid"], true);
    assert_eq!(parsed["data"]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"]["authenticity_state"], "valid");
}

#[test]
fn cli_plugins_validate_json_reports_invalid_signature_for_wrong_trusted_key() {
    let temp = tempfile::tempdir().unwrap();
    let plugin_dir = temp.path().join("plugins").join("acme");
    let xdg = temp.path().join("xdg");
    let user_config_dir = xdg.join("nemo-relay");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    write_dynamic_plugin_manifest_with_options(
        &plugin_dir,
        "acme.cli-signed-wrong-key",
        &["plugin_worker"],
        Some("plugin.py.sig"),
    );
    write_detached_ed25519_signature(&plugin_dir, "plugin.py.sig");
    let wrong_public_key = generate_ed25519_public_key();
    std::fs::write(
        user_config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[plugins.policy.defaults]\n",
                "attestation = \"signature_required\"\n",
                "trusted_public_keys = [{}]\n"
            ),
            toml_basic_string(&wrong_public_key)
        ),
    )
    .unwrap();

    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .args(["plugins", "validate"])
        .arg(&plugin_dir)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["valid"], false);
    assert_eq!(parsed["data"]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"]["authenticity_state"], "invalid");
    assert!(
        parsed["data"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value
                .as_str()
                .unwrap()
                .contains("failed signature verification"))
    );
}

#[test]
fn cli_plugins_list_json_reports_blocked_policy_for_installed_plugin() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    let config_dir = cwd.join(".nemo-relay");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.cli-blocked-list");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    std::fs::write(
        config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[[plugins.dynamic]]\n",
                "manifest = {}\n\n",
                "[plugins.policy.defaults]\n",
                "startup = \"required\"\n",
                "attestation = \"signature_required\"\n",
                "allowed = false\n"
            ),
            toml_basic_string(plugin_dir.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let list = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "list", "--json"])
        .output()
        .unwrap();

    assert!(
        list.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"][0]["id"], "acme.cli-blocked-list");
    assert_eq!(parsed["data"][0]["validation_state"], "invalid");
    assert_eq!(parsed["data"][0]["policy_state"], "invalid");
    assert_eq!(parsed["data"][0]["startup_class"], "required");
    assert_eq!(parsed["data"][0]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"][0]["last_error"]["phase"], "policy");

    let state_path = config_dir.join(".dynamic-plugins.json");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        state["records"][0]["status"]["validation"]["policy_satisfied"],
        "invalid"
    );
    assert_eq!(
        state["records"][0]["status"]["last_error"]["phase"],
        "policy"
    );
}

#[test]
fn cli_plugins_list_json_reports_invalid_trust_in_validation_state() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    let config_dir = cwd.join(".nemo-relay");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.cli-trust-list");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    std::fs::write(
        config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[[plugins.dynamic]]\n",
                "manifest = {}\n\n",
                "[plugins.policy.defaults]\n",
                "startup = \"required\"\n",
                "attestation = \"signature_required\"\n"
            ),
            toml_basic_string(plugin_dir.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let list = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "list", "--json"])
        .output()
        .unwrap();

    assert!(
        list.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"][0]["id"], "acme.cli-trust-list");
    assert_eq!(parsed["data"][0]["validation_state"], "invalid");
    assert_eq!(parsed["data"][0]["policy_state"], "valid");
    assert_eq!(parsed["data"][0]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"][0]["last_error"]["phase"], "validation");
}

#[test]
fn cli_plugins_validate_json_reports_blocked_policy_for_installed_id_target() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    let config_dir = cwd.join(".nemo-relay");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.cli-blocked-id");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    std::fs::write(
        config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[[plugins.dynamic]]\n",
                "manifest = {}\n\n",
                "[plugins.policy.defaults]\n",
                "startup = \"required\"\n",
                "attestation = \"signature_required\"\n",
                "allowed = false\n"
            ),
            toml_basic_string(plugin_dir.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let validate = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "validate", "acme.cli-blocked-id", "--json"])
        .output()
        .unwrap();

    assert!(
        validate.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["target_kind"], "plugin_id");
    assert_eq!(parsed["data"]["valid"], false);
    assert_eq!(parsed["data"]["policy_state"], "invalid");
    assert_eq!(parsed["data"]["startup_class"], "required");
    assert_eq!(parsed["data"]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"]["desired_enabled"], false);
    assert!(
        parsed["data"]["errors"][0]
            .as_str()
            .unwrap()
            .contains("blocked by host policy")
    );
}

#[test]
fn cli_plugins_inspect_json_emits_installed_plugin_details() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    std::fs::create_dir_all(&cwd).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.inspect-json");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let inspect = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "inspect", "acme.inspect-json", "--json"])
        .output()
        .unwrap();

    assert!(
        inspect.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["command"], "plugins inspect");
    assert_eq!(parsed["target"], "acme.inspect-json");
    assert_eq!(parsed["data"]["id"], "acme.inspect-json");
    assert_eq!(parsed["data"]["kind"], "worker");
    assert_eq!(parsed["data"]["scope"], "project");
    assert_eq!(parsed["data"]["policy_state"], "valid");
    assert_eq!(parsed["data"]["startup_class"], "optional");
    assert_eq!(parsed["data"]["attestation_mode"], "integrity_only");
    assert_eq!(parsed["data"]["host_config_status"], "absent");
    assert!(parsed["data"]["source"]["manifest_ref"].is_string());
}

#[test]
fn cli_plugins_inspect_json_reports_blocked_policy_for_installed_plugin() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    let config_dir = cwd.join(".nemo-relay");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.inspect-blocked");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    std::fs::write(
        config_dir.join("plugins.toml"),
        format!(
            concat!(
                "[[plugins.dynamic]]\n",
                "manifest = {}\n\n",
                "[plugins.policy.defaults]\n",
                "startup = \"required\"\n",
                "attestation = \"signature_required\"\n",
                "allowed = false\n"
            ),
            toml_basic_string(plugin_dir.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let validate = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "validate", "acme.inspect-blocked"])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let inspect = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "inspect", "acme.inspect-blocked", "--json"])
        .output()
        .unwrap();

    assert!(
        inspect.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(parsed["data"]["id"], "acme.inspect-blocked");
    assert_eq!(parsed["data"]["policy_state"], "invalid");
    assert_eq!(parsed["data"]["startup_class"], "required");
    assert_eq!(parsed["data"]["attestation_mode"], "signature_required");
    assert_eq!(parsed["data"]["status"]["last_error"]["phase"], "policy");
}

#[test]
fn cli_plugins_mutation_commands_emit_terse_confirmation_output() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    std::fs::create_dir_all(&cwd).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.mutate-output");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&add.stdout).trim(),
        "Added dynamic plugin acme.mutate-output"
    );

    let enable = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "enable", "acme.mutate-output"])
        .output()
        .unwrap();
    assert!(
        enable.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&enable.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&enable.stdout).trim(),
        "Enabled dynamic plugin acme.mutate-output"
    );

    let disable = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "disable", "acme.mutate-output"])
        .output()
        .unwrap();
    assert!(
        disable.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&disable.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&disable.stdout).trim(),
        "Disabled dynamic plugin acme.mutate-output"
    );

    let remove = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "remove", "acme.mutate-output"])
        .output()
        .unwrap();
    assert!(
        remove.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&remove.stdout).trim(),
        "Removed dynamic plugin acme.mutate-output"
    );

    let revive = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        revive.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&revive.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&revive.stdout).trim(),
        "Revived dynamic plugin acme.mutate-output"
    );
}

#[test]
fn cli_plugins_enable_tombstoned_plugin_returns_refused_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    let plugin_dir = cwd.join("plugins").join("acme");
    std::fs::create_dir_all(&cwd).unwrap();
    write_dynamic_plugin_manifest(&plugin_dir, "acme.tombstone-enable");

    let add = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "add", "--project"])
        .arg(&plugin_dir)
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    let remove = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "remove", "acme.tombstone-enable"])
        .output()
        .unwrap();
    assert!(
        remove.status.success(),
        "stderr was:\n{}",
        String::from_utf8_lossy(&remove.stderr)
    );

    let enable = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "enable", "acme.tombstone-enable"])
        .output()
        .unwrap();
    assert_eq!(enable.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&enable.stderr).contains("tombstoned"),
        "stderr was:\n{}",
        String::from_utf8_lossy(&enable.stderr)
    );
}

#[test]
fn cli_completions_prints_script_for_requested_shell() {
    let output = Command::new(gateway_bin())
        .args(["completions", "zsh"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("#compdef nemo-relay") || stdout.contains("_nemo-relay"));
}

#[test]
fn cli_plugins_edit_requires_tty() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["plugins", "edit", "--user"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires a TTY"),
        "stderr was:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_model_pricing_validate_accepts_valid_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("pricing.json");
    std::fs::write(&catalog, pricing_catalog_json("test-model")).unwrap();

    let output = Command::new(gateway_bin())
        .args(["model-pricing", "validate"])
        .arg(&catalog)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Valid model pricing catalog"));
    assert!(stdout.contains("1 entry"));
}

#[test]
fn cli_model_pricing_validate_rejects_invalid_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("pricing.json");
    std::fs::write(
        &catalog,
        r#"{
  "version": 1,
  "entries": [{
    "provider": "test",
    "model_id": "bad-model",
    "prompt_cache": { "read_accounting": "included_in_prompt_tokens" },
    "pricing_as_of": "2026-06-05",
    "pricing_source": "test"
  }]
}"#,
    )
    .unwrap();

    let output = Command::new(gateway_bin())
        .args(["model-pricing", "validate"])
        .arg(&catalog)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid model pricing catalog"));
    assert!(stderr.contains("rates or rate_schedule"));
}

#[test]
fn cli_model_pricing_init_creates_project_pricing_component() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&project)
        .args(["model-pricing", "init", "--project"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let path = project.join(".nemo-relay/plugins.toml");
    let rendered = std::fs::read_to_string(path).unwrap();
    assert!(rendered.contains("kind = \"pricing\""));
    assert!(!rendered.contains("include_bundled"));
}

#[test]
fn cli_model_pricing_add_source_validates_and_updates_user_plugin_config() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("pricing.json");
    std::fs::write(&catalog, pricing_catalog_json("custom-model")).unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::copy(&catalog, cwd.join("pricing.json")).unwrap();
    let canonical = std::fs::canonicalize(cwd.join("pricing.json")).unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["model-pricing", "add-source"])
        .arg("pricing.json")
        .output()
        .unwrap();

    assert!(output.status.success());
    let rendered = std::fs::read_to_string(
        temp.path()
            .join("xdg")
            .join("nemo-relay")
            .join("plugins.toml"),
    )
    .unwrap();
    assert!(rendered.contains("kind = \"pricing\""));
    assert!(rendered.contains("type = \"file\""));
    assert!(rendered.contains(canonical.to_str().unwrap()));
}

#[test]
fn cli_model_pricing_resolve_reports_source_match_and_estimate() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("pricing.json");
    let xdg = temp.path().join("xdg/nemo-relay");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(&catalog, pricing_catalog_json("custom-model")).unwrap();
    std::fs::write(
        xdg.join("plugins.toml"),
        format!(
            r#"
[[components]]
kind = "pricing"

[components.config]
[[components.config.sources]]
type = "file"
path = {}
"#,
            toml_basic_string(&catalog.display().to_string())
        ),
    )
    .unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&project)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args([
            "model-pricing",
            "resolve",
            "custom-model",
            "--provider",
            "test",
            "--prompt-tokens",
            "1000",
            "--completion-tokens",
            "500",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr was:\n{}\nstdout was:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Resolved model pricing"));
    assert!(stdout.contains(&format!("source = file:{}", catalog.display())));
    assert!(stdout.contains("provider = test"));
    assert!(stdout.contains("model = custom-model"));
    assert!(stdout.contains("estimated_total"));
    assert!(stdout.contains("currency = USD"));
}

#[test]
fn cli_model_pricing_resolve_reports_missing_sources_distinctly() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(&cwd).unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("HOME", temp.path())
        .args(["model-pricing", "resolve", "custom-model"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no model pricing sources configured"),
        "expected missing model pricing source error, got:\n{stderr}"
    );
}

#[test]
fn cli_rejects_removed_coding_agent_transport_commands() {
    let output = Command::new(gateway_bin()).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    for command in ["claude", "codex", "hermes", "mcp", "run", "serve"] {
        assert!(
            !stdout
                .lines()
                .any(|line| { line.split_whitespace().next() == Some(command) }),
            "removed command `{command}` remained in help:\n{stdout}"
        );
        let rejected = Command::new(gateway_bin()).arg(command).output().unwrap();
        assert_eq!(rejected.status.code(), Some(2), "{command}");
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("unrecognized subcommand"),
            "{command}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
}

#[test]
fn cli_rejects_removed_cursor_entry_points() {
    let output = Command::new(gateway_bin()).arg("cursor").output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand 'cursor'"));

    let output = Command::new(gateway_bin())
        .args(["hook-forward", "cursor"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value 'cursor'"));
}

#[test]
fn cli_rejects_removed_plugin_shim_entry_point() {
    let output = Command::new(gateway_bin())
        .args(["plugin-shim", "--help"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn cli_help_lists_model_pricing_command_only() {
    let output = Command::new(gateway_bin()).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("  model-pricing"),
        "expected `--help` to list `model-pricing` subcommand, got:\n{stdout}"
    );
    assert!(
        !stdout.lines().any(|line| line.starts_with("  pricing")),
        "expected `--help` not to list the old `pricing` subcommand, got:\n{stdout}"
    );

    let old_command = Command::new(gateway_bin()).arg("pricing").output().unwrap();
    assert!(!old_command.status.success());
    assert!(String::from_utf8_lossy(&old_command.stderr).contains("unrecognized subcommand"));

    let model_pricing_help = Command::new(gateway_bin())
        .args(["model-pricing", "--help"])
        .output()
        .unwrap();
    let model_pricing_stdout = String::from_utf8_lossy(&model_pricing_help.stdout);
    for description in [
        "Validate a model pricing catalog JSON file",
        "Initialize model pricing in",
        "Add a model pricing catalog file source",
        "Resolve which model pricing entry matches a model",
    ] {
        assert!(
            model_pricing_stdout.contains(description),
            "expected `model-pricing --help` to include `{description}`, got:\n{model_pricing_stdout}"
        );
    }
}

#[test]
fn cli_help_lists_plugin_install_commands() {
    let output = Command::new(gateway_bin()).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    for command in ["install", "uninstall"] {
        assert!(
            stdout.contains(&format!("  {command}")),
            "expected `--help` to list `{command}` subcommand, got:\n{stdout}"
        );
    }
}

#[test]
fn cli_install_dry_run_plans_local_codex_marketplace() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .args([
            "install",
            "codex",
            "--dry-run",
            "--skip-doctor",
            "--install-dir",
        ])
        .arg(temp.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("codex-marketplace"),
        "stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("codex plugin marketplace add"),
        "stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("configure Codex provider and trust plugin-owned hooks"),
        "stdout was:\n{stdout}"
    );
}

#[test]
fn cli_doctor_help_uses_a_positional_enrollment_target() {
    let output = Command::new(gateway_bin())
        .args(["doctor", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[AGENT]"), "stdout was:\n{stdout}");
    assert!(stdout.contains("claude-desktop"), "stdout was:\n{stdout}");
    assert!(!stdout.contains("--plugin"), "stdout was:\n{stdout}");
}

#[test]
fn cli_doctor_enrollment_target_accepts_json_flag() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .args(["doctor", "codex", "--json", "--install-dir"])
        .arg(temp.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "stderr was:\n{stderr}"
    );
}

#[test]
fn cli_bare_invocation_reports_persistent_configuration_choices() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    std::fs::create_dir_all(&xdg).unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(&cwd).unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "bare invocation should reject missing persistent configuration"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no persistent Relay configuration exists")
            && stderr.contains("nemo-relay config")
            && stderr.contains("nemo-relay install <agent>"),
        "expected persistent configuration guidance in stderr, got:\n{stderr}"
    );
}

#[test]
fn cli_doctor_rejects_install_dir_without_an_agent_target() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(gateway_bin())
        .args(["doctor", "--install-dir"])
        .arg(temp.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required"), "stderr was:\n{stderr}");
    assert!(stderr.contains("<AGENT>"), "stderr was:\n{stderr}");
}

#[test]
fn cli_bare_invocation_runs_doctor_when_config_exists() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    std::fs::create_dir_all(&xdg).unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(cwd.join(".nemo-relay")).unwrap();
    std::fs::write(cwd.join(".nemo-relay/config.toml"), "[upstream]\n").unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "bare invocation should run doctor when config exists: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Environment"));
    assert!(stdout.contains("Configuration"));
    assert!(stdout.contains("Agents detected"));
}

#[test]
fn cli_bare_invocation_reports_invalid_config_resolution() {
    let temp = tempfile::tempdir().unwrap();
    let xdg = temp.path().join("xdg");
    std::fs::create_dir_all(&xdg).unwrap();
    let cwd = temp.path().join("workdir");
    std::fs::create_dir_all(cwd.join(".nemo-relay")).unwrap();
    std::fs::write(cwd.join(".nemo-relay/config.toml"), "[upstream]\n").unwrap();
    std::fs::write(cwd.join(".nemo-relay/plugins.toml"), "components = [\n").unwrap();

    let output = Command::new(gateway_bin())
        .current_dir(&cwd)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "bare invocation should fail doctor when config resolution fails"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration"));
    assert!(stdout.contains("Resolution"));
    assert!(stdout.contains("invalid plugin TOML"));
}

#[test]
fn cli_hook_forward_reports_transport_failure_when_fail_closed() {
    let mut child = Command::new(gateway_bin())
        .args(["hook-forward", "codex", "--fail-closed"])
        .env("NEMO_RELAY_GATEWAY_URL", "http://127.0.0.1:1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}").unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("hook forward failed"));
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut buffer = Vec::new();
    let mut scratch = [0; 1024];
    loop {
        let read = stream.read(&mut scratch).unwrap();
        assert_ne!(read, 0);
        buffer.extend_from_slice(&scratch[..read]);
        if let Some(header_end) = find_header_end(&buffer) {
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let expected = header_end + 4 + content_length;
            while buffer.len() < expected {
                let read = stream.read(&mut scratch).unwrap();
                assert_ne!(read, 0);
                buffer.extend_from_slice(&scratch[..read]);
            }
            return String::from_utf8(buffer).unwrap();
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn pricing_catalog_json(model_id: &str) -> String {
    format!(
        r#"{{
  "version": 1,
  "entries": [{{
    "provider": "test",
    "model_id": "{model_id}",
    "rates": {{
      "input_per_million": 1.0,
      "output_per_million": 2.0,
      "cache_read_per_million": 0.1
    }},
    "prompt_cache": {{ "read_accounting": "included_in_prompt_tokens" }},
    "pricing_as_of": "2026-06-05",
    "pricing_source": "test"
  }}]
}}"#
    )
}
