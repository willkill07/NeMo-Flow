// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use crate::error::CliError;
use crate::installation::generation::{ActiveGenerationGuard, InstallGeneration};

use super::response::handle_hook_forward_response;
use super::{GatewayMode, HookForwardRequest};

const HOOK_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const HOOK_INPUT_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) async fn hook_forward(command: HookForwardRequest) -> Result<(), CliError> {
    if !command.fail_closed {
        return handle_hook_error(
            CliError::Launch(
                "unfenced hook forwarding was removed; reinstall this coding-agent integration"
                    .into(),
            ),
            true,
        );
    }
    validate_optional_json("session metadata", command.session_metadata.as_deref())?;
    let fail_closed = true;
    let enrollment = match crate::claude_desktop::hook_enrollment(command.agent) {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => {
            return handle_hook_error(
                CliError::Launch(format!(
                    "{} is not enrolled in the per-user coding-agent proxy",
                    command.agent.label()
                )),
                fail_closed,
            );
        }
        Err(error) => return handle_hook_error(CliError::Launch(error), fail_closed),
    };
    let destination = command
        .gateway_url
        .as_deref()
        .unwrap_or(&enrollment.gateway_url);
    if enrollment.gateway_url.trim_end_matches('/') != destination.trim_end_matches('/') {
        return handle_hook_error(
            CliError::Launch(format!(
                "{} hook targets {destination}, but its enrolled proxy endpoint is {}; reinstall the integration",
                command.agent.label(),
                enrollment.gateway_url
            )),
            fail_closed,
        );
    };
    if let Err(error) =
        crate::claude_desktop::verify_hook_enrollment_health(command.agent, &enrollment)
    {
        return handle_hook_error(CliError::Launch(error), fail_closed);
    }
    let input = match read_hook_payload(enrollment.max_hook_payload_bytes) {
        Ok(input) => input,
        Err(error) => return handle_hook_error(error, fail_closed),
    };
    let _generation_guard = match capture_generation_guard(&command) {
        Ok(guard) => guard,
        Err(error) => return handle_hook_error(error, fail_closed),
    };
    if let Err(error) =
        crate::claude_desktop::verify_hook_enrollment_health(command.agent, &enrollment)
    {
        return handle_hook_error(CliError::Launch(error), fail_closed);
    }
    if let Err(error) = verify_hook_host_configuration(&command, destination) {
        return handle_hook_error(CliError::Launch(error), fail_closed);
    }

    let url = format!(
        "{}{}",
        destination.trim_end_matches('/'),
        command.agent.hook_path()
    );
    let response = match send_hook_forward_request(
        &command,
        &url,
        input,
        Some(enrollment.authorization.as_str()),
        Some(enrollment.root_ca_pem.as_path()),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return handle_hook_error(error, fail_closed),
    };
    handle_hook_forward_response(response, fail_closed).await
}

fn verify_hook_host_configuration(
    command: &HookForwardRequest,
    gateway_url: &str,
) -> Result<(), String> {
    let generation_file = command.generation_file.as_deref().ok_or_else(|| {
        format!(
            "{} hook is missing its generation path",
            command.agent.label()
        )
    })?;
    let generation_token = command.generation_token.as_deref().ok_or_else(|| {
        format!(
            "{} hook is missing its generation identity",
            command.agent.label()
        )
    })?;
    crate::agents::verify_hook_host_configuration(
        command.agent,
        gateway_url,
        generation_file,
        generation_token,
    )
}

fn capture_generation_guard(
    command: &HookForwardRequest,
) -> Result<Option<ActiveGenerationGuard>, CliError> {
    let install_host = command.agent.install_arg();
    let generation_file = command.generation_file.clone().ok_or_else(|| {
        CliError::Launch(format!(
            "persistent {} hook is missing its install-generation fence; run `nemo-relay install {install_host} --force`",
            command.agent.label()
        ))
    })?;
    let generation_token = command.generation_token.as_deref().ok_or_else(|| {
        CliError::Launch(format!(
            "persistent {} hook is missing its expected install-generation identity; run `nemo-relay install {install_host} --force`",
            command.agent.label()
        ))
    })?;
    InstallGeneration::capture_guarded_expected(generation_file, generation_token)
        .map(|(_generation, guard)| Some(guard))
        .map_err(CliError::Launch)
}

fn handle_hook_error(error: CliError, fail_closed: bool) -> Result<(), CliError> {
    if fail_closed {
        log::error!(
            target: "nemo_relay.hook",
            event = "hook_delivery_failed",
            mode = "fail_closed",
            error_kind = error.log_kind();
            "Hook delivery failed"
        );
        Err(CliError::HookDelivery {
            source: Box::new(error),
        })
    } else {
        log::warn!(
            target: "nemo_relay.hook",
            event = "hook_delivery_failed",
            mode = "fail_open",
            error_kind = error.log_kind();
            "Hook delivery failed open"
        );
        eprintln!("nemo-relay hook forward failed: {error}");
        Ok(())
    }
}

// Reads the native hook payload from stdin and normalizes empty payloads to JSON object syntax.
// This keeps hook commands observable even for agents or events that invoke hooks without input.
fn read_hook_payload(limit: usize) -> Result<String, CliError> {
    read_hook_payload_with_timeout(std::io::stdin(), limit, HOOK_INPUT_TIMEOUT)
}

pub(crate) fn read_hook_payload_with_timeout(
    reader: impl Read + Send + 'static,
    limit: usize,
    timeout: Duration,
) -> Result<String, CliError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("nemo-relay-hook-input".into())
        .spawn(move || {
            let _ = sender.send(read_hook_payload_from(reader, limit));
        })
        .map_err(|error| {
            CliError::Install(format!(
                "failed to start bounded hook input reader: {error}"
            ))
        })?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(CliError::Install(format!(
            "hook payload was not closed within {} seconds",
            timeout.as_secs_f64()
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(CliError::Install(
            "hook payload reader stopped before returning input".into(),
        )),
    }
}

pub(crate) fn read_hook_payload_from(reader: impl Read, limit: usize) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(CliError::Install(format!(
            "hook payload exceeds the {limit}-byte limit"
        )));
    }
    let input = String::from_utf8(bytes)
        .map_err(|error| CliError::Install(format!("hook payload is not valid UTF-8: {error}")))?;
    if input.trim().is_empty() {
        Ok("{}".to_string())
    } else {
        Ok(input)
    }
}

// Sends the hook payload with gateway-specific headers translated from CLI flags. The reqwest
// transport result is returned separately so response handling can preserve the provider reply.
async fn send_hook_forward_request(
    command: &HookForwardRequest,
    url: &str,
    input: String,
    authorization: Option<&str>,
    root_ca_pem: Option<&std::path::Path>,
) -> Result<Result<reqwest::Response, reqwest::Error>, CliError> {
    let mut client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HOOK_FORWARD_TIMEOUT);
    if let Some(path) = root_ca_pem {
        let bytes = crate::filesystem::bounded::read_bounded_regular_file(
            path,
            "coding-agent proxy hook trust anchor",
        )
        .map_err(CliError::Install)?;
        let certificates = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|error| {
            CliError::Install(format!(
                "failed to parse coding-agent proxy hook trust anchor {}: {error}",
                path.display()
            ))
        })?;
        if certificates.is_empty() {
            return Err(CliError::Install(format!(
                "coding-agent proxy hook trust anchor {} contains no certificates",
                path.display()
            )));
        }
        for certificate in certificates {
            client = client.add_root_certificate(certificate);
        }
    }
    let mut request = client.build()?.post(url).headers(gateway_headers(
        command.profile.as_deref(),
        command.session_metadata.as_deref(),
        command.gateway_mode,
    )?);
    if let Some(authorization) = authorization {
        request = request.header(
            crate::claude_desktop::AGENT_AUTHORIZATION_HEADER,
            authorization,
        );
    }
    Ok(request
        .header(CONTENT_TYPE, "application/json")
        .body(input)
        .send()
        .await)
}

// Handles hook delivery results without changing agent control flow unless `--fail-closed` was
// requested. Successful non-empty endpoint bodies are printed verbatim for the invoking hook API.
fn validate_optional_json(name: &str, value: Option<&str>) -> Result<(), CliError> {
    if let Some(value) = value {
        serde_json::from_str::<Value>(value)
            .map_err(|error| CliError::Install(format!("invalid {name}: {error}")))?;
    }
    Ok(())
}

// Converts optional session/export/gateway settings into gateway headers for hook-forward. Each
// absent value is omitted so the server can fall back to file, environment, or default config.
pub(crate) fn gateway_headers(
    profile: Option<&str>,
    session_metadata: Option<&str>,
    gateway_mode: Option<GatewayMode>,
) -> Result<HeaderMap, CliError> {
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "x-nemo-relay-config-profile", profile)?;
    insert_header(
        &mut headers,
        "x-nemo-relay-session-metadata",
        session_metadata,
    )?;
    insert_header(
        &mut headers,
        "x-nemo-relay-gateway-mode",
        gateway_mode.map(GatewayMode::as_arg),
    )?;
    Ok(headers)
}

// Inserts one optional header after validating it is legal HTTP header text. Invalid values are
// reported as installer errors because they came from generated or user-provided hook options.
pub(crate) fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: Option<&str>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value)
                .map_err(|error| CliError::Install(format!("invalid header {name}: {error}")))?,
        );
    }
    Ok(())
}
