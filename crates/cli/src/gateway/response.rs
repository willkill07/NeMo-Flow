// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Observable header policy and downstream response construction.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, Response, StatusCode};
use serde_json::{Map, Value, json};

use crate::configuration::BOOTSTRAP_CLIENT_TOKEN_HEADER;
use crate::error::CliError;

pub(super) fn observable_headers(headers: &HeaderMap) -> Map<String, Value> {
    let private_headers = declared_provider_credential_headers(headers);
    let mut output = Map::new();
    for (name, value) in headers {
        if should_record_header(name, headers)
            && !private_headers.contains(name.as_str())
            && let Ok(value) = value.to_str()
        {
            output.insert(name.as_str().to_string(), json!(value));
        }
    }
    output
}

pub(super) fn declared_provider_credential_headers(headers: &HeaderMap) -> BTreeSet<String> {
    headers
        .get_all(nemo_relay::api::llm::PROVIDER_CREDENTIAL_HEADER_NAMES_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty() && HeaderName::from_bytes(name.as_bytes()).is_ok())
        .collect()
}

// Copies upstream response headers except hop-by-hop transport headers that Axum/hyper must manage
// for the downstream connection. Multiple values are appended to preserve provider behavior.
// Content-Length is also dropped because the gateway re-encodes streaming responses and the
// upstream-reported length will not match the bytes the client sees.
pub(super) fn response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut output = HeaderMap::new();
    for (name, value) in headers {
        if !is_hop_by_hop(name)
            && !named_by_connection_header(name, headers)
            && name != http::header::CONTENT_LENGTH
        {
            output.append(name.clone(), value.clone());
        }
    }
    output
}

// Reconstructs an Axum response from upstream status, filtered headers, and the selected body. All
// builder errors are converted into gateway HTTP errors rather than panics.
pub(super) fn build_response(
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, CliError> {
    let mut builder = Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(body)?)
}

// Allows provider request headers through unless they are transport-owned or must be recalculated
// for the forwarded body. Host and content length are intentionally excluded because reqwest sets
// them for the upstream connection.
pub(super) fn should_forward_request_header(name: &HeaderName, headers: &HeaderMap) -> bool {
    !is_hop_by_hop(name)
        && !named_by_connection_header(name, headers)
        && name != http::header::HOST
        && name != http::header::CONTENT_LENGTH
        && name.as_str() != BOOTSTRAP_CLIENT_TOKEN_HEADER
        // Strip Accept-Encoding so upstreams return identity-encoded bodies; otherwise the
        // observability capture (`output.value` on LLM spans, ATIF trajectory bodies) records
        // gzip/br/zstd bytes that downstream consumers can't read. Bandwidth cost is paid only
        // on the gateway-upstream hop. The client never asked for the encoding it would have
        // received from upstream, so its decoders never trigger.
        && name != http::header::ACCEPT_ENCODING
}

// Allows headers into observability metadata only after removing credentials and provider API
// keys. The shared classifier covers canonical and provider-specific secret-bearing names.
pub(super) fn should_record_header(name: &HeaderName, headers: &HeaderMap) -> bool {
    should_forward_request_header(name, headers)
        && !super::is_internal_dispatch_header(name)
        && !nemo_relay::api::llm::is_provider_credential_header_name(name.as_str())
}

fn named_by_connection_header(name: &HeaderName, headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name.as_str()))
}

// Identifies headers that describe a single transport hop and therefore must not be proxied across
// the client-gateway-upstream boundary.
pub(super) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
