// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated CONNECT proxy and exact-host TLS interception for Claude Code traffic.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use base64::Engine;
use futures_util::StreamExt;
use http::header::{
    CONNECTION, CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use reqwest::{Client, NoProxy, Proxy, Url};
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::certificate::INTERCEPTED_HOST;
use super::settings::UpstreamProxy;
use super::state::DesktopState;

const CONTROL_HOST: &str = "nemo-relay.invalid";
const HEALTH_PATH: &str = "/.nemo-relay/healthz";
const SHUTDOWN_PATH: &str = "/.nemo-relay/shutdown";
const CONNECT_HEADER_LIMIT: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxStream = Box<dyn AsyncStream>;

#[derive(Clone)]
pub(super) struct Runtime {
    state: Arc<DesktopState>,
    tls: Arc<rustls::ServerConfig>,
    upstream_client: Client,
    gateway_client: Client,
    gateway_base: String,
    shutdown: watch::Sender<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Health {
    pub(super) service: String,
    pub(super) version: String,
    pub(super) generation: String,
    pub(super) configuration_fingerprint: String,
    pub(super) gateway_url: String,
    pub(super) proxy_url: String,
}

impl Runtime {
    pub(super) fn new(
        state: DesktopState,
        tls: Arc<rustls::ServerConfig>,
        shutdown: watch::Sender<bool>,
    ) -> Result<Self, String> {
        Self::new_with_gateway(state, tls, shutdown, crate::bootstrap::DEFAULT_URL.into())
    }

    fn new_with_gateway(
        state: DesktopState,
        tls: Arc<rustls::ServerConfig>,
        shutdown: watch::Sender<bool>,
        gateway_base: String,
    ) -> Result<Self, String> {
        let upstream_client = upstream_client(state.upstream_proxy.as_ref())?;
        let gateway_client = Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| format!("failed to build loopback gateway client: {error}"))?;
        Ok(Self {
            state: Arc::new(state),
            tls,
            upstream_client,
            gateway_client,
            gateway_base,
            shutdown,
        })
    }
}

pub(super) fn upstream_client(proxy: Option<&UpstreamProxy>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(30))
        .timeout(REQUEST_TIMEOUT)
        .read_timeout(REQUEST_TIMEOUT);
    if let Some(proxy) = proxy {
        let (url, auth) = proxy_url_and_auth(&proxy.url)?;
        let mut configured = Proxy::all(url.as_str())
            .map_err(|error| format!("invalid corporate proxy: {error}"))?;
        if let Some((username, password)) = auth {
            configured = configured.basic_auth(&username, &password);
        }
        let normalized_no_proxy = proxy
            .no_proxy
            .as_deref()
            .map(super::settings::normalize_no_proxy);
        configured = configured.no_proxy(
            normalized_no_proxy
                .as_deref()
                .and_then(NoProxy::from_string),
        );
        builder = builder.proxy(configured);
        if let Some(path) = proxy.ca_bundle.as_deref() {
            let pem = crate::filesystem::bounded::read_bounded_regular_file(
                path,
                "Claude Desktop corporate proxy CA bundle",
            )?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
                format!(
                    "failed to parse Claude Desktop corporate proxy CA bundle {}: {error}",
                    path.display()
                )
            })?;
            if certificates.is_empty() {
                return Err(format!(
                    "Claude Desktop corporate proxy CA bundle {} contains no certificates",
                    path.display()
                ));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
    }
    builder
        .build()
        .map_err(|error| format!("failed to build Claude Desktop upstream client: {error}"))
}

pub(super) async fn serve(listener: TcpListener, runtime: Runtime) -> Result<(), String> {
    let mut shutdown = runtime.shutdown.subscribe();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|error| format!("Claude Desktop proxy accept failed: {error}"))?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(stream, runtime).await {
                        log::warn!(
                            target: "nemo_relay.gateway",
                            event = "proxy_connection_failed",
                            error_kind = "transport";
                            "Claude Desktop proxy connection failed: {error}"
                        );
                    }
                });
            }
        }
    }
}

async fn serve_connection(stream: TcpStream, runtime: Runtime) -> Result<(), String> {
    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| handle_proxy_request(request, runtime.clone())),
        )
        .with_upgrades()
        .await
        .map_err(|error| format!("proxy HTTP connection failed: {error}"))
}

async fn handle_proxy_request(
    request: Request<Incoming>,
    runtime: Runtime,
) -> Result<Response<Body>, std::convert::Infallible> {
    let response = match authenticate(
        request.headers(),
        &runtime.state.proxy_username,
        &runtime.state.proxy_token,
    ) {
        Ok(()) if request.method() == Method::CONNECT => connect_request(request, runtime).await,
        Ok(()) => control_request(request, &runtime),
        Err(()) => Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header(PROXY_AUTHENTICATE, "Basic realm=\"nemo-relay\"")
            .header(CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("proxy authentication response is valid"),
    };
    Ok(response)
}

enum ConnectTarget {
    Intercepted,
    Public(Vec<SocketAddr>),
}

async fn connect_request(mut request: Request<Incoming>, runtime: Runtime) -> Response<Body> {
    let (host, port) = match validate_connect_request(&request)
        .and_then(|_| parse_connect_authority(request.uri()))
    {
        Ok(authority) => authority,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(error) = validate_connect_host(request.headers(), &host, port) {
        return text_response(StatusCode::BAD_REQUEST, error);
    }
    let target = match prepare_connect_target(&host, port).await {
        Ok(target) => target,
        Err(error) => return text_response(StatusCode::FORBIDDEN, error),
    };
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(run_connect_tunnel(upgrade, host, port, target, runtime));
    connect_response()
}

async fn prepare_connect_target(host: &str, port: u16) -> Result<ConnectTarget, String> {
    if port != 443 {
        return Err(format!("refusing CONNECT to non-TLS port {host}:{port}"));
    }
    if host.eq_ignore_ascii_case(INTERCEPTED_HOST) {
        return Ok(ConnectTarget::Intercepted);
    }
    resolve_public_addresses(host, port)
        .await
        .map(ConnectTarget::Public)
}

async fn run_connect_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    host: String,
    port: u16,
    target: ConnectTarget,
    runtime: Runtime,
) {
    let result = complete_connect_tunnel(upgrade, &host, port, target, &runtime).await;
    if let Err(error) = result {
        log::warn!(
            target: "nemo_relay.gateway",
            event = "connect_tunnel_failed",
            destination = format!("{host}:{port}").as_str(),
            error_kind = "transport";
            "Claude Desktop CONNECT tunnel failed: {error}"
        );
    }
}

async fn complete_connect_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    host: &str,
    port: u16,
    target: ConnectTarget,
    runtime: &Runtime,
) -> Result<(), String> {
    let upgraded = upgrade
        .await
        .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
    match target {
        ConnectTarget::Intercepted => inspect_anthropic(upgraded, runtime.clone()).await,
        ConnectTarget::Public(addresses) => {
            tunnel_public(
                upgraded,
                host,
                port,
                &addresses,
                runtime.state.upstream_proxy.as_ref(),
            )
            .await
        }
    }
}

fn control_request(request: Request<Incoming>, runtime: &Runtime) -> Response<Body> {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    if host != CONTROL_HOST {
        return text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "authenticated proxy accepts CONNECT only",
        );
    }
    match (request.method(), request.uri().path()) {
        (&Method::GET, HEALTH_PATH) => {
            let health = Health {
                service: "nemo-relay-claude-desktop".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                generation: runtime.state.generation.clone(),
                configuration_fingerprint: runtime.state.configuration_fingerprint.clone(),
                gateway_url: crate::bootstrap::DEFAULT_URL.into(),
                proxy_url: format!("http://{}", super::PROXY_BIND),
            };
            let bytes = serde_json::to_vec(&health).expect("health response is serializable");
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(CONTENT_LENGTH, bytes.len().to_string())
                .body(Body::from(bytes))
                .expect("health response is valid")
        }
        (&Method::POST, SHUTDOWN_PATH) => {
            let _ = runtime.shutdown.send(true);
            empty_response(StatusCode::NO_CONTENT)
        }
        _ => empty_response(StatusCode::NOT_FOUND),
    }
}

async fn inspect_anthropic(
    upgraded: hyper::upgrade::Upgraded,
    runtime: Runtime,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(runtime.tls.clone());
    let tls = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(TokioIo::new(upgraded)))
        .await
        .map_err(|_| "TLS handshake with Claude timed out".to_string())?
        .map_err(|error| format!("TLS handshake with Claude failed: {error}"))?;
    let server_name = tls
        .get_ref()
        .1
        .server_name()
        .ok_or_else(|| "Claude did not present TLS SNI".to_string())?;
    if !server_name.eq_ignore_ascii_case(INTERCEPTED_HOST) {
        return Err(format!("refusing unexpected TLS SNI {server_name:?}"));
    }
    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(tls),
            service_fn(move |request| handle_anthropic_request(request, runtime.clone())),
        )
        .await
        .map_err(|error| format!("intercepted Anthropic HTTP connection failed: {error}"))
}

async fn handle_anthropic_request(
    request: Request<Incoming>,
    runtime: Runtime,
) -> Result<Response<Body>, std::convert::Infallible> {
    let response = match validate_anthropic_host(request.headers()) {
        Err(error) => text_response(StatusCode::MISDIRECTED_REQUEST, error),
        Ok(()) => match classify_route(request.method(), request.uri().path()) {
            Route::Managed => {
                forward(request, &runtime.gateway_client, &runtime.gateway_base).await
            }
            Route::Control => {
                forward(
                    request,
                    &runtime.upstream_client,
                    "https://api.anthropic.com",
                )
                .await
            }
            Route::Rejected(reason) => text_response(StatusCode::FORBIDDEN, reason),
        },
    };
    Ok(response)
}

async fn forward(request: Request<Incoming>, client: &Client, base: &str) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body_limit = crate::configuration::DEFAULT_MAX_PASSTHROUGH_BODY_BYTES;
    if parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > body_limit)
    {
        return text_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds the {body_limit}-byte Relay limit"),
        );
    }
    let path = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str());
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let body = match Limited::new(body, body_limit).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds the {body_limit}-byte Relay limit"),
            );
        }
    };
    let mut upstream = client.request(parts.method, url).body(body);
    for (name, value) in &parts.headers {
        if should_forward_header(name) {
            upstream = upstream.header(name, value);
        }
    }
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            log::warn!(
                target: "nemo_relay.gateway",
                event = "intercept_forward_failed",
                error_kind = "upstream";
                "Claude Desktop intercepted request failed: {error}"
            );
            return text_response(StatusCode::BAD_GATEWAY, "Relay upstream request failed");
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let stream = response
        .bytes_stream()
        .map(|result| result.map_err(std::io::Error::other));
    let mut output = Response::builder().status(status);
    for (name, value) in &headers {
        if should_forward_header(name) {
            output = output.header(name, value);
        }
    }
    output
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Managed,
    Control,
    Rejected(&'static str),
}

fn classify_route(method: &Method, path: &str) -> Route {
    if matches!(path, "/v1/messages" | "/v1/messages/count_tokens") {
        return if method == Method::POST {
            Route::Managed
        } else {
            Route::Rejected("managed Anthropic inference routes require POST")
        };
    }
    if path == "/v1/messages/batches"
        || path.starts_with("/v1/messages/batches/")
        || matches!(path, "/v1/complete" | "/v1/completions")
    {
        return Route::Rejected("unsupported Anthropic inference route is fail-closed");
    }
    let allowed = matches!(
        path,
        "/api/account/settings"
            | "/api/bootstrap"
            | "/api/bootstrap/"
            | "/api/claude_cli/bootstrap"
            | "/api/claude_code/settings"
            | "/api/oauth/claude_cli/create_api_key"
            | "/api/oauth/claude_cli/roles"
            | "/api/oauth/profile"
            | "/v1/oauth/device_authorization"
            | "/v1/oauth/token"
            | "/v1/models"
    ) || path.starts_with("/api/organizations/")
        || path.starts_with("/v1/oauth/")
        || path.starts_with("/v1/mcp/")
        || path.starts_with("/v1/toolbox/shttp/mcp/");
    if allowed && control_method_allowed(method) {
        Route::Control
    } else if path.starts_with("/v1/") {
        Route::Rejected("unknown Anthropic /v1 route is fail-closed")
    } else {
        Route::Rejected("Anthropic endpoint is not on the audited control-plane allowlist")
    }
}

fn control_method_allowed(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE | Method::HEAD
    )
}

async fn tunnel_public(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: u16,
    public_addresses: &[SocketAddr],
    upstream_proxy: Option<&UpstreamProxy>,
) -> Result<(), String> {
    let mut remote = if upstream_proxy.is_some_and(|proxy| {
        !no_proxy_matches(proxy.no_proxy.as_deref(), host, port, public_addresses)
    }) {
        connect_through_upstream_proxy(
            upstream_proxy.expect("proxy presence was checked"),
            host,
            port,
        )
        .await?
    } else {
        connect_addresses(public_addresses)
            .await
            .map(|stream| Box::new(stream) as BoxStream)?
    };
    let mut client = TokioIo::new(upgraded);
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio::io::copy_bidirectional(&mut client, &mut remote),
    )
    .await
    .map_err(|_| format!("CONNECT tunnel to {host}:{port} timed out"))?
    .map_err(|error| format!("CONNECT tunnel to {host}:{port} failed: {error}"))?;
    Ok(())
}

async fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err("refusing CONNECT to a local hostname".into());
    }
    let addresses = tokio::time::timeout(IO_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| format!("DNS resolution for {host} timed out"))?
        .map_err(|error| format!("failed to resolve {host}: {error}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(format!(
            "refusing CONNECT to {host}: resolution included a private, loopback, link-local, multicast, or unspecified address"
        ));
    }
    Ok(addresses)
}

async fn connect_addresses(addresses: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some("connection timed out".into()),
        }
    }
    Err(format!(
        "could not connect to resolved destination: {}",
        last_error.unwrap_or_else(|| "no address".into())
    ))
}

async fn connect_through_upstream_proxy(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<BoxStream, String> {
    let (url, auth) = proxy_url_and_auth(&proxy.url)?;
    let proxy_host = url
        .host_str()
        .ok_or_else(|| "corporate proxy URL has no host".to_string())?;
    let proxy_port = url
        .port_or_known_default()
        .ok_or_else(|| "corporate proxy URL has no port".to_string())?;
    let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((proxy_host, proxy_port)))
        .await
        .map_err(|_| "corporate proxy connection timed out".to_string())?
        .map_err(|error| format!("failed to connect to corporate proxy: {error}"))?;
    let mut stream: BoxStream = if url.scheme() == "https" {
        Box::new(connect_tls_to_proxy(tcp, proxy_host, proxy.ca_bundle.as_deref()).await?)
    } else {
        Box::new(tcp)
    };
    let mut request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some((username, password)) = auth {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "corporate proxy CONNECT write timed out".to_string())?
        .map_err(|error| format!("corporate proxy CONNECT write failed: {error}"))?;
    let response = read_headers(&mut stream).await?;
    let status = upstream_connect_status(&response)?;
    if status != 200 {
        return Err(format!(
            "corporate proxy rejected CONNECT to {host}:{port} with HTTP {status}"
        ));
    }
    Ok(stream)
}

fn upstream_connect_status(response: &str) -> Result<u16, String> {
    let mut fields = response
        .split_once("\r\n")
        .map_or(response, |(status, _)| status)
        .split_ascii_whitespace();
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err("corporate proxy returned a malformed CONNECT response".into());
    }
    fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .ok_or_else(|| "corporate proxy returned a malformed CONNECT response".into())
}

async fn connect_tls_to_proxy(
    stream: TcpStream,
    host: &str,
    ca_bundle: Option<&std::path::Path>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (mut added, mut ignored) = roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_bundle {
        let pem = crate::filesystem::bounded::read_bounded_regular_file(
            path,
            "Claude Desktop corporate proxy CA bundle",
        )?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "failed to parse Claude Desktop corporate proxy CA bundle {}: {error}",
                    path.display()
                )
            })?;
        let (custom_added, custom_ignored) = roots.add_parsable_certificates(certificates);
        added += custom_added;
        ignored += custom_ignored;
    }
    if added == 0 {
        return Err(format!(
            "no trusted root certificates were available for HTTPS corporate proxy ({ignored} invalid entries)"
        ));
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| "corporate proxy host is not a valid TLS server name".to_string())?;
    tokio::time::timeout(
        IO_TIMEOUT,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| "TLS handshake with corporate proxy timed out".to_string())?
    .map_err(|error| format!("TLS handshake with corporate proxy failed: {error}"))
}

async fn read_headers(stream: &mut BoxStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() < CONNECT_HEADER_LIMIT {
        let count = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut byte))
            .await
            .map_err(|_| "corporate proxy response timed out".to_string())?
            .map_err(|error| format!("failed to read corporate proxy response: {error}"))?;
        if count == 0 {
            return Err("corporate proxy closed before completing CONNECT response".into());
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| "corporate proxy response headers are not UTF-8".into());
        }
    }
    Err("corporate proxy response headers exceed the 16 KiB limit".into())
}

fn authenticate(headers: &HeaderMap, username: &str, token: &str) -> Result<(), ()> {
    let values = headers
        .get_all(PROXY_AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(());
    }
    let raw = values[0].to_str().map_err(|_| ())?;
    let (scheme, encoded) = raw.split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("basic")
        || encoded.is_empty()
        || encoded.chars().any(char::is_whitespace)
    {
        return Err(());
    }
    let presented = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ())?;
    let expected = format!("{username}:{token}");
    if bool::from(presented.as_slice().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_connect_request(request: &Request<Incoming>) -> Result<(), String> {
    if request.headers().contains_key(TRANSFER_ENCODING) {
        return Err("CONNECT requests must not use Transfer-Encoding".into());
    }
    let lengths = request
        .headers()
        .get_all(CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    if lengths.len() > 1 {
        return Err("CONNECT requests must contain at most one Content-Length".into());
    }
    if let Some(value) = lengths.first() {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "CONNECT Content-Length is malformed".to_string())?;
        if length != 0 {
            return Err("CONNECT requests must not contain a body".into());
        }
    }
    Ok(())
}

fn parse_connect_authority(uri: &http::Uri) -> Result<(String, u16), String> {
    if uri.path_and_query().is_some() {
        return Err("CONNECT target must be an authority, not a path or query".into());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "CONNECT target is missing an authority".to_string())?;
    let host = authority.host();
    if host.is_empty() || authority.as_str().contains('@') {
        return Err("CONNECT target contains an invalid hostname".into());
    }
    let port = authority
        .port_u16()
        .ok_or_else(|| "CONNECT target must include an explicit port".to_string())?;
    if port == 0 {
        return Err("CONNECT target port must be nonzero".into());
    }
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        port,
    ))
}

fn validate_connect_host(headers: &HeaderMap, host: &str, port: u16) -> Result<(), String> {
    let values = headers.get_all(HOST).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err("CONNECT request must contain one Host header".into());
    }
    let raw = values[0]
        .to_str()
        .map_err(|_| "CONNECT Host header is not valid text".to_string())?;
    let authority = raw
        .parse::<http::uri::Authority>()
        .map_err(|_| "CONNECT Host header is not a valid authority".to_string())?;
    let candidate = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    if candidate.eq_ignore_ascii_case(host) && authority.port_u16() == Some(port) {
        Ok(())
    } else {
        Err("CONNECT Host header does not match the request target".into())
    }
}

fn validate_anthropic_host(headers: &HeaderMap) -> Result<(), String> {
    let values = headers.get_all(HOST).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err("intercepted request must contain one Host header".into());
    }
    let host = values[0]
        .to_str()
        .map_err(|_| "intercepted Host header is not valid text".to_string())?;
    let host = host
        .strip_suffix(":443")
        .unwrap_or(host)
        .trim_end_matches('.');
    if host.eq_ignore_ascii_case(INTERCEPTED_HOST) {
        Ok(())
    } else {
        Err(format!("refusing intercepted request for Host {host:?}"))
    }
}

fn should_forward_header(name: &http::HeaderName) -> bool {
    !matches!(
        *name,
        CONNECTION
            | PROXY_AUTHORIZATION
            | PROXY_AUTHENTICATE
            | TRANSFER_ENCODING
            | HOST
            | TE
            | TRAILER
            | UPGRADE
    ) && !matches!(name.as_str(), "keep-alive" | "proxy-connection")
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip.octets()),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ipv4(mapped.octets());
            }
            let value = u128::from(ip);
            ![
                (0_u128, 128),                     // unspecified
                (0_u128, 96),                      // deprecated IPv4-compatible addresses
                (1, 128),                          // loopback
                (0x0064_ff9b_u128 << 96, 96),      // well-known IPv4 translation prefix
                (0x0064_ff9b_0001_u128 << 80, 48), // local-use translation prefix
                (0x100_u128 << 112, 64),           // discard-only
                (0x2001_u128 << 112, 23),          // IETF protocol assignments
                (0x2001_0db8_u128 << 96, 32),      // documentation
                (0x2002_u128 << 112, 16),          // 6to4 can encode private IPv4
                (0x3fff_u128 << 112, 20),          // documentation
                (0x5f00_u128 << 112, 16),          // segment-routing SIDs
                (0xfc_u128 << 120, 7),             // unique-local
                (0xfe80_u128 << 112, 10),          // link-local
                (0xfec0_u128 << 112, 10),          // deprecated site-local
                (0xff_u128 << 120, 8),             // multicast
            ]
            .into_iter()
            .any(|(network, prefix)| in_ipv6_prefix(value, network, prefix))
        }
    }
}

fn in_ipv6_prefix(value: u128, network: u128, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(u128::MAX);
    value & mask == network & mask
}

fn is_public_ipv4([a, b, c, _d]: [u8; 4]) -> bool {
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn no_proxy_matches(raw: Option<&str>, host: &str, port: u16, addresses: &[SocketAddr]) -> bool {
    raw.is_some_and(|raw| {
        raw.split(|character: char| character == ',' || character.is_ascii_whitespace())
            .map(str::trim)
            .any(|entry| no_proxy_entry_matches(entry, host, port, addresses))
    })
}

fn no_proxy_entry_matches(entry: &str, host: &str, port: u16, addresses: &[SocketAddr]) -> bool {
    if entry == "*" {
        return true;
    }
    let (entry_host, entry_port) = split_no_proxy_host_port(entry);
    if entry_port.is_some_and(|candidate| candidate != port) {
        return false;
    }
    if let Ok(network) = entry_host.parse::<IpNet>() {
        return host
            .parse::<IpAddr>()
            .is_ok_and(|address| network.contains(&address))
            || addresses
                .iter()
                .any(|address| network.contains(&address.ip()));
    }
    let entry_host = entry_host.trim_start_matches("*.").trim_start_matches('.');
    host.eq_ignore_ascii_case(entry_host)
        || host
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", entry_host.to_ascii_lowercase()))
}

fn split_no_proxy_host_port(entry: &str) -> (&str, Option<u16>) {
    if let Some(bracketed) = entry.strip_prefix('[')
        && let Some((host, suffix)) = bracketed.split_once(']')
    {
        return (
            host,
            suffix
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok()),
        );
    }
    entry
        .rsplit_once(':')
        .map_or((entry, None), |(host, port)| {
            if port.chars().all(|character| character.is_ascii_digit()) {
                (host, port.parse::<u16>().ok())
            } else {
                (entry, None)
            }
        })
}

fn proxy_url_and_auth(url: &str) -> Result<(Url, Option<(String, String)>), String> {
    let mut url = Url::parse(url).map_err(|error| format!("invalid proxy URL: {error}"))?;
    let auth = if url.username().is_empty() && url.password().is_none() {
        None
    } else {
        let username = percent_decode_str(url.username())
            .decode_utf8()
            .map_err(|_| "proxy username is not valid UTF-8".to_string())?
            .into_owned();
        let password = percent_decode_str(url.password().unwrap_or_default())
            .decode_utf8()
            .map_err(|_| "proxy password is not valid UTF-8".to_string())?
            .into_owned();
        Some((username, password))
    };
    url.set_username("")
        .map_err(|_| "failed to remove proxy username".to_string())?;
    url.set_password(None)
        .map_err(|_| "failed to remove proxy password".to_string())?;
    Ok((url, auth))
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("empty proxy response is valid")
}

fn connect_response() -> Response<Body> {
    // RFC 9110 forbids Content-Length and Transfer-Encoding on a successful CONNECT response.
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("CONNECT proxy response is valid")
}

fn text_response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    let message = message.into();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, message.len().to_string())
        .body(Body::from(message))
        .expect("text proxy response is valid")
}

pub(super) fn health(state: &DesktopState, timeout: Duration) -> Result<Health, String> {
    let health = control_health(state, timeout)?;
    if !crate::gateway::client::healthz_compatible(
        crate::bootstrap::DEFAULT_URL,
        &state.gateway_fingerprint,
    ) {
        return Err("Claude Desktop Relay gateway is unavailable or has the wrong identity".into());
    }
    Ok(health)
}

fn control_health(state: &DesktopState, timeout: Duration) -> Result<Health, String> {
    let mut stream = std::net::TcpStream::connect_timeout(&super::PROXY_BIND, timeout)
        .map_err(|error| format!("Claude Desktop sidecar is unavailable: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure sidecar health timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure sidecar health timeout: {error}"))?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", state.proxy_username, state.proxy_token));
    let request = format!(
        "GET http://{CONTROL_HOST}{HEALTH_PATH} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nProxy-Authorization: Basic {encoded}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to send sidecar health request: {error}"))?;
    let mut bytes = Vec::new();
    stream
        .take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read sidecar health response: {error}"))?;
    let response = String::from_utf8(bytes)
        .map_err(|_| "sidecar health response is not valid UTF-8".to_string())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "sidecar health response is malformed".to_string())?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err("sidecar health endpoint rejected authenticated request".into());
    }
    let health = serde_json::from_str::<Health>(body)
        .map_err(|error| format!("invalid sidecar health response: {error}"))?;
    if health.service != "nemo-relay-claude-desktop"
        || health.version != state.relay_version
        || health.generation != state.generation
        || health.configuration_fingerprint != state.configuration_fingerprint
        || health.gateway_url != crate::bootstrap::DEFAULT_URL
        || health.proxy_url != format!("http://{}", super::PROXY_BIND)
    {
        return Err("sidecar health identity does not match installed state".into());
    }
    Ok(health)
}

pub(super) fn shutdown(state: &DesktopState, timeout: Duration) -> Result<(), String> {
    control_post(state, SHUTDOWN_PATH, timeout)
}

fn control_post(state: &DesktopState, path: &str, timeout: Duration) -> Result<(), String> {
    let mut stream = std::net::TcpStream::connect_timeout(&super::PROXY_BIND, timeout)
        .map_err(|error| format!("Claude Desktop sidecar is unavailable: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure sidecar control timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure sidecar control timeout: {error}"))?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", state.proxy_username, state.proxy_token));
    let request = format!(
        "POST http://{CONTROL_HOST}{path} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nProxy-Authorization: Basic {encoded}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to send sidecar control request: {error}"))?;
    validate_control_response(&mut stream)
}

fn validate_control_response(stream: &mut impl Read) -> Result<(), String> {
    let mut bytes = Vec::new();
    stream
        .take((CONNECT_HEADER_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read sidecar control response: {error}"))?;
    if bytes.len() > CONNECT_HEADER_LIMIT {
        return Err("sidecar control response headers exceed the 16 KiB limit".into());
    }
    let response = std::str::from_utf8(&bytes)
        .map_err(|_| "sidecar control response is not valid UTF-8".to_string())?;
    let headers = response
        .split_once("\r\n\r\n")
        .map(|(headers, _)| headers)
        .ok_or_else(|| "sidecar control response is malformed".to_string())?;
    if headers.starts_with("HTTP/1.1 204") || headers.starts_with("HTTP/1.0 204") {
        Ok(())
    } else {
        Err("sidecar control endpoint rejected authenticated request".into())
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/proxy_tests.rs"]
mod tests;
