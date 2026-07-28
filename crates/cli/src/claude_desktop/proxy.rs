// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated CONNECT proxy and exact-host TLS interception for Claude Code traffic.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use base64::Engine;
use bytes::BytesMut;
use futures_util::StreamExt;
use http::header::{
    CONNECTION, CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use reqwest::{Client, NoProxy, Proxy, Url};
use rustls::pki_types::ServerName;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::AGENT_AUTHORIZATION_HEADER;
use super::ENROLLED_AGENT_HEADER;
use super::certificate::{INTERCEPTED_HOST, INTERCEPTED_HOSTS};
use super::settings::UpstreamProxy;
use super::state::DesktopState;

const CONTROL_HOST: &str = "nemo-relay.invalid";
const HEALTH_PATH: &str = "/.nemo-relay/healthz";
const SHUTDOWN_PATH: &str = "/.nemo-relay/shutdown";
const CONNECT_HEADER_LIMIT: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const BODY_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONTROL_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROXY_CONNECTIONS: usize = 256;

pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(crate) type BoxStream = Box<dyn AsyncStream>;
#[derive(Clone)]
enum AuthenticatedRoute {
    Control,
    Agent(String),
}

#[derive(Clone)]
pub(super) struct Runtime {
    state: Arc<DesktopState>,
    tls: Arc<rustls::ServerConfig>,
    agent_routes: Arc<BTreeMap<String, super::AgentRouteContext>>,
    gateway_client: Client,
    gateway_base: String,
    managed: Option<crate::server::ManagedProviderDispatcher>,
    shutdown: watch::Sender<bool>,
    configuration_verifier: Option<super::ConfigurationFence>,
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
    #[cfg(test)]
    pub(super) fn new(
        state: DesktopState,
        tls: Arc<rustls::ServerConfig>,
        shutdown: watch::Sender<bool>,
    ) -> Result<Self, String> {
        Self::new_with_gateway(
            state,
            tls,
            shutdown,
            crate::bootstrap::LEGACY_FIXED_URL.into(),
        )
    }

    fn new_with_gateway(
        state: DesktopState,
        tls: Arc<rustls::ServerConfig>,
        shutdown: watch::Sender<bool>,
        gateway_base: String,
    ) -> Result<Self, String> {
        let agent_routes = state
            .enrollments
            .iter()
            .map(|(agent, enrollment)| {
                // `None` is an explicit direct route for this enrollment. Never inherit another
                // agent's corporate proxy selection from shared state.
                (
                    agent.clone(),
                    super::AgentRouteContext {
                        agent: agent.clone(),
                        upstream_proxy: enrollment.upstream_proxy.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let gateway_client = Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(REQUEST_IDLE_TIMEOUT)
            .build()
            .map_err(|error| format!("failed to build loopback gateway client: {error}"))?;
        Ok(Self {
            state: Arc::new(state),
            tls,
            agent_routes: Arc::new(agent_routes),
            gateway_client,
            gateway_base,
            managed: None,
            shutdown,
            configuration_verifier: None,
        })
    }

    pub(super) fn new_with_dispatcher(
        state: DesktopState,
        tls: Arc<rustls::ServerConfig>,
        managed: crate::server::ManagedProviderDispatcher,
        shutdown: watch::Sender<bool>,
    ) -> Result<Self, String> {
        let gateway_base = format!("https://{}", state.bind);
        Self::new_with_gateway(state, tls, shutdown, gateway_base).map(|mut runtime| {
            runtime.managed = Some(managed);
            runtime
        })
    }

    pub(super) fn with_configuration_verifier(
        mut self,
        verifier: impl Fn() -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.configuration_verifier = Some(super::ConfigurationFence::new(Arc::new(verifier)));
        self
    }
}

pub(super) fn upstream_client(proxy: Option<&UpstreamProxy>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .read_timeout(REQUEST_IDLE_TIMEOUT);
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
                "coding-agent proxy corporate proxy CA bundle",
            )?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|error| {
                format!(
                    "failed to parse coding-agent proxy corporate proxy CA bundle {}: {error}",
                    path.display()
                )
            })?;
            if certificates.is_empty() {
                return Err(format!(
                    "coding-agent proxy corporate proxy CA bundle {} contains no certificates",
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
        .map_err(|error| format!("failed to build coding-agent proxy upstream client: {error}"))
}

pub(super) async fn serve(listener: TcpListener, runtime: Runtime) -> Result<(), String> {
    serve_with_limits(listener, runtime, MAX_PROXY_CONNECTIONS, IO_TIMEOUT, true).await
}

async fn serve_with_limits(
    listener: TcpListener,
    runtime: Runtime,
    max_connections: usize,
    header_timeout: Duration,
    listener_tls: bool,
) -> Result<(), String> {
    let mut shutdown = runtime.shutdown.subscribe();
    let connections = Arc::new(Semaphore::new(max_connections));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|error| format!("coding-agent proxy proxy accept failed: {error}"))?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    // Do not allocate a task or parse attacker-controlled bytes once the bounded
                    // connection budget is exhausted.
                    drop(stream);
                    continue;
                };
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = if listener_tls {
                        serve_tls_connection_with_header_timeout(stream, runtime, header_timeout)
                            .await
                    } else {
                        serve_http_connection_with_header_timeout(stream, runtime, header_timeout)
                            .await
                    };
                    if let Err(error) = result {
                        log::warn!(
                            target: "nemo_relay.gateway",
                            event = "proxy_connection_failed",
                            error_kind = "transport";
                            "coding-agent proxy proxy connection failed: {error}"
                        );
                    }
                });
            }
        }
    }
}

#[cfg(test)]
async fn serve_plain(listener: TcpListener, runtime: Runtime) -> Result<(), String> {
    serve_with_limits(listener, runtime, MAX_PROXY_CONNECTIONS, IO_TIMEOUT, false).await
}

#[cfg(test)]
async fn serve_connection(stream: TcpStream, runtime: Runtime) -> Result<(), String> {
    serve_http_connection_with_header_timeout(stream, runtime, IO_TIMEOUT).await
}

async fn serve_tls_connection_with_header_timeout(
    stream: TcpStream,
    runtime: Runtime,
    header_timeout: Duration,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(runtime.tls.clone());
    let stream = tokio::time::timeout(header_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| "proxy listener TLS handshake timed out".to_string())?
        .map_err(|error| format!("proxy listener TLS handshake failed: {error}"))?;
    serve_http_connection_with_header_timeout(stream, runtime, header_timeout).await
}

async fn serve_http_connection_with_header_timeout(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    runtime: Runtime,
    header_timeout: Duration,
) -> Result<(), String> {
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout);
    builder
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
    let authenticated = authenticate_state(request.headers(), &runtime.state);
    let response = if matches!(authenticated, Ok(AuthenticatedRoute::Agent(_)))
        && runtime_configuration_error(&runtime).is_some()
    {
        text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "coding-agent proxy configuration changed; reinstall with --force",
        )
    } else if request.method() == Method::CONNECT {
        match authenticated {
            Ok(route @ AuthenticatedRoute::Agent(_)) => {
                connect_request(request, runtime, route).await
            }
            Ok(AuthenticatedRoute::Control) => text_response(
                StatusCode::FORBIDDEN,
                "control credentials cannot open proxy tunnels",
            ),
            Err(()) => proxy_authentication_required(),
        }
    } else if direct_managed_path(request.uri().path()) {
        match authenticated {
            Ok(route @ AuthenticatedRoute::Agent(_))
                if direct_path_allowed(&route, request.uri().path()) =>
            {
                dispatch_direct_request(request, &runtime, route).await
            }
            Ok(AuthenticatedRoute::Agent(_)) => text_response(
                StatusCode::FORBIDDEN,
                "agent credential is not enrolled for this provider route",
            ),
            Ok(AuthenticatedRoute::Control) => text_response(
                StatusCode::FORBIDDEN,
                "control credentials cannot invoke managed providers",
            ),
            Err(()) => proxy_authentication_required(),
        }
    } else if direct_internal_path(request.uri().path()) {
        match authenticated {
            Ok(route @ AuthenticatedRoute::Agent(_))
                if direct_path_allowed(&route, request.uri().path()) =>
            {
                dispatch_direct_request(request, &runtime, route).await
            }
            Ok(AuthenticatedRoute::Agent(_)) => text_response(
                StatusCode::FORBIDDEN,
                "agent credential does not match this hook route",
            ),
            Ok(AuthenticatedRoute::Control) => text_response(
                StatusCode::FORBIDDEN,
                "control credentials cannot deliver lifecycle hooks",
            ),
            Err(()) => proxy_authentication_required(),
        }
    } else {
        match authenticated {
            Ok(AuthenticatedRoute::Control) => control_request(request, &runtime),
            Ok(AuthenticatedRoute::Agent(_)) => text_response(
                StatusCode::FORBIDDEN,
                "agent credentials cannot access proxy control",
            ),
            Err(()) => proxy_authentication_required(),
        }
    };
    Ok(response)
}

fn proxy_authentication_required() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, "Basic realm=\"nemo-relay\"")
        .header(http::header::CONNECTION, "close")
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("proxy authentication response is valid")
}

fn direct_managed_path(path: &str) -> bool {
    matches!(
        path,
        "/responses"
            | "/v1/responses"
            | "/chat/completions"
            | "/v1/chat/completions"
            | "/models"
            | "/v1/models"
            | "/v1/messages"
            | "/v1/messages/count_tokens"
    )
}

fn direct_internal_path(path: &str) -> bool {
    path == "/healthz" || path.starts_with("/hooks/")
}

fn direct_path_allowed(route: &AuthenticatedRoute, path: &str) -> bool {
    let AuthenticatedRoute::Agent(agent) = route else {
        return false;
    };
    match path {
        "/healthz" => true,
        "/models" | "/v1/models" => matches!(agent.as_str(), "codex" | "hermes"),
        "/responses" | "/v1/responses" | "/chat/completions" | "/v1/chat/completions" => {
            matches!(agent.as_str(), "codex" | "hermes")
        }
        "/v1/messages" | "/v1/messages/count_tokens" => {
            matches!(agent.as_str(), "claude" | "hermes")
        }
        "/hooks/codex" => agent == "codex",
        "/hooks/claude-code" => agent == "claude",
        "/hooks/hermes" => agent == "hermes",
        _ => false,
    }
}

async fn dispatch_direct_request(
    request: Request<Incoming>,
    runtime: &Runtime,
    route: AuthenticatedRoute,
) -> Response<Body> {
    let Some(dispatcher) = runtime.managed.as_ref() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed provider engine is unavailable",
        );
    };
    let (mut parts, body) = request.into_parts();
    parts.headers.remove(PROXY_AUTHORIZATION);
    parts.headers.remove(AGENT_AUTHORIZATION_HEADER);
    set_enrolled_hook_identity(&mut parts.headers, parts.uri.path(), &route);
    if let Some(context) = agent_route_context(runtime, &route) {
        parts.extensions.insert(context);
    }
    if let Some(fence) = runtime.configuration_verifier.clone() {
        parts.extensions.insert(fence);
    }
    dispatcher
        .dispatch(Request::from_parts(parts, Body::new(body)))
        .await
}

fn set_enrolled_hook_identity(headers: &mut HeaderMap, path: &str, route: &AuthenticatedRoute) {
    headers.remove(ENROLLED_AGENT_HEADER);
    if path.starts_with("/hooks/")
        && let AuthenticatedRoute::Agent(agent) = route
    {
        headers.insert(
            ENROLLED_AGENT_HEADER,
            agent
                .parse()
                .expect("enrolled agent names are valid HTTP header values"),
        );
    }
}

enum ConnectTarget {
    Intercepted,
    Public(BoxStream),
}

async fn connect_request(
    mut request: Request<Incoming>,
    runtime: Runtime,
    route: AuthenticatedRoute,
) -> Response<Body> {
    let (host, port) = match validate_connect_request(&request)
        .and_then(|_| parse_connect_authority(request.uri()))
    {
        Ok(authority) => authority,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(error) = validate_connect_host(request.headers(), &host, port) {
        return text_response(StatusCode::BAD_REQUEST, error);
    }
    if !agent_allows_intercepted_host(&route, &host) {
        return text_response(
            StatusCode::FORBIDDEN,
            "agent credential is not enrolled for this provider host",
        );
    }
    let target = match prepare_connect_target(
        &host,
        port,
        selected_upstream_proxy(&runtime, &route),
    )
    .await
    {
        Ok(target) => target,
        Err((status, error)) => return text_response(status, error),
    };
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(run_connect_tunnel(
        upgrade, host, port, target, runtime, route,
    ));
    connect_response()
}

fn agent_allows_intercepted_host(route: &AuthenticatedRoute, host: &str) -> bool {
    let AuthenticatedRoute::Agent(agent) = route else {
        return false;
    };
    match agent.as_str() {
        "claude" => host.eq_ignore_ascii_case("api.anthropic.com"),
        "codex" => {
            host.eq_ignore_ascii_case("api.openai.com") || host.eq_ignore_ascii_case("chatgpt.com")
        }
        "hermes" => true,
        _ => false,
    }
}

async fn prepare_connect_target(
    host: &str,
    port: u16,
    upstream_proxy: Option<&UpstreamProxy>,
) -> Result<ConnectTarget, (StatusCode, String)> {
    if port != 443 {
        return Err((
            StatusCode::FORBIDDEN,
            format!("refusing CONNECT to non-TLS port {host}:{port}"),
        ));
    }
    if INTERCEPTED_HOSTS
        .iter()
        .any(|candidate| host.eq_ignore_ascii_case(candidate))
    {
        return Ok(ConnectTarget::Intercepted);
    }
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    let addresses = resolve_public_addresses_before(host, port, deadline)
        .await
        .map_err(|error| {
            let status = if error.starts_with("refusing CONNECT") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_GATEWAY
            };
            (status, error)
        })?;
    let stream = if upstream_proxy
        .is_some_and(|proxy| !no_proxy_matches(proxy.no_proxy.as_deref(), host, port, &addresses))
    {
        connect_through_upstream_proxy_before(
            upstream_proxy.expect("proxy presence was checked"),
            *addresses
                .first()
                .expect("public destination resolution is non-empty"),
            deadline,
        )
        .await
    } else {
        connect_addresses_before(&addresses, deadline)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
    }
    .map_err(|error| (StatusCode::BAD_GATEWAY, error))?;
    Ok(ConnectTarget::Public(stream))
}

async fn run_connect_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    host: String,
    port: u16,
    target: ConnectTarget,
    runtime: Runtime,
    route: AuthenticatedRoute,
) {
    let result = complete_connect_tunnel(upgrade, &host, port, target, &runtime, &route).await;
    if let Err(error) = result {
        log::warn!(
            target: "nemo_relay.gateway",
            event = "connect_tunnel_failed",
            destination = format!("{host}:{port}").as_str(),
            error_kind = "transport";
            "coding-agent proxy CONNECT tunnel failed: {error}"
        );
    }
}

async fn complete_connect_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    host: &str,
    port: u16,
    target: ConnectTarget,
    runtime: &Runtime,
    route: &AuthenticatedRoute,
) -> Result<(), String> {
    let upgraded = upgrade
        .await
        .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
    match target {
        ConnectTarget::Intercepted => {
            inspect_provider(upgraded, host, runtime.clone(), route.clone()).await
        }
        ConnectTarget::Public(stream) => tunnel_public(upgraded, host, port, stream).await,
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
            if let Some(verifier) = runtime.configuration_verifier.as_ref()
                && verifier.verify().is_err()
            {
                log::error!(
                    target: "nemo_relay.gateway",
                    event = "desktop_configuration_changed",
                    error_kind = "configuration";
                    "coding-agent proxy configuration changed"
                );
                return text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "coding-agent proxy Relay configuration changed",
                );
            }
            let health = Health {
                service: "nemo-relay-agent-proxy".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                generation: runtime.state.generation.clone(),
                configuration_fingerprint: runtime.state.configuration_fingerprint.clone(),
                gateway_url: format!("https://{}", runtime.state.bind),
                proxy_url: format!("https://{}", runtime.state.bind),
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

async fn inspect_provider(
    upgraded: hyper::upgrade::Upgraded,
    connect_host: &str,
    runtime: Runtime,
    route: AuthenticatedRoute,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(runtime.tls.clone());
    let tls = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(TokioIo::new(upgraded)))
        .await
        .map_err(|_| "TLS handshake with coding agent timed out".to_string())?
        .map_err(|error| format!("TLS handshake with coding agent failed: {error}"))?;
    let server_name = tls
        .get_ref()
        .1
        .server_name()
        .ok_or_else(|| "coding agent did not present TLS SNI".to_string())?;
    if !server_name.eq_ignore_ascii_case(connect_host)
        || !INTERCEPTED_HOSTS
            .iter()
            .any(|candidate| server_name.eq_ignore_ascii_case(candidate))
    {
        return Err(format!(
            "refusing TLS SNI {server_name:?} for CONNECT destination {connect_host:?}"
        ));
    }
    let provider_host = connect_host.to_string();
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(IO_TIMEOUT);
    builder
        .serve_connection(
            TokioIo::new(tls),
            service_fn(move |request| {
                handle_provider_request(
                    request,
                    provider_host.clone(),
                    runtime.clone(),
                    route.clone(),
                )
            }),
        )
        .with_upgrades()
        .await
        .map_err(|error| format!("intercepted provider HTTP connection failed: {error}"))
}

async fn handle_provider_request(
    mut request: Request<Incoming>,
    provider_host: String,
    runtime: Runtime,
    route: AuthenticatedRoute,
) -> Result<Response<Body>, std::convert::Infallible> {
    // Enrollment credentials authenticate only the local proxy. Strip both possible proxy-auth
    // forms before route classification so managed, control, and rejected paths can never forward
    // them to a provider.
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    request.headers_mut().remove(AGENT_AUTHORIZATION_HEADER);
    let response = match runtime_configuration_error(&runtime) {
        Some(_) => text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "coding-agent proxy configuration changed; reinstall with --force",
        ),
        None => match validate_provider_host(request.headers(), &provider_host) {
            Err(error) => text_response(StatusCode::MISDIRECTED_REQUEST, error),
            Ok(()) => {
                match classify_provider_route(
                    &provider_host,
                    request.method(),
                    request.uri().path(),
                ) {
                    Route::Managed => {
                        if provider_host.eq_ignore_ascii_case("chatgpt.com")
                            && let Err(error) = normalize_chatgpt_managed_uri(request.uri_mut())
                        {
                            return Ok(text_response(StatusCode::BAD_REQUEST, error));
                        }
                        managed_request(request, &runtime, &route).await
                    }
                    Route::Control => match agent_route_context(&runtime, &route) {
                        Some(context) => {
                            forward_provider_control(
                                request,
                                &context,
                                &format!("https://{provider_host}"),
                            )
                            .await
                        }
                        None => text_response(
                            StatusCode::FORBIDDEN,
                            "control credentials cannot forward provider requests",
                        ),
                    },
                    Route::Rejected(reason) => text_response(StatusCode::FORBIDDEN, reason),
                }
            }
        },
    };
    Ok(response)
}

fn runtime_configuration_error(runtime: &Runtime) -> Option<String> {
    runtime
        .configuration_verifier
        .as_ref()
        .and_then(|fence| fence.verify().err())
}

fn classify_provider_route(host: &str, method: &Method, path: &str) -> Route {
    if host.eq_ignore_ascii_case(INTERCEPTED_HOST) {
        return classify_route(method, path);
    }
    if !provider_path_is_canonical(path) {
        return Route::Rejected("provider path is not in canonical absolute form");
    }
    if host.eq_ignore_ascii_case("api.openai.com") {
        return match path {
            "/responses" | "/v1/responses" | "/chat/completions" | "/v1/chat/completions"
                if method == Method::POST =>
            {
                Route::Managed
            }
            "/models" | "/v1/models" if method == Method::GET => Route::Managed,
            "/responses"
            | "/v1/responses"
            | "/chat/completions"
            | "/v1/chat/completions"
            | "/models"
            | "/v1/models" => Route::Rejected("managed OpenAI route uses an unsupported method"),
            path if path.starts_with("/v1/") => {
                Route::Rejected("unknown OpenAI /v1 route is fail-closed")
            }
            _ => Route::Rejected("OpenAI endpoint is not on the audited route allowlist"),
        };
    }
    if host.eq_ignore_ascii_case("chatgpt.com") {
        return match path {
            "/backend-api/codex/responses" | "/backend-api/codex/v1/responses"
                if method == Method::POST =>
            {
                Route::Managed
            }
            "/backend-api/codex/models" if method == Method::GET => Route::Managed,
            path if path.starts_with("/backend-api/codex/") => {
                Route::Rejected("unknown ChatGPT Codex inference route is fail-closed")
            }
            "/api/auth/session" | "/backend-api/accounts/check" if method == Method::GET => {
                Route::Control
            }
            _ => Route::Rejected("ChatGPT endpoint is not on the audited route allowlist"),
        };
    }
    Route::Rejected("provider host is not enrolled")
}

fn normalize_chatgpt_managed_uri(uri: &mut http::Uri) -> Result<(), String> {
    let normalized = match uri.path() {
        "/backend-api/codex/responses" | "/backend-api/codex/v1/responses" => "/responses",
        "/backend-api/codex/models" => "/models",
        _ => return Ok(()),
    };
    let path_and_query = uri.query().map_or_else(
        || normalized.to_string(),
        |query| format!("{normalized}?{query}"),
    );
    *uri = path_and_query
        .parse()
        .map_err(|error| format!("failed to normalize ChatGPT Codex request URI: {error}"))?;
    Ok(())
}

fn agent_route_context(
    runtime: &Runtime,
    route: &AuthenticatedRoute,
) -> Option<super::AgentRouteContext> {
    let AuthenticatedRoute::Agent(agent) = route else {
        return None;
    };
    runtime.agent_routes.get(agent).cloned()
}

fn selected_upstream_proxy<'a>(
    runtime: &'a Runtime,
    route: &AuthenticatedRoute,
) -> Option<&'a UpstreamProxy> {
    let AuthenticatedRoute::Agent(agent) = route else {
        return None;
    };
    runtime
        .agent_routes
        .get(agent)
        .and_then(|context| context.upstream_proxy.as_ref())
}

async fn managed_request(
    request: Request<Incoming>,
    runtime: &Runtime,
    route: &AuthenticatedRoute,
) -> Response<Body> {
    let (mut parts, body) = request.into_parts();
    parts.headers.remove(PROXY_AUTHORIZATION);
    parts.headers.remove(AGENT_AUTHORIZATION_HEADER);
    parts.headers.remove(ENROLLED_AGENT_HEADER);
    let Some(dispatcher) = runtime.managed.as_ref() else {
        return forward(
            Request::from_parts(parts, body),
            &runtime.gateway_client,
            &runtime.gateway_base,
        )
        .await;
    };
    if let Some(context) = agent_route_context(runtime, route) {
        parts.extensions.insert(context);
    }
    if let Some(fence) = runtime.configuration_verifier.clone() {
        parts.extensions.insert(fence);
    }
    dispatcher
        .dispatch(Request::from_parts(parts, Body::new(body)))
        .await
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
    let body = match collect_incoming_body(body, body_limit, BODY_ACTIVITY_TIMEOUT).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge) => {
            return text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds the {body_limit}-byte Relay limit"),
            );
        }
        Err(BodyReadError::Idle) => {
            return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
        Err(BodyReadError::Transport) => {
            return text_response(StatusCode::BAD_REQUEST, "request body could not be read");
        }
    };
    let mut upstream = client.request(parts.method, url).body(body);
    for (name, value) in &parts.headers {
        if should_forward_header(name, &parts.headers) {
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
                "coding-agent proxy intercepted request failed: {error}"
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
        if should_forward_header(name, &headers) {
            output = output.header(name, value);
        }
    }
    output
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
}

async fn forward_provider_control(
    request: Request<Incoming>,
    route: &super::AgentRouteContext,
    base: &str,
) -> Response<Body> {
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
    let url = format!("{base}{path}");
    let body = match collect_incoming_body(body, body_limit, BODY_ACTIVITY_TIMEOUT).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge) => {
            return text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds the {body_limit}-byte Relay limit"),
            );
        }
        Err(BodyReadError::Idle) => {
            return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
        Err(BodyReadError::Transport) => {
            return text_response(StatusCode::BAD_REQUEST, "request body could not be read");
        }
    };
    let mut upstream = match Request::builder()
        .method(parts.method)
        .uri(url)
        .body(Body::from(body))
    {
        Ok(request) => request,
        Err(_) => return empty_response(StatusCode::BAD_GATEWAY),
    };
    for (name, value) in &parts.headers {
        if should_forward_header(name, &parts.headers) {
            upstream.headers_mut().append(name, value.clone());
        }
    }
    match super::send_provider_http(route, upstream).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            if content_length_exceeds(&parts.headers, MAX_CONTROL_RESPONSE_BODY_BYTES) {
                return text_response(
                    StatusCode::BAD_GATEWAY,
                    "provider control response exceeds the Relay limit",
                );
            }
            let body = match collect_incoming_body(
                body,
                MAX_CONTROL_RESPONSE_BODY_BYTES,
                BODY_ACTIVITY_TIMEOUT,
            )
            .await
            {
                Ok(body) => body,
                Err(_) => {
                    return text_response(
                        StatusCode::BAD_GATEWAY,
                        "provider control response could not be read within Relay limits",
                    );
                }
            };
            let mut downstream = Response::builder().status(parts.status);
            for (name, value) in &parts.headers {
                if should_forward_header(name, &parts.headers) {
                    downstream = downstream.header(name, value);
                }
            }
            downstream
                .body(Body::from(body))
                .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
        }
        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyReadError {
    TooLarge,
    Idle,
    Transport,
}

async fn collect_incoming_body(
    body: Incoming,
    limit: usize,
    activity_timeout: Duration,
) -> Result<Bytes, BodyReadError> {
    let mut stream = body.into_data_stream();
    let mut output = BytesMut::new();
    loop {
        let chunk = tokio::time::timeout(activity_timeout, stream.next())
            .await
            .map_err(|_| BodyReadError::Idle)?;
        let Some(chunk) = chunk else {
            return Ok(output.freeze());
        };
        let chunk = chunk.map_err(|_| BodyReadError::Transport)?;
        if output.len().saturating_add(chunk.len()) > limit {
            return Err(BodyReadError::TooLarge);
        }
        output.extend_from_slice(&chunk);
    }
}

fn content_length_exceeds(headers: &HeaderMap, limit: usize) -> bool {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Managed,
    Control,
    Rejected(&'static str),
}

fn classify_route(method: &Method, path: &str) -> Route {
    if !provider_path_is_canonical(path) {
        return Route::Rejected("provider path is not in canonical absolute form");
    }
    classify_canonical_anthropic_route(method, path)
}

fn classify_canonical_anthropic_route(method: &Method, path: &str) -> Route {
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

fn provider_path_is_canonical(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\\') || !has_valid_percent_encoding(path) {
        return false;
    }
    let Ok(decoded) = percent_decode_str(path).decode_utf8() else {
        return false;
    };
    let decoded = decoded.as_ref();
    if decoded.contains('\\')
        || decoded.contains("//")
        || decoded.matches('/').count() != path.matches('/').count()
    {
        return false;
    }
    !decoded
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
}

fn has_valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
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
    mut remote: BoxStream,
) -> Result<(), String> {
    let mut client = TokioIo::new(upgraded);
    copy_bidirectional_with_idle_timeout(&mut client, &mut remote, REQUEST_IDLE_TIMEOUT)
        .await
        .map_err(|error| format!("CONNECT tunnel to {host}:{port} failed: {error}"))?;
    Ok(())
}

struct ActivityStream<T> {
    inner: T,
    activity: watch::Sender<tokio::time::Instant>,
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let previous = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > previous {
            self.activity.send_replace(tokio::time::Instant::now());
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, bytes);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            self.activity.send_replace(tokio::time::Instant::now());
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
    first: &mut A,
    second: &mut B,
    idle_timeout: Duration,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (activity_tx, mut activity_rx) = watch::channel(tokio::time::Instant::now());
    let mut first = ActivityStream {
        inner: first,
        activity: activity_tx.clone(),
    };
    let mut second = ActivityStream {
        inner: second,
        activity: activity_tx,
    };
    let copy = tokio::io::copy_bidirectional(&mut first, &mut second);
    tokio::pin!(copy);
    loop {
        let deadline = *activity_rx.borrow_and_update() + idle_timeout;
        tokio::select! {
            result = &mut copy => return result,
            changed = activity_rx.changed() => {
                if changed.is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "CONNECT tunnel activity channel closed",
                    ));
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                if tokio::time::Instant::now().duration_since(*activity_rx.borrow()) >= idle_timeout {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "CONNECT tunnel was idle",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
async fn resolve_public_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    resolve_public_addresses_before(host, port, tokio::time::Instant::now() + IO_TIMEOUT).await
}

async fn resolve_public_addresses_before(
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<Vec<SocketAddr>, String> {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err("refusing CONNECT to a local hostname".into());
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err("refusing CONNECT to an IP-literal destination".into());
    }
    let addresses = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| format!("DNS resolution for {host} timed out"))?
        .map_err(|error| format!("failed to resolve {host}: {error}"))?
        .collect::<Vec<_>>();
    validate_public_addresses(host, &addresses)?;
    Ok(addresses)
}

fn validate_public_addresses(host: &str, addresses: &[SocketAddr]) -> Result<(), String> {
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(format!(
            "refusing CONNECT to {host}: resolution included a private, loopback, link-local, multicast, or unspecified address"
        ));
    }
    Ok(())
}

#[cfg(test)]
async fn connect_addresses(addresses: &[SocketAddr]) -> Result<TcpStream, String> {
    connect_addresses_before(addresses, tokio::time::Instant::now() + IO_TIMEOUT).await
}

async fn connect_addresses_before(
    addresses: &[SocketAddr],
    deadline: tokio::time::Instant,
) -> Result<TcpStream, String> {
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout_at(deadline, TcpStream::connect(address)).await {
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

#[cfg(any(test, feature = "internal-test-server"))]
pub(crate) async fn connect_through_upstream_proxy(
    proxy: &UpstreamProxy,
    destination: SocketAddr,
) -> Result<BoxStream, String> {
    connect_through_upstream_proxy_before(
        proxy,
        destination,
        tokio::time::Instant::now() + IO_TIMEOUT,
    )
    .await
}

async fn connect_through_upstream_proxy_before(
    proxy: &UpstreamProxy,
    destination: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<BoxStream, String> {
    let (url, auth) = proxy_url_and_auth(&proxy.url)?;
    let proxy_host = url
        .host_str()
        .ok_or_else(|| "corporate proxy URL has no host".to_string())?;
    let proxy_port = url
        .port_or_known_default()
        .ok_or_else(|| "corporate proxy URL has no port".to_string())?;
    let tcp = tokio::time::timeout_at(deadline, TcpStream::connect((proxy_host, proxy_port)))
        .await
        .map_err(|_| "corporate proxy connection timed out".to_string())?
        .map_err(|error| format!("failed to connect to corporate proxy: {error}"))?;
    let mut stream: BoxStream = if url.scheme() == "https" {
        Box::new(
            connect_tls_to_proxy_before(tcp, proxy_host, proxy.ca_bundle.as_deref(), deadline)
                .await?,
        )
    } else {
        Box::new(tcp)
    };
    // Pin the CONNECT authority to the already validated public address. TLS still authenticates
    // the original provider hostname after the tunnel opens, but a corporate proxy cannot
    // re-resolve that hostname to a private destination between validation and use.
    let authority = destination.to_string();
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some((username, password)) = auth {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    tokio::time::timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "corporate proxy CONNECT write timed out".to_string())?
        .map_err(|error| format!("corporate proxy CONNECT write failed: {error}"))?;
    let response = read_headers_before(&mut stream, deadline).await?;
    let status = upstream_connect_status(&response)?;
    if status != 200 {
        return Err(format!(
            "corporate proxy rejected CONNECT to validated destination {authority} with HTTP {status}"
        ));
    }
    Ok(stream)
}

pub(crate) async fn connect_provider_tls(
    proxy: Option<&UpstreamProxy>,
    host: &str,
    port: u16,
) -> Result<BoxStream, String> {
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    let addresses = resolve_public_addresses_before(host, port, deadline).await?;
    connect_provider_tls_to_addresses(proxy, host, port, &addresses, deadline).await
}

#[cfg(test)]
pub(crate) async fn connect_test_provider_tls_to_addresses(
    proxy: Option<&UpstreamProxy>,
    host: &str,
    port: u16,
    addresses: &[SocketAddr],
) -> Result<BoxStream, String> {
    connect_provider_tls_to_addresses(
        proxy,
        host,
        port,
        addresses,
        tokio::time::Instant::now() + IO_TIMEOUT,
    )
    .await
}

async fn connect_provider_tls_to_addresses(
    proxy: Option<&UpstreamProxy>,
    host: &str,
    port: u16,
    addresses: &[SocketAddr],
    deadline: tokio::time::Instant,
) -> Result<BoxStream, String> {
    if addresses.is_empty() {
        return Err("provider address resolution returned no destinations".into());
    }
    let stream = if proxy
        .is_some_and(|proxy| !no_proxy_matches(proxy.no_proxy.as_deref(), host, port, addresses))
    {
        connect_through_upstream_proxy_before(
            proxy.expect("proxy presence was checked"),
            *addresses
                .first()
                .expect("public destination resolution is non-empty"),
            deadline,
        )
        .await?
    } else {
        Box::new(connect_addresses_before(addresses, deadline).await?) as BoxStream
    };
    connect_tls_to_host_before(
        stream,
        host,
        proxy.and_then(|proxy| proxy.ca_bundle.as_deref()),
        deadline,
    )
    .await
    .map(|stream| Box::new(stream) as BoxStream)
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

async fn connect_tls_to_proxy_before(
    stream: TcpStream,
    host: &str,
    ca_bundle: Option<&std::path::Path>,
    deadline: tokio::time::Instant,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (mut added, mut ignored) = roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_bundle {
        let pem = crate::filesystem::bounded::read_bounded_regular_file(
            path,
            "coding-agent proxy corporate proxy CA bundle",
        )?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "failed to parse coding-agent proxy corporate proxy CA bundle {}: {error}",
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
    tokio::time::timeout_at(
        deadline,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| "TLS handshake with corporate proxy timed out".to_string())?
    .map_err(|error| format!("TLS handshake with corporate proxy failed: {error}"))
}

async fn connect_tls_to_host_before(
    stream: BoxStream,
    host: &str,
    ca_bundle: Option<&std::path::Path>,
    deadline: tokio::time::Instant,
) -> Result<tokio_rustls::client::TlsStream<BoxStream>, String> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (mut added, mut ignored) = roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_bundle {
        let pem = crate::filesystem::bounded::read_bounded_regular_file(
            path,
            "coding-agent corporate proxy CA bundle",
        )?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "failed to parse corporate proxy CA bundle {}: {error}",
                    path.display()
                )
            })?;
        let (custom_added, custom_ignored) = roots.add_parsable_certificates(certificates);
        added += custom_added;
        ignored += custom_ignored;
    }
    if added == 0 {
        return Err(format!(
            "no trusted root certificates were available for provider TLS ({ignored} invalid entries)"
        ));
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| "provider host is not a valid TLS server name".to_string())?;
    tokio::time::timeout_at(
        deadline,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| "TLS handshake with provider timed out".to_string())?
    .map_err(|error| format!("TLS handshake with provider failed: {error}"))
}

#[cfg(test)]
async fn read_headers(stream: &mut BoxStream) -> Result<String, String> {
    read_headers_before(stream, tokio::time::Instant::now() + IO_TIMEOUT).await
}

async fn read_headers_before(
    stream: &mut BoxStream,
    deadline: tokio::time::Instant,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() < CONNECT_HEADER_LIMIT {
        let count = tokio::time::timeout_at(deadline, stream.read(&mut byte))
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

#[cfg(test)]
fn authenticate(headers: &HeaderMap, username: &str, token: &str) -> Result<(), ()> {
    authenticate_presented(headers, |presented| {
        let expected = format!("{username}:{token}");
        bool::from(presented.ct_eq(expected.as_bytes()))
    })
}

fn authenticate_state(headers: &HeaderMap, state: &DesktopState) -> Result<AuthenticatedRoute, ()> {
    authenticate_state_with(headers, state, |presented, expected| {
        bool::from(presented.ct_eq(expected))
    })
}

fn authenticate_state_with(
    headers: &HeaderMap,
    state: &DesktopState,
    mut compare: impl FnMut(&[u8], &[u8]) -> bool,
) -> Result<AuthenticatedRoute, ()> {
    let presented = presented_credential(headers)?;
    let control = format!("{}:{}", state.proxy_username, state.proxy_token);
    let control_match = compare(&presented, control.as_bytes());
    let enrollment_matches = state
        .enrollments
        .iter()
        .map(|(agent, enrollment)| {
            let expected = format!("{}:{}", enrollment.username, enrollment.token);
            (agent.clone(), compare(&presented, expected.as_bytes()))
        })
        .collect::<Vec<_>>();
    if control_match {
        return Ok(AuthenticatedRoute::Control);
    }
    enrollment_matches
        .into_iter()
        .find_map(|(agent, matched)| matched.then_some(AuthenticatedRoute::Agent(agent)))
        .ok_or(())
}

#[cfg(test)]
fn authenticate_presented(
    headers: &HeaderMap,
    accepts: impl FnOnce(&[u8]) -> bool,
) -> Result<(), ()> {
    let presented = presented_credential(headers)?;
    if accepts(&presented) { Ok(()) } else { Err(()) }
}

fn presented_credential(headers: &HeaderMap) -> Result<Vec<u8>, ()> {
    let proxy_values = headers
        .get_all(PROXY_AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    let direct_values = headers
        .get_all(AGENT_AUTHORIZATION_HEADER)
        .iter()
        .collect::<Vec<_>>();
    let values = if proxy_values.is_empty() {
        direct_values
    } else if direct_values.is_empty() {
        proxy_values
    } else {
        return Err(());
    };
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
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ())
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

#[cfg(test)]
fn validate_anthropic_host(headers: &HeaderMap) -> Result<(), String> {
    validate_provider_host(headers, INTERCEPTED_HOST)
}

fn validate_provider_host(headers: &HeaderMap, expected_host: &str) -> Result<(), String> {
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
    if host.eq_ignore_ascii_case(expected_host) {
        Ok(())
    } else {
        Err(format!(
            "refusing intercepted request for Host {host:?}; CONNECT destination was {expected_host:?}"
        ))
    }
}

fn should_forward_header(name: &http::HeaderName, headers: &HeaderMap) -> bool {
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
    ) && !matches!(
        name.as_str(),
        "keep-alive" | "proxy-connection" | AGENT_AUTHORIZATION_HEADER
    ) && !named_by_connection_header(name, headers)
}

fn named_by_connection_header(name: &http::HeaderName, headers: &HeaderMap) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name.as_str()))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip.octets()),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ipv4(mapped.octets());
            }
            let value = u128::from(ip);
            // Accept only currently allocated global-unicast space. A denylist alone is unsafe
            // because newly reserved top-level ranges (for example 0400::/6) would otherwise
            // become CONNECT destinations until Relay learned about them.
            in_ipv6_prefix(value, 0x2000_u128 << 112, 3)
                && ![
                    (0x2001_u128 << 112, 23),     // IETF protocol assignments
                    (0x2001_0db8_u128 << 96, 32), // documentation
                    (0x2002_u128 << 112, 16),     // 6to4 can encode private IPv4
                    (0x3fff_u128 << 112, 20),     // documentation
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
            | (192, 88, 99)
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
    if entry.parse::<IpAddr>().is_ok() {
        return (entry, None);
    }
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
    control_health(state, timeout)
}

fn control_health(state: &DesktopState, timeout: Duration) -> Result<Health, String> {
    let deadline = Instant::now() + timeout;
    let mut stream = connect_listener_tls(state, deadline)?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", state.proxy_username, state.proxy_token));
    let request = format!(
        "GET http://{CONTROL_HOST}{HEALTH_PATH} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nProxy-Authorization: Basic {encoded}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to send proxy health request: {error}"))?;
    let bytes = read_sync_response_before(&mut stream, 64 * 1024, deadline)
        .map_err(|error| format!("failed to read proxy health response: {error}"))?;
    parse_health_response(state, bytes)
}

fn parse_health_response(state: &DesktopState, bytes: Vec<u8>) -> Result<Health, String> {
    let response = String::from_utf8(bytes)
        .map_err(|_| "proxy health response is not valid UTF-8".to_string())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "proxy health response is malformed".to_string())?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err("proxy health endpoint rejected authenticated request".into());
    }
    let health = serde_json::from_str::<Health>(body)
        .map_err(|error| format!("invalid proxy health response: {error}"))?;
    if health.service != "nemo-relay-agent-proxy"
        || health.version != state.relay_version
        || health.generation != state.generation
        || health.configuration_fingerprint != state.configuration_fingerprint
        || health.gateway_url != format!("https://{}", state.bind)
        || health.proxy_url != format!("https://{}", state.bind)
    {
        return Err("proxy health identity does not match installed state".into());
    }
    Ok(health)
}

pub(super) fn shutdown(state: &DesktopState, timeout: Duration) -> Result<(), String> {
    control_post(state, SHUTDOWN_PATH, timeout)
}

fn control_post(state: &DesktopState, path: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut stream = connect_listener_tls(state, deadline)?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", state.proxy_username, state.proxy_token));
    let request = format!(
        "POST http://{CONTROL_HOST}{path} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nProxy-Authorization: Basic {encoded}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to send proxy control request: {error}"))?;
    let bytes = read_sync_response_before(&mut stream, CONNECT_HEADER_LIMIT + 1, deadline)
        .map_err(|error| format!("failed to read proxy control response: {error}"))?;
    validate_control_response(&mut std::io::Cursor::new(bytes))
}

type ListenerTlsStream = StreamOwned<ClientConnection, std::net::TcpStream>;

fn connect_listener_tls(
    state: &DesktopState,
    deadline: Instant,
) -> Result<ListenerTlsStream, String> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "coding-agent proxy listener deadline expired".to_string())?;
    let stream = std::net::TcpStream::connect_timeout(&state.bind, timeout)
        .map_err(|error| format!("coding-agent proxy is unavailable: {error}"))?;
    set_sync_socket_deadline(&stream, deadline)
        .map_err(|error| format!("failed to configure proxy listener timeout: {error}"))?;
    let name = ServerName::try_from(state.bind.ip().to_string())
        .map_err(|error| format!("invalid coding-agent proxy listener identity: {error}"))?;
    let connection =
        ClientConnection::new(super::certificate::client_config(&state.certificate)?, name)
            .map_err(|error| format!("failed to configure proxy listener TLS: {error}"))?;
    let mut stream = StreamOwned::new(connection, stream);
    stream.conn.complete_io(&mut stream.sock).map_err(|error| {
        format!("coding-agent proxy listener TLS authentication failed: {error}")
    })?;
    Ok(stream)
}

fn set_sync_socket_deadline(
    stream: &std::net::TcpStream,
    deadline: Instant,
) -> std::io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline expired"))?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))
}

fn read_sync_response_before(
    stream: &mut ListenerTlsStream,
    limit: usize,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        set_sync_socket_deadline(&stream.sock, deadline)?;
        let read_limit = buffer.len().min(limit + 1 - bytes.len());
        let count = stream.read(&mut buffer[..read_limit])?;
        if count == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > limit {
            return Ok(bytes);
        }
    }
}

fn validate_control_response(stream: &mut impl Read) -> Result<(), String> {
    let mut bytes = Vec::new();
    stream
        .take((CONNECT_HEADER_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read proxy control response: {error}"))?;
    if bytes.len() > CONNECT_HEADER_LIMIT {
        return Err("proxy control response headers exceed the 16 KiB limit".into());
    }
    let response = std::str::from_utf8(&bytes)
        .map_err(|_| "proxy control response is not valid UTF-8".to_string())?;
    let headers = response
        .split_once("\r\n\r\n")
        .map(|(headers, _)| headers)
        .ok_or_else(|| "proxy control response is malformed".to_string())?;
    if headers.starts_with("HTTP/1.1 204") || headers.starts_with("HTTP/1.0 204") {
        Ok(())
    } else {
        Err("proxy control endpoint rejected authenticated request".into())
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/proxy_tests.rs"]
mod tests;
