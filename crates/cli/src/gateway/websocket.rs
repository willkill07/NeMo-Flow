// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Managed OpenAI Responses WebSocket transport for Codex.

#![deny(clippy::cognitive_complexity)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_stream::stream;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use futures_util::Stream;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use nemo_relay::api::llm::{LlmRequest, LlmStreamCallExecuteParams, llm_stream_call_execute};
use nemo_relay::api::runtime::{LlmJsonStream, LlmStreamExecutionNextFn, TASK_SCOPE_STACK};
use nemo_relay::codec::resolve::{ProviderSurface, response_codec, streaming_codec};
use nemo_relay::error::FlowError;
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::request::{ManagedRequestTransport, build_llm_gateway_start, prepare_gateway_request};
use super::routes::ProviderRoute;
use super::{GatewayRequestCodec, build_request_codec};
use crate::server::AppState;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_WRITE_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUEUED_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUEUED_EVENT_FRAMES: usize = 32;
const MAX_CONCURRENT_SOCKETS: usize = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_HANDSHAKE_HEADERS: &[&str] = &[
    "openai-model",
    "x-codex-turn-state",
    "x-models-etag",
    "x-reasoning-included",
    "x-request-id",
];

static SOCKETS: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(crate) async fn upgrade(
    State(state): State<AppState>,
    route: Option<Extension<crate::claude_desktop::AgentRouteContext>>,
    fence: Option<Extension<crate::claude_desktop::ConfigurationFence>>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    let sockets = SOCKETS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_SOCKETS)))
        .clone();
    let Ok(permit) = acquire_socket(sockets) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "coding-agent proxy WebSocket capacity is exhausted",
        )
            .into_response();
    };
    let mut provider_headers = headers;
    let authorization = match state.authorize_provider_request(&mut provider_headers) {
        Ok(authorization) => authorization,
        Err(error) => return error.into_response(),
    };
    let route = route.map(|Extension(route)| route);
    let fence = fence.map(|Extension(fence)| fence);
    let upstream = match tokio::time::timeout(
        UPSTREAM_HANDSHAKE_TIMEOUT,
        connect_upstream(
            &state,
            &provider_headers,
            authorization,
            route.as_ref(),
            ProviderRoute::OpenAiResponses,
            None,
        ),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(error)) => {
            return (
                StatusCode::BAD_GATEWAY,
                compatibility_error(&format!("upstream WebSocket handshake failed: {error}")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                compatibility_error("upstream WebSocket handshake timed out"),
            )
                .into_response();
        }
    };
    let (upstream, upstream_response) = upstream;
    let (upstream_write, upstream_read) = upstream.split();
    let upstream = PersistentUpstream::new(
        upstream_write,
        upstream_read,
        reconnect_upstream_factory(
            state.clone(),
            provider_headers.clone(),
            authorization,
            route.clone(),
        ),
    );
    let mut response = websocket
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let context = SocketContext {
                state,
                provider_headers,
                authorization,
                route,
                fence,
                upstream,
            };
            if let Err(error) = serve_socket(socket, context).await {
                log::warn!(
                    target: "nemo_relay.gateway",
                    event = "responses_websocket_failed",
                    error_kind = "transport";
                    "Managed Responses WebSocket failed: {error}"
                );
            }
        });
    forward_upstream_handshake_headers(upstream_response.headers(), response.headers_mut());
    response
}

fn acquire_socket(
    sockets: Arc<Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
    sockets.try_acquire_owned()
}

struct SocketContext {
    state: AppState,
    provider_headers: HeaderMap,
    authorization: crate::provider_auth::ProviderRequestAuthorization,
    route: Option<crate::claude_desktop::AgentRouteContext>,
    fence: Option<crate::claude_desktop::ConfigurationFence>,
    upstream: PersistentUpstream,
}

async fn serve_socket(client: WebSocket, context: SocketContext) -> Result<(), String> {
    let (client_write, mut client_read) = client.split();
    let client_write = Arc::new(AsyncMutex::new(client_write));
    let result = serve_socket_loop(&mut client_read, &client_write, &context).await;
    forward_client_close(&context.upstream.write, None).await;
    result
}

async fn serve_socket_loop(
    client_read: &mut ClientRead,
    client_write: &Arc<AsyncMutex<ClientWrite>>,
    context: &SocketContext,
) -> Result<(), String> {
    loop {
        let message =
            match receive_idle_message(client_read, client_write, &context.upstream.read).await? {
                IdleInput::Client(message) => message,
                IdleInput::Continue => continue,
                IdleInput::Closed => return Ok(()),
            };
        match message {
            Message::Text(text) => {
                let request = match decode_response_create(&text) {
                    Ok(request) => request,
                    Err(error) => {
                        close(client_write, close_code::INVALID, &error).await;
                        return Ok(());
                    }
                };
                if let Some(fence) = context.fence.as_ref()
                    && fence.verify().is_err()
                {
                    let error = "coding-agent proxy configuration changed; reinstall with --force";
                    close(client_write, close_code::POLICY, error).await;
                    return Err(error.into());
                }
                let result = run_managed_response(
                    client_read,
                    client_write.clone(),
                    &context.state,
                    &context.provider_headers,
                    context.authorization,
                    request,
                    context.route.clone(),
                    context.upstream.clone(),
                )
                .await;
                match result {
                    Ok(ActiveResponseState::Completed) => {}
                    Ok(ActiveResponseState::ClientClosed) => return Ok(()),
                    Err(error) => {
                        close(client_write, close_code::ERROR, &error).await;
                        return Err(error);
                    }
                }
            }
            Message::Ping(payload) => {
                send_upstream_control(
                    &context.upstream.write,
                    tokio_tungstenite::tungstenite::Message::Ping(payload),
                    "ping",
                )
                .await?;
            }
            Message::Pong(payload) => {
                send_upstream_control(
                    &context.upstream.write,
                    tokio_tungstenite::tungstenite::Message::Pong(payload),
                    "pong",
                )
                .await?;
            }
            Message::Close(_) => return Ok(()),
            Message::Binary(_) => {
                close(
                    client_write,
                    close_code::UNSUPPORTED,
                    "Responses WebSocket accepts text JSON frames only",
                )
                .await;
                return Ok(());
            }
        };
    }
}

fn forward_upstream_handshake_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for name in UPSTREAM_HANDSHAKE_HEADERS {
        for value in source.get_all(*name) {
            target.append(*name, value.clone());
        }
    }
}

enum IdleInput {
    Client(Message),
    Continue,
    Closed,
}

async fn receive_idle_message(
    client_read: &mut ClientRead,
    client_write: &Arc<AsyncMutex<ClientWrite>>,
    upstream_read: &Arc<AsyncMutex<UpstreamRead>>,
) -> Result<IdleInput, String> {
    tokio::select! {
        message = client_read.next() => match message {
            Some(Ok(message)) => Ok(IdleInput::Client(message)),
            Some(Err(error)) => Err(format!("client WebSocket read failed: {error}")),
            None => Ok(IdleInput::Closed),
        },
        message = receive_upstream_idle(upstream_read) => {
            handle_idle_upstream_message(message, client_write).await
        }
        () = tokio::time::sleep(IDLE_TIMEOUT) => {
            close(
                client_write,
                close_code::AWAY,
                "coding-agent proxy idle timeout",
            )
            .await;
            Ok(IdleInput::Closed)
        }
    }
}

async fn receive_upstream_idle(
    upstream_read: &Arc<AsyncMutex<UpstreamRead>>,
) -> Option<Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>
{
    upstream_read.lock().await.next().await
}

async fn handle_idle_upstream_message(
    message: Option<
        Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    >,
    client_write: &Arc<AsyncMutex<ClientWrite>>,
) -> Result<IdleInput, String> {
    use tokio_tungstenite::tungstenite::Message as UpstreamMessage;

    match message {
        Some(Ok(UpstreamMessage::Ping(payload))) => {
            send_client_control(client_write, Message::Ping(payload), "ping")
                .await
                .map_err(|error| error.to_string())?;
            Ok(IdleInput::Continue)
        }
        Some(Ok(UpstreamMessage::Pong(payload))) => {
            send_client_control(client_write, Message::Pong(payload), "pong")
                .await
                .map_err(|error| error.to_string())?;
            Ok(IdleInput::Continue)
        }
        Some(Ok(UpstreamMessage::Close(frame))) => {
            forward_upstream_close(client_write, frame).await;
            Ok(IdleInput::Closed)
        }
        Some(Ok(UpstreamMessage::Text(_))) => Err(compatibility_error(
            "upstream sent a response event without an active response.create",
        )),
        Some(Ok(UpstreamMessage::Binary(_) | UpstreamMessage::Frame(_))) => Err(
            compatibility_error("upstream sent an unsupported WebSocket frame"),
        ),
        Some(Err(error)) => Err(format!("upstream WebSocket read failed: {error}")),
        None => Err("upstream Responses WebSocket closed".into()),
    }
}

fn decode_response_create(text: &str) -> Result<Value, String> {
    let request = serde_json::from_str::<Value>(text)
        .map_err(|error| format!("malformed response.create JSON: {error}"))?;
    if request.get("type").and_then(Value::as_str) != Some("response.create") {
        return Err(
            "unsupported Codex WebSocket message; expected protocol message `response.create`"
                .into(),
        );
    }
    request
        .as_object()
        .filter(|object| object.len() > 1)
        .ok_or_else(|| "response.create message contains no request fields".to_string())?;
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
async fn run_managed_response(
    client_read: &mut ClientRead,
    client_write: Arc<AsyncMutex<ClientWrite>>,
    state: &AppState,
    provider_headers: &HeaderMap,
    authorization: crate::provider_auth::ProviderRequestAuthorization,
    request_json: Value,
    route: Option<crate::claude_desktop::AgentRouteContext>,
    upstream: PersistentUpstream,
) -> Result<ActiveResponseState, String> {
    let response_deadline = tokio::time::Instant::now() + RESPONSE_TIMEOUT;
    let request_bytes = serde_json::to_vec(&request_json)
        .map_err(|error| format!("failed to encode response.create request: {error}"))?;
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/responses")
        .body(axum::body::Body::from(request_bytes))
        .map_err(|error| format!("failed to construct managed WebSocket request: {error}"))?;
    let mut request = request;
    *request.headers_mut() = provider_headers.clone();
    request
        .extensions_mut()
        .insert(ManagedRequestTransport::WebSocket);
    if let Some(route) = route.as_ref() {
        request.extensions_mut().insert(route.clone());
    }
    let prepared = prepare_gateway_request(&state.config, request, authorization)
        .await
        .map_err(|error| error.to_string())?;
    let prep = state
        .sessions
        .prepare_gateway_call(&prepared.headers, build_llm_gateway_start(&prepared))
        .await
        .map_err(|error| error.to_string())?;
    let codec = streaming_codec(ProviderSurface::OpenAIResponses);
    let collector = codec.collector();
    let final_response = Arc::new(Mutex::new(None));
    let final_response_for_finalizer = final_response.clone();
    let original_finalizer = codec.finalizer();
    let finalizer = Box::new(move || {
        let response = original_finalizer();
        *final_response_for_finalizer
            .lock()
            .expect("WebSocket final response lock poisoned") = Some(response.clone());
        response
    });
    let func = websocket_execution(
        provider_headers.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        client_write.clone(),
        upstream.clone(),
    );
    let request_codec = Arc::new(GatewayRequestCodec {
        inner: build_request_codec(ProviderSurface::OpenAIResponses),
    });
    let response_codec = response_codec(ProviderSurface::OpenAIResponses);
    let session_id = prep.session_id.clone();
    let owner_subagent_id = prep.owner_subagent_id.clone();
    let session_finish = prep.session_finish;
    let params = LlmStreamCallExecuteParams::builder()
        .name(prep.provider_name)
        .request(prep.request)
        .func(func)
        .collector(collector)
        .finalizer(finalizer)
        .parent_opt(prep.parent)
        .attributes(prep.attributes)
        .metadata(prep.metadata)
        .model_name_opt(prep.model_name)
        .codec(request_codec)
        .response_codec(response_codec)
        .build();
    let execution = TASK_SCOPE_STACK.scope(prep.scope_stack, async move {
        llm_stream_call_execute(params).await
    });
    let mut output = match await_managed_output(response_deadline, execution).await {
        Ok(output) => output,
        Err(error) => {
            state
                .sessions
                .finish_gateway_call(&session_id, session_finish)
                .await;
            return Err(error);
        }
    };
    let result = tokio::time::timeout_at(
        response_deadline,
        relay_active_response(&mut output, client_read, &client_write, &upstream.write),
    )
    .await
    .unwrap_or_else(|_| Err("managed response exceeded the total duration limit".into()));
    cleanup_incomplete_output(&mut output, &result).await;
    record_final_response_hints(state, &session_id, owner_subagent_id, &final_response).await;
    state
        .sessions
        .finish_gateway_call(&session_id, session_finish)
        .await;
    result
}

async fn cleanup_incomplete_output(
    output: &mut LlmJsonStream,
    result: &Result<ActiveResponseState, String>,
) {
    if !matches!(result, Ok(ActiveResponseState::Completed)) {
        let _ = tokio::time::timeout(STREAM_CLEANUP_TIMEOUT, output.close()).await;
    }
}

async fn record_final_response_hints(
    state: &AppState,
    session_id: &str,
    owner_subagent_id: Option<String>,
    final_response: &Arc<Mutex<Option<Value>>>,
) {
    let response = final_response
        .lock()
        .expect("WebSocket final response lock poisoned")
        .take();
    if let Some(response) = response {
        state
            .sessions
            .record_gateway_response_hints(session_id, owner_subagent_id, response)
            .await;
    }
}

async fn await_managed_output(
    deadline: tokio::time::Instant,
    execution: impl std::future::Future<Output = Result<LlmJsonStream, FlowError>>,
) -> Result<LlmJsonStream, String> {
    match tokio::time::timeout_at(deadline, execution).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(format!(
            "managed response exceeded the total duration limit before streaming: {error}"
        )),
    }
}

type UpstreamSocket =
    tokio_tungstenite::WebSocketStream<crate::claude_desktop::AgentUpstreamStream>;
type UpstreamWrite =
    futures_util::stream::SplitSink<UpstreamSocket, tokio_tungstenite::tungstenite::Message>;
type UpstreamRead = futures_util::stream::SplitStream<UpstreamSocket>;
type ClientWrite = SplitSink<WebSocket, Message>;
type ClientRead = SplitStream<WebSocket>;
type UpstreamReconnectFuture =
    Pin<Box<dyn Future<Output = Result<(UpstreamWrite, UpstreamRead), String>> + Send + 'static>>;
type UpstreamReconnect = Arc<dyn Fn() -> UpstreamReconnectFuture + Send + Sync>;

#[derive(Clone)]
struct PersistentUpstream {
    write: Arc<AsyncMutex<UpstreamWrite>>,
    read: Arc<AsyncMutex<UpstreamRead>>,
    reconnect: UpstreamReconnect,
}

impl PersistentUpstream {
    fn new(write: UpstreamWrite, read: UpstreamRead, reconnect: UpstreamReconnect) -> Self {
        Self {
            write: Arc::new(AsyncMutex::new(write)),
            read: Arc::new(AsyncMutex::new(read)),
            reconnect,
        }
    }

    async fn replace_connection(&self) -> Result<(), FlowError> {
        let (write, read) = (self.reconnect)().await.map_err(|error| {
            FlowError::Internal(compatibility_error(&format!(
                "upstream reconnect before a safe retry failed: {error}"
            )))
        })?;
        *self.write.lock().await = write;
        *self.read.lock().await = read;
        Ok(())
    }
}

fn reconnect_upstream_factory(
    state: AppState,
    headers: HeaderMap,
    authorization: crate::provider_auth::ProviderRequestAuthorization,
    route: Option<crate::claude_desktop::AgentRouteContext>,
) -> UpstreamReconnect {
    Arc::new(move || {
        let state = state.clone();
        let headers = headers.clone();
        let route = route.clone();
        Box::pin(async move {
            let upstream = tokio::time::timeout(
                UPSTREAM_HANDSHAKE_TIMEOUT,
                connect_upstream(
                    &state,
                    &headers,
                    authorization,
                    route.as_ref(),
                    ProviderRoute::OpenAiResponses,
                    None,
                ),
            )
            .await
            .map_err(|_| "upstream WebSocket handshake timed out".to_string())??;
            Ok(upstream.0.split())
        })
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveResponseState {
    Completed,
    ClientClosed,
}

enum ActiveClientAction {
    Forward(tokio_tungstenite::tungstenite::Message, &'static str),
    Close(Option<CloseFrame>),
    Reject(u16, &'static str),
}

fn websocket_execution(
    provider_headers: HeaderMap,
    output_observed: Arc<AtomicBool>,
    request_dispatched: Arc<AtomicBool>,
    client_write: Arc<AsyncMutex<ClientWrite>>,
    upstream: PersistentUpstream,
) -> LlmStreamExecutionNextFn {
    Arc::new(move |request| {
        let provider_headers = provider_headers.clone();
        let output_observed = output_observed.clone();
        let request_dispatched = request_dispatched.clone();
        let client_write = client_write.clone();
        let upstream = upstream.clone();
        Box::pin(async move {
            ensure_retry_allowed(output_observed.load(Ordering::Acquire))?;
            if request_dispatched.swap(true, Ordering::AcqRel) {
                upstream.replace_connection().await?;
            }
            let dispatch = effective_websocket_dispatch(&provider_headers, &request)?;
            ensure_persistent_dispatch_compatible(&provider_headers, &dispatch)?;
            let mut request_content = request.content;
            let object = request_content.as_object_mut().ok_or_else(|| {
                FlowError::InvalidArgument("response.create request must be a JSON object".into())
            })?;
            object.insert("type".into(), Value::String("response.create".into()));
            tokio::time::timeout(WRITE_TIMEOUT, async {
                upstream
                    .write
                    .lock()
                    .await
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        request_content.to_string().into(),
                    ))
                    .await
            })
            .await
            .map_err(|_| FlowError::Internal("upstream WebSocket request write timed out".into()))?
            .map_err(|error| FlowError::Internal(error.to_string()))?;
            let stream = stream! {
                let mut sequence = UpstreamEventSequence::default();
                loop {
                    let message = match next_persistent_upstream(&upstream.read).await {
                        Ok(Some(message)) => message,
                        Ok(None) => {
                            yield Err(FlowError::Internal(
                                "upstream Responses WebSocket disconnected before a terminal event".into(),
                            ));
                            return;
                        }
                        Err(()) => {
                            yield Err(FlowError::Internal(compatibility_error(
                                "upstream response exceeded the activity idle timeout"
                            )));
                            return;
                        }
                    };
                    match message {
                        Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                            match serde_json::from_str::<Value>(&text) {
                                Ok(event) => {
                                    if let Err(error) = validate_upstream_event(&event, &mut sequence) {
                                        yield Err(error);
                                        return;
                                    }
                                    let terminal = terminal_event(&event);
                                    output_observed.store(true, Ordering::Release);
                                    yield Ok(event);
                                    if terminal {
                                        return;
                                    }
                                }
                                Err(error) => {
                                    yield Err(FlowError::InvalidArgument(compatibility_error(
                                        &format!("upstream Responses WebSocket emitted malformed JSON: {error}")
                                    )));
                                    return;
                                }
                            }
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Binary(_)) => {
                            yield Err(FlowError::InvalidArgument(
                                "upstream Responses WebSocket emitted a binary frame".into(),
                            ));
                            return;
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Close(frame)) => {
                            let frame_description = format!("{frame:?}");
                            forward_upstream_close(&client_write, frame).await;
                            yield Err(FlowError::Internal(format!(
                                "upstream Responses WebSocket closed before a terminal response event: {frame_description}"
                            )));
                            return;
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Ping(payload)) => {
                            if let Err(error) = send_client_control(
                                &client_write,
                                Message::Ping(payload),
                                "ping",
                            ).await {
                                yield Err(error);
                                return;
                            }
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Pong(payload)) => {
                            if let Err(error) = send_client_control(
                                &client_write,
                                Message::Pong(payload),
                                "pong",
                            ).await {
                                yield Err(error);
                                return;
                            }
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Frame(_)) => {
                            yield Err(FlowError::Internal(compatibility_error(
                                "upstream exposed an unexpected raw WebSocket frame"
                            )));
                            return;
                        }
                        Err(error) => {
                            yield Err(FlowError::Internal(error.to_string()));
                            return;
                        }
                    }
                }
            };
            Ok(LlmJsonStream::new(stream))
        })
    })
}

async fn next_persistent_upstream(
    stream: &Arc<AsyncMutex<UpstreamRead>>,
) -> Result<
    Option<Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>,
    (),
> {
    tokio::time::timeout(IDLE_TIMEOUT, async { stream.lock().await.next().await })
        .await
        .map_err(|_| ())
}

#[cfg(test)]
async fn next_with_idle_timeout<S>(stream: &mut S, timeout: Duration) -> Result<Option<S::Item>, ()>
where
    S: Stream + Unpin,
{
    tokio::time::timeout(timeout, stream.next())
        .await
        .map_err(|_| ())
}

async fn relay_active_response(
    output: &mut LlmJsonStream,
    client_read: &mut ClientRead,
    client_write: &Arc<AsyncMutex<ClientWrite>>,
    upstream_write: &Arc<AsyncMutex<UpstreamWrite>>,
) -> Result<ActiveResponseState, String> {
    let mut queue = ManagedEventQueue::default();
    let mut write = None;
    loop {
        start_next_event_write(&mut queue, &mut write, client_write.clone())?;
        if queue.is_complete() && write.is_none() {
            return Ok(ActiveResponseState::Completed);
        }
        match next_relay_action(output, client_read, &mut write, queue.can_read_output()).await {
            RelayAction::Output(Some(event)) => queue.push(event)?,
            RelayAction::Output(None) => queue.output_complete = true,
            RelayAction::Write(result) => {
                result?;
                write = None;
            }
            RelayAction::Client(message) => {
                let Some(message) = client_message(message)? else {
                    return Ok(ActiveResponseState::ClientClosed);
                };
                let outcome = handle_active_client_message(message, upstream_write).await?;
                if finish_active_client_outcome(outcome, &mut write, client_write).await {
                    return Ok(ActiveResponseState::ClientClosed);
                }
            }
        }
    }
}

type ManagedEventWrite = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

#[derive(Default)]
struct ManagedEventQueue {
    events: VecDeque<Result<String, String>>,
    bytes: usize,
    output_complete: bool,
}

impl ManagedEventQueue {
    fn can_read_output(&self) -> bool {
        !self.output_complete
            && self.events.len() < MAX_QUEUED_EVENT_FRAMES
            && self.bytes <= MAX_QUEUED_EVENT_BYTES.saturating_sub(MAX_FRAME_BYTES)
    }

    fn push(&mut self, event: Result<Value, FlowError>) -> Result<(), String> {
        let event = event
            .map(|event| event.to_string())
            .map_err(|error| error.to_string());
        let bytes = event.as_ref().map_or(0, String::len);
        if bytes > MAX_FRAME_BYTES {
            return Err("managed WebSocket event exceeds the frame-size limit".into());
        }
        self.bytes += bytes;
        if event.is_err() {
            self.output_complete = true;
        }
        self.events.push_back(event);
        Ok(())
    }

    fn pop(&mut self) -> Option<Result<String, String>> {
        let event = self.events.pop_front()?;
        self.bytes = self
            .bytes
            .saturating_sub(event.as_ref().map_or(0, String::len));
        Some(event)
    }

    fn is_complete(&self) -> bool {
        self.output_complete && self.events.is_empty()
    }
}

enum RelayAction {
    Output(Option<Result<Value, FlowError>>),
    Write(Result<(), String>),
    Client(Option<Result<Message, axum::Error>>),
}

async fn next_relay_action(
    output: &mut LlmJsonStream,
    client_read: &mut ClientRead,
    write: &mut Option<ManagedEventWrite>,
    can_read_output: bool,
) -> RelayAction {
    tokio::select! {
        event = next_output_when_ready(output, can_read_output) => RelayAction::Output(event),
        result = next_write_when_active(write) => RelayAction::Write(result),
        message = client_read.next() => RelayAction::Client(message),
    }
}

async fn next_output_when_ready(
    output: &mut LlmJsonStream,
    ready: bool,
) -> Option<Result<Value, FlowError>> {
    if ready {
        output.next().await
    } else {
        std::future::pending().await
    }
}

async fn next_write_when_active(write: &mut Option<ManagedEventWrite>) -> Result<(), String> {
    match write {
        Some(write) => write.await,
        None => std::future::pending().await,
    }
}

fn start_next_event_write(
    queue: &mut ManagedEventQueue,
    write: &mut Option<ManagedEventWrite>,
    client_write: Arc<AsyncMutex<ClientWrite>>,
) -> Result<(), String> {
    if write.is_some() {
        return Ok(());
    }
    let Some(event) = queue.pop() else {
        return Ok(());
    };
    let event = event?;
    *write = Some(Box::pin(async move {
        tokio::time::timeout(WRITE_TIMEOUT, async {
            client_write
                .lock()
                .await
                .send(Message::Text(event.into()))
                .await
        })
        .await
        .map_err(|_| "client WebSocket write timed out".to_string())?
        .map_err(|error| format!("client WebSocket write failed: {error}"))
    }));
    Ok(())
}

fn client_message(
    message: Option<Result<Message, axum::Error>>,
) -> Result<Option<Message>, String> {
    match message {
        Some(Ok(message)) => Ok(Some(message)),
        Some(Err(error)) => Err(format!("client WebSocket read failed: {error}")),
        None => Ok(None),
    }
}

enum ActiveClientOutcome {
    Continue,
    Closed,
    Reject(u16, &'static str),
}

async fn handle_active_client_message(
    message: Message,
    upstream_write: &Arc<AsyncMutex<UpstreamWrite>>,
) -> Result<ActiveClientOutcome, String> {
    match active_client_action(message) {
        ActiveClientAction::Forward(message, kind) => {
            send_upstream_control(upstream_write, message, kind).await?;
            Ok(ActiveClientOutcome::Continue)
        }
        ActiveClientAction::Close(frame) => {
            forward_client_close(upstream_write, frame).await;
            Ok(ActiveClientOutcome::Closed)
        }
        ActiveClientAction::Reject(code, reason) => Ok(ActiveClientOutcome::Reject(code, reason)),
    }
}

async fn finish_active_client_outcome(
    outcome: ActiveClientOutcome,
    write: &mut Option<ManagedEventWrite>,
    client_write: &Arc<AsyncMutex<ClientWrite>>,
) -> bool {
    match outcome {
        ActiveClientOutcome::Continue => false,
        ActiveClientOutcome::Closed => true,
        ActiveClientOutcome::Reject(code, reason) => {
            *write = None;
            close(client_write, code, reason).await;
            true
        }
    }
}

fn active_client_action(message: Message) -> ActiveClientAction {
    match message {
        Message::Ping(payload) => ActiveClientAction::Forward(
            tokio_tungstenite::tungstenite::Message::Ping(payload),
            "ping",
        ),
        Message::Pong(payload) => ActiveClientAction::Forward(
            tokio_tungstenite::tungstenite::Message::Pong(payload),
            "pong",
        ),
        Message::Close(frame) => ActiveClientAction::Close(frame),
        Message::Text(_) => ActiveClientAction::Reject(
            close_code::POLICY,
            "only one active response.create is allowed per connection",
        ),
        Message::Binary(_) => ActiveClientAction::Reject(
            close_code::UNSUPPORTED,
            "Responses WebSocket accepts text JSON frames only",
        ),
    }
}

async fn send_upstream_control(
    upstream_write: &Arc<AsyncMutex<UpstreamWrite>>,
    message: tokio_tungstenite::tungstenite::Message,
    kind: &str,
) -> Result<(), String> {
    tokio::time::timeout(WRITE_TIMEOUT, async {
        upstream_write.lock().await.send(message).await
    })
    .await
    .map_err(|_| format!("upstream WebSocket {kind} timed out"))?
    .map_err(|error| format!("upstream WebSocket {kind} failed: {error}"))
}

async fn send_client_control(
    client_write: &Arc<AsyncMutex<ClientWrite>>,
    message: Message,
    kind: &str,
) -> Result<(), FlowError> {
    tokio::time::timeout(WRITE_TIMEOUT, async {
        client_write.lock().await.send(message).await
    })
    .await
    .map_err(|_| FlowError::Internal(format!("client WebSocket {kind} timed out")))?
    .map_err(|error| FlowError::Internal(format!("client WebSocket {kind} failed: {error}")))
}

async fn forward_client_close(
    upstream_write: &Arc<AsyncMutex<UpstreamWrite>>,
    frame: Option<CloseFrame>,
) {
    let frame = frame.map(
        |frame| tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: frame.code.into(),
            reason: frame.reason.to_string().into(),
        },
    );
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        upstream_write
            .lock()
            .await
            .send(tokio_tungstenite::tungstenite::Message::Close(frame))
            .await
    })
    .await;
}

async fn forward_upstream_close(
    client_write: &Arc<AsyncMutex<ClientWrite>>,
    frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
) {
    let frame = frame.map(|frame| CloseFrame {
        code: frame.code.into(),
        reason: frame.reason.to_string().into(),
    });
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        client_write.lock().await.send(Message::Close(frame)).await
    })
    .await;
}

const SUPPORTED_UPSTREAM_EVENT_TYPES: &[&str] = &[
    "error",
    "response.audio.delta",
    "response.audio.done",
    "response.audio.transcript.delta",
    "response.audio.transcript.done",
    "response.code_interpreter_call.completed",
    "response.code_interpreter_call.in_progress",
    "response.code_interpreter_call.interpreting",
    "response.code_interpreter_call_code.delta",
    "response.code_interpreter_call_code.done",
    "response.completed",
    "response.content_part.added",
    "response.content_part.done",
    "response.created",
    "response.custom_tool_call_input.delta",
    "response.custom_tool_call_input.done",
    "response.failed",
    "response.file_search_call.completed",
    "response.file_search_call.in_progress",
    "response.file_search_call.searching",
    "response.function_call_arguments.delta",
    "response.function_call_arguments.done",
    "response.image_generation_call.completed",
    "response.image_generation_call.generating",
    "response.image_generation_call.in_progress",
    "response.image_generation_call.partial_image",
    "response.in_progress",
    "response.incomplete",
    "response.inject.created",
    "response.inject.failed",
    "response.mcp_call.completed",
    "response.mcp_call.failed",
    "response.mcp_call.in_progress",
    "response.mcp_call_arguments.delta",
    "response.mcp_call_arguments.done",
    "response.mcp_list_tools.completed",
    "response.mcp_list_tools.failed",
    "response.mcp_list_tools.in_progress",
    "response.output_item.added",
    "response.output_item.done",
    "response.output_text.annotation.added",
    "response.output_text.delta",
    "response.output_text.done",
    "response.queued",
    "response.reasoning_summary_part.added",
    "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
    "response.reasoning_text.delta",
    "response.reasoning_text.done",
    "response.refusal.delta",
    "response.refusal.done",
    "response.web_search_call.completed",
    "response.web_search_call.in_progress",
    "response.web_search_call.searching",
];

#[derive(Default)]
struct UpstreamEventSequence {
    last: Option<u64>,
}

fn validate_upstream_event(
    event: &Value,
    sequence: &mut UpstreamEventSequence,
) -> Result<(), FlowError> {
    let event = event.as_object().ok_or_else(|| {
        FlowError::InvalidArgument(compatibility_error("upstream JSON event must be an object"))
    })?;
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .filter(|event_type| !event_type.is_empty())
        .ok_or_else(|| {
            FlowError::InvalidArgument(compatibility_error(
                "upstream JSON event has no string `type` field",
            ))
        })?;
    if !SUPPORTED_UPSTREAM_EVENT_TYPES.contains(&event_type) {
        return Err(FlowError::InvalidArgument(compatibility_error(&format!(
            "unsupported upstream event type `{event_type}`"
        ))));
    }
    validate_upstream_event_shape(event, event_type)?;
    sequence.observe(event, event_type)
}

impl UpstreamEventSequence {
    fn observe(
        &mut self,
        event: &serde_json::Map<String, Value>,
        event_type: &str,
    ) -> Result<(), FlowError> {
        let current = event["sequence_number"]
            .as_u64()
            .expect("shape validation requires an unsigned sequence number");
        if self.last.is_some_and(|last| current <= last) {
            return Err(FlowError::InvalidArgument(compatibility_error(&format!(
                "upstream `{event_type}` sequence_number {current} is duplicate or decreasing"
            ))));
        }
        self.last = Some(current);
        Ok(())
    }
}

fn validate_upstream_event_shape(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    require_upstream_field(event, event_type, "sequence_number", Value::is_u64)?;
    match event_type {
        "response.created"
        | "response.in_progress"
        | "response.queued"
        | "response.completed"
        | "response.failed"
        | "response.incomplete" => {
            require_upstream_field(event, event_type, "response", Value::is_object)
        }
        "response.output_item.added" | "response.output_item.done" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "item", Value::is_object)
        }
        "response.content_part.added" | "response.content_part.done" => {
            require_content_position(event, event_type)?;
            require_upstream_field(event, event_type, "part", Value::is_object)
        }
        "response.inject.created" | "response.inject.failed" => {
            require_upstream_field(event, event_type, "response_id", Value::is_string)
        }
        "error" => require_upstream_field(event, event_type, "message", Value::is_string),
        "response.audio.delta" | "response.audio.transcript.delta" => {
            require_upstream_field(event, event_type, "delta", Value::is_string)
        }
        "response.audio.done" | "response.audio.transcript.done" => Ok(()),
        "response.reasoning_summary_part.added" | "response.reasoning_summary_part.done" => {
            require_summary_position(event, event_type)?;
            require_upstream_field(event, event_type, "part", Value::is_object)
        }
        event_type if event_type.ends_with(".delta") => validate_delta_event(event, event_type),
        event_type if event_type.ends_with(".done") => validate_done_event(event, event_type),
        "response.image_generation_call.partial_image" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "partial_image_b64", Value::is_string)?;
            require_upstream_field(event, event_type, "partial_image_index", Value::is_u64)
        }
        "response.output_text.annotation.added" => {
            require_content_position(event, event_type)?;
            require_upstream_field(event, event_type, "annotation_index", Value::is_u64)?;
            require_upstream_field(event, event_type, "annotation", Value::is_object)
        }
        _ => require_item_position(event, event_type),
    }
}

fn validate_delta_event(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    require_upstream_field(event, event_type, "delta", Value::is_string)?;
    match event_type {
        "response.output_text.delta"
        | "response.reasoning_text.delta"
        | "response.refusal.delta" => require_content_position(event, event_type),
        "response.reasoning_summary_text.delta" => require_summary_position(event, event_type),
        _ => require_item_position(event, event_type),
    }
}

fn validate_done_event(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    match event_type {
        "response.code_interpreter_call_code.done" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "code", Value::is_string)
        }
        "response.custom_tool_call_input.done" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "input", Value::is_string)
        }
        "response.function_call_arguments.done" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "arguments", Value::is_string)?;
            require_upstream_field(event, event_type, "name", Value::is_string)
        }
        "response.mcp_call_arguments.done" => {
            require_item_position(event, event_type)?;
            require_upstream_field(event, event_type, "arguments", Value::is_string)
        }
        "response.output_text.done" | "response.reasoning_text.done" => {
            require_content_position(event, event_type)?;
            require_upstream_field(event, event_type, "text", Value::is_string)
        }
        "response.reasoning_summary_text.done" => {
            require_summary_position(event, event_type)?;
            require_upstream_field(event, event_type, "text", Value::is_string)
        }
        "response.refusal.done" => {
            require_content_position(event, event_type)?;
            require_upstream_field(event, event_type, "refusal", Value::is_string)
        }
        _ => Err(FlowError::InvalidArgument(compatibility_error(&format!(
            "upstream event discriminator `{event_type}` has no validation schema"
        )))),
    }
}

fn require_item_position(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    require_upstream_field(event, event_type, "item_id", Value::is_string)?;
    require_upstream_field(event, event_type, "output_index", Value::is_u64)
}

fn require_content_position(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    require_item_position(event, event_type)?;
    require_upstream_field(event, event_type, "content_index", Value::is_u64)
}

fn require_summary_position(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
) -> Result<(), FlowError> {
    require_item_position(event, event_type)?;
    require_upstream_field(event, event_type, "summary_index", Value::is_u64)
}

fn require_upstream_field(
    event: &serde_json::Map<String, Value>,
    event_type: &str,
    field: &str,
    valid: impl FnOnce(&Value) -> bool,
) -> Result<(), FlowError> {
    event
        .get(field)
        .filter(|value| valid(value))
        .map(|_| ())
        .ok_or_else(|| {
            FlowError::InvalidArgument(compatibility_error(&format!(
                "upstream `{event_type}` event has invalid or missing `{field}`"
            )))
        })
}

fn ensure_retry_allowed(output_observed: bool) -> Result<(), FlowError> {
    if output_observed {
        return Err(FlowError::Internal(
            "Responses WebSocket retry rejected after observable upstream output; Codex must reconnect"
                .into(),
        ));
    }
    Ok(())
}

fn terminal_event(event: &Value) -> bool {
    matches!(
        event.get("type").and_then(Value::as_str),
        Some("response.completed" | "response.failed" | "response.incomplete" | "error")
    )
}

struct EffectiveWebSocketDispatch {
    headers: HeaderMap,
    route: ProviderRoute,
    url: Option<String>,
}

fn effective_websocket_dispatch(
    source_headers: &HeaderMap,
    request: &LlmRequest,
) -> Result<EffectiveWebSocketDispatch, FlowError> {
    let source_private_headers =
        super::response::declared_provider_credential_headers(source_headers);
    let overrides = super::dispatch_overrides(&request.headers)
        .map_err(|error| FlowError::InvalidArgument(compatibility_error(&error)))?;
    let explicit_target = overrides.is_explicit_target();
    let route = overrides.route.unwrap_or(ProviderRoute::OpenAiResponses);
    if route != ProviderRoute::OpenAiResponses {
        return Err(FlowError::InvalidArgument(compatibility_error(
            "a Responses WebSocket request interceptor selected a non-Responses route",
        )));
    }
    let mut headers = source_headers.clone();
    if explicit_target {
        let target_private_headers = super::declared_provider_credential_headers(&request.headers);
        crate::provider_auth::remove_named_provider_credentials(
            &mut headers,
            source_private_headers
                .iter()
                .chain(target_private_headers.iter())
                .map(String::as_str),
        );
    }
    super::apply_rewritten_headers(&mut headers, &request.headers, &source_private_headers);
    Ok(EffectiveWebSocketDispatch {
        headers,
        route,
        url: overrides.url,
    })
}

fn ensure_persistent_dispatch_compatible(
    handshake_headers: &HeaderMap,
    dispatch: &EffectiveWebSocketDispatch,
) -> Result<(), FlowError> {
    if dispatch.route != ProviderRoute::OpenAiResponses || dispatch.url.is_some() {
        return Err(FlowError::InvalidArgument(compatibility_error(
            "request interceptors cannot change the provider route of an established Responses WebSocket",
        )));
    }
    let mut expected = handshake_headers.clone();
    let mut actual = dispatch.headers.clone();
    super::strip_internal_dispatch_headers(&mut expected);
    super::strip_internal_dispatch_headers(&mut actual);
    for name in [
        http::header::CONTENT_LENGTH,
        http::header::CONTENT_TYPE,
        http::header::TRANSFER_ENCODING,
    ] {
        expected.remove(&name);
        actual.remove(&name);
    }
    if expected != actual {
        return Err(FlowError::InvalidArgument(compatibility_error(
            "request interceptors cannot change handshake headers on an established Responses WebSocket",
        )));
    }
    Ok(())
}

async fn connect_upstream(
    state: &AppState,
    headers: &HeaderMap,
    authorization: crate::provider_auth::ProviderRequestAuthorization,
    agent_route: Option<&crate::claude_desktop::AgentRouteContext>,
    route: ProviderRoute,
    explicit_url: Option<&str>,
) -> Result<
    (
        UpstreamSocket,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    String,
> {
    let upstream = explicit_url.map(str::to_owned).unwrap_or_else(|| {
        super::routes::gateway_upstream_url_override(
            route,
            headers,
            "/responses",
            authorization.allow_configured_provider_auth,
            authorization.allow_environment_provider_auth,
            &state.config,
        )
        .unwrap_or_else(|| route.upstream_url(&state.config, "/responses"))
    });
    let url = upstream
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let mut forward_headers = headers.clone();
    super::strip_internal_dispatch_headers(&mut forward_headers);
    let normalized_headers = super::routes::strip_replaceable_agent_auth_headers(
        &forward_headers,
        route,
        authorization.allow_configured_provider_auth,
        authorization.allow_environment_provider_auth,
        state.config.openai_auth_header.as_deref(),
    );
    let mut request = url
        .into_client_request()
        .map_err(|error| format!("invalid upstream Responses WebSocket URL: {error}"))?;
    for (name, value) in &normalized_headers {
        if super::response::should_forward_request_header(name, &normalized_headers)
            && !name.as_str().starts_with("sec-websocket-")
        {
            request.headers_mut().append(name, value.clone());
        }
    }
    if !crate::provider_auth::has_provider_credential(request.headers()) {
        let value = state
            .config
            .openai_auth_header
            .clone()
            .filter(|_| authorization.allow_configured_provider_auth)
            .or_else(|| {
                authorization
                    .allow_environment_provider_auth
                    .then(|| std::env::var("OPENAI_API_KEY").ok())
                    .flatten()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("Bearer {}", value.trim()))
            });
        if let Some(value) = value {
            request.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                value
                    .parse()
                    .map_err(|error| format!("invalid OpenAI authorization header: {error}"))?,
            );
        }
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES);
    let parsed = reqwest::Url::parse(request.uri().to_string().as_str())
        .map_err(|error| format!("invalid upstream Responses WebSocket URL: {error}"))?;
    let allow_test_loopback_dispatch = state.allows_test_loopback_dispatch() || cfg!(test);
    super::validate_managed_dispatch_target(
        parsed.as_str(),
        route,
        super::ManagedDispatchTransport::WebSocket,
        allow_test_loopback_dispatch,
    )?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "upstream Responses WebSocket URL has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let stream = connect_upstream_stream(
        &parsed,
        agent_route.and_then(|route| route.upstream_proxy.as_ref()),
        host,
        port,
        allow_test_loopback_dispatch,
    )
    .await?;
    tokio_tungstenite::client_async_with_config(request, stream, Some(config))
        .await
        .map_err(|error| format!("upstream Responses WebSocket handshake failed: {error}"))
}

async fn connect_upstream_stream(
    parsed: &reqwest::Url,
    proxy: Option<&crate::claude_desktop::AgentUpstreamProxy>,
    host: &str,
    port: u16,
    allow_test_loopback_dispatch: bool,
) -> Result<UpstreamTransport, String> {
    #[cfg(any(test, feature = "internal-test-server"))]
    if allow_test_loopback_dispatch && parsed.scheme() == "ws" {
        if let Some(proxy) = proxy {
            let destination =
                std::net::SocketAddr::new(std::net::Ipv4Addr::new(93, 184, 216, 34).into(), port);
            return crate::claude_desktop::connect_test_upstream_proxy(proxy, destination).await;
        }
        return tokio::net::TcpStream::connect((host, port))
            .await
            .map(|stream| Box::new(stream) as UpstreamTransport)
            .map_err(|error| format!("test WebSocket upstream connection failed: {error}"));
    }
    #[cfg(not(any(test, feature = "internal-test-server")))]
    let _ = allow_test_loopback_dispatch;
    if parsed.scheme() != "wss" {
        return Err("managed Responses WebSocket upstream must use wss".into());
    }
    crate::claude_desktop::connect_provider_tls(proxy, host, port).await
}

#[cfg(test)]
async fn connect_test_upstream_wss_stream(
    parsed: &reqwest::Url,
    proxy: Option<&crate::claude_desktop::AgentUpstreamProxy>,
    host: &str,
    port: u16,
    addresses: &[std::net::SocketAddr],
) -> Result<UpstreamTransport, String> {
    if parsed.scheme() != "wss" {
        return Err("managed Responses WebSocket upstream must use wss".into());
    }
    crate::claude_desktop::connect_test_provider_tls_to_addresses(proxy, host, port, addresses)
        .await
}

type UpstreamTransport = crate::claude_desktop::AgentUpstreamStream;

async fn close(socket: &Arc<AsyncMutex<ClientWrite>>, code: u16, reason: &str) {
    let reason = reason.chars().take(120).collect::<String>();
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        socket
            .lock()
            .await
            .send(Message::Close(Some(CloseFrame {
                code,
                reason: reason.into(),
            })))
            .await
    })
    .await;
}

fn compatibility_error(error: &str) -> String {
    format!(
        "Codex Responses WebSocket compatibility failure: {error}; run `nemo-relay doctor codex` and verify the supported Codex version"
    )
}

#[cfg(test)]
#[path = "../../tests/coverage/shared/gateway_websocket_tests.rs"]
mod tests;
