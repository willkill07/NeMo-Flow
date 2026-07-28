// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn response_create_requires_valid_text_json_with_request_fields() {
    let request =
        decode_response_create(r#"{"type":"response.create","model":"gpt-5","input":"hello"}"#)
            .unwrap();
    assert_eq!(request["model"], "gpt-5");

    for (raw, expected) in [
        ("not-json", "malformed response.create JSON"),
        (r#"{"type":"response.cancel"}"#, "expected protocol message"),
        (
            r#"{"type":"response.create"}"#,
            "contains no request fields",
        ),
        ("[]", "expected protocol message"),
    ] {
        assert!(decode_response_create(raw).unwrap_err().contains(expected));
    }
}

#[test]
fn responses_terminal_events_cover_every_supported_outcome() {
    for event in [
        "response.completed",
        "response.failed",
        "response.incomplete",
        "error",
    ] {
        assert!(terminal_event(&serde_json::json!({"type": event})));
    }
    for event in ["response.created", "response.output_text.delta"] {
        assert!(!terminal_event(&serde_json::json!({"type": event})));
    }
    assert!(!terminal_event(&Value::Null));
}

#[test]
fn compatibility_errors_are_actionable_and_close_safe() {
    let message = compatibility_error("unexpected protocol version");
    assert!(message.contains("Codex Responses WebSocket compatibility failure"));
    assert!(message.contains("nemo-relay doctor codex"));
    assert!(message.contains("supported Codex version"));
    assert!(message.len() < 256);
}

#[test]
fn active_client_control_frames_are_forwarded_and_data_frames_are_rejected() {
    for (message, expected_kind) in [
        (Message::Ping(vec![1, 2].into()), "ping"),
        (Message::Pong(vec![3, 4].into()), "pong"),
    ] {
        match active_client_action(message) {
            ActiveClientAction::Forward(_, kind) => assert_eq!(kind, expected_kind),
            _ => panic!("control frame was not forwarded"),
        }
    }
    assert!(matches!(
        active_client_action(Message::Close(None)),
        ActiveClientAction::Close(None)
    ));
    assert!(matches!(
        active_client_action(Message::Text("second response".into())),
        ActiveClientAction::Reject(close_code::POLICY, _)
    ));
    assert!(matches!(
        active_client_action(Message::Binary(vec![0].into())),
        ActiveClientAction::Reject(close_code::UNSUPPORTED, _)
    ));
}

#[test]
fn upstream_events_require_a_protocol_type_and_retry_stops_after_output() {
    let mut sequence = UpstreamEventSequence::default();
    validate_upstream_event(
        &serde_json::json!({
        "type": "response.created",
        "sequence_number": 0,
        "response": {}
        }),
        &mut sequence,
    )
    .unwrap();
    for event in [
        Value::Null,
        serde_json::json!({}),
        serde_json::json!({"type": 1}),
        serde_json::json!({"type": ""}),
    ] {
        let error = validate_upstream_event(&event, &mut UpstreamEventSequence::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("compatibility failure"), "{error}");
    }
    let unknown = validate_upstream_event(
        &serde_json::json!({
            "type": "response.protocol_changed",
            "sequence_number": 1
        }),
        &mut UpstreamEventSequence::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        unknown.contains("unsupported upstream event type"),
        "{unknown}"
    );
    let malformed = validate_upstream_event(
        &serde_json::json!({
            "type": "response.created",
            "response": {}
        }),
        &mut UpstreamEventSequence::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(malformed.contains("sequence_number"), "{malformed}");

    ensure_retry_allowed(false).unwrap();
    let error = ensure_retry_allowed(true).unwrap_err().to_string();
    assert!(error.contains("retry rejected after observable upstream output"));
    assert!(error.contains("Codex must reconnect"));
}

#[test]
fn upstream_event_schemas_require_family_specific_fields_and_monotonic_sequences() {
    for (event, missing) in [
        (
            serde_json::json!({
                "type": "response.content_part.added",
                "sequence_number": 0,
                "content_index": 0,
                "part": {}
            }),
            "item_id",
        ),
        (
            serde_json::json!({
                "type": "response.output_text.delta",
                "sequence_number": 0,
                "item_id": "item",
                "output_index": 0,
                "content_index": 0,
                "delta": {}
            }),
            "delta",
        ),
        (
            serde_json::json!({
                "type": "response.mcp_call_arguments.done",
                "sequence_number": 0,
                "item_id": "item",
                "output_index": 0
            }),
            "arguments",
        ),
    ] {
        let error = validate_upstream_event(&event, &mut UpstreamEventSequence::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains(missing), "{error}");
    }

    let mut sequence = UpstreamEventSequence::default();
    for number in [2, 3] {
        validate_upstream_event(
            &serde_json::json!({
                "type": "response.created",
                "sequence_number": number,
                "response": {}
            }),
            &mut sequence,
        )
        .unwrap();
    }
    for number in [3, 1] {
        let error = validate_upstream_event(
            &serde_json::json!({
                "type": "response.completed",
                "sequence_number": number,
                "response": {}
            }),
            &mut sequence,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate or decreasing"), "{error}");
    }
}

#[test]
fn every_supported_upstream_discriminator_has_an_acceptance_schema() {
    for event_type in SUPPORTED_UPSTREAM_EVENT_TYPES {
        let event = serde_json::json!({
            "type": event_type,
            "sequence_number": 0,
            "response": {},
            "response_id": "response",
            "message": "error",
            "item_id": "item",
            "output_index": 0,
            "content_index": 0,
            "summary_index": 0,
            "item": {},
            "part": {},
            "annotation": {},
            "annotation_index": 0,
            "partial_image_b64": "aW1hZ2U=",
            "partial_image_index": 0,
            "delta": "delta",
            "code": "code",
            "input": "input",
            "arguments": "{}",
            "name": "tool",
            "text": "text",
            "refusal": "refusal"
        });
        validate_upstream_event(&event, &mut UpstreamEventSequence::default())
            .unwrap_or_else(|error| panic!("{event_type}: {error}"));
    }
}

async fn test_upstream_connection() -> (
    (UpstreamWrite, UpstreamRead),
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(address);
    let server = listener.accept();
    let (client, server) = tokio::join!(client, server);
    let (server, _) = server.unwrap();
    let server: crate::claude_desktop::AgentUpstreamStream = Box::new(server);
    let socket = UpstreamSocket::from_raw_socket(
        server,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        client.unwrap(),
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    (socket.split(), peer)
}

#[tokio::test]
async fn pre_output_retry_reconnects_before_dispatch_and_ignores_stale_frames() {
    let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel(1);
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move |upgrade: WebSocketUpgrade| {
            let socket_tx = socket_tx.clone();
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    socket_tx.send(socket).await.unwrap();
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (client, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
        .await
        .unwrap();
    let socket = socket_rx.recv().await.unwrap();
    let (client_write, _) = socket.split();

    let ((upstream_write, upstream_read), mut upstream_peer) = test_upstream_connection().await;
    let (replacement, mut replacement_peer) = test_upstream_connection().await;
    let replacement = Arc::new(AsyncMutex::new(Some(replacement)));
    let reconnect: UpstreamReconnect = Arc::new(move || {
        let replacement = replacement.clone();
        Box::pin(async move {
            replacement
                .lock()
                .await
                .take()
                .ok_or_else(|| "replacement test connection already consumed".to_string())
        })
    });
    let upstream = PersistentUpstream::new(upstream_write, upstream_read, reconnect);

    let output_observed = Arc::new(AtomicBool::new(false));
    let execution = websocket_execution(
        HeaderMap::new(),
        output_observed.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AsyncMutex::new(client_write)),
        upstream,
    );
    let request = || LlmRequest {
        headers: serde_json::Map::new(),
        content: serde_json::json!({"model": "gpt-5", "input": "retry me"}),
    };

    let mut first = execution(request()).await.unwrap();
    upstream_peer.next().await.unwrap().unwrap();
    upstream_peer
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "not-json".into(),
        ))
        .await
        .unwrap();
    let first_error = first.next().await.unwrap().unwrap_err().to_string();
    assert!(first_error.contains("malformed JSON"), "{first_error}");
    assert!(
        first_error.contains("nemo-relay doctor codex"),
        "{first_error}"
    );
    assert!(!output_observed.load(Ordering::Acquire));

    upstream_peer
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "type": "response.created",
                "sequence_number": 0,
                "response": {"id": "stale"}
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let mut retry = execution(request()).await.unwrap();
    replacement_peer.next().await.unwrap().unwrap();
    replacement_peer
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "type": "response.created",
                "sequence_number": 0,
                "response": {"id": "replacement"}
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let event = retry.next().await.unwrap().unwrap();
    assert_eq!(event["type"], "response.created");
    assert_eq!(event["response"]["id"], "replacement");
    assert!(output_observed.load(Ordering::Acquire));
    assert!(execution(request()).await.is_err());

    drop(client);
    server.abort();
}

#[test]
fn established_websocket_rejects_intercepts_that_change_handshake_dispatch() {
    let mut source_headers = HeaderMap::new();
    source_headers.insert("authorization", "Bearer source-secret".parse().unwrap());
    source_headers.insert("x-source", "retained".parse().unwrap());
    source_headers.insert(
        "x-custom-signature",
        "source-custom-secret".parse().unwrap(),
    );
    source_headers.insert(
        "x-nemo-relay-internal-provider-credential-headers",
        "X-Custom-Signature".parse().unwrap(),
    );
    let unchanged = LlmRequest {
        headers: serde_json::Map::from_iter([
            ("x-source".into(), serde_json::json!("retained")),
            (
                "x-nemo-relay-session-id".into(),
                serde_json::json!("internal-session"),
            ),
        ]),
        content: serde_json::json!({"model": "gpt-5", "input": "unchanged"}),
    };
    let unchanged_dispatch = effective_websocket_dispatch(&source_headers, &unchanged).unwrap();
    ensure_persistent_dispatch_compatible(&source_headers, &unchanged_dispatch).unwrap();
    assert_eq!(
        unchanged_dispatch
            .headers
            .get("x-custom-signature")
            .and_then(|value| value.to_str().ok()),
        Some("source-custom-secret")
    );
    assert!(
        unchanged_dispatch
            .headers
            .get("x-nemo-relay-session-id")
            .is_none(),
        "Relay correlation metadata must remain internal"
    );

    let request = LlmRequest {
        headers: serde_json::Map::from_iter([
            (
                "x-nemo-relay-internal-dispatch-url".into(),
                serde_json::json!("https://api.openai.com/v1/responses"),
            ),
            (
                "authorization".into(),
                serde_json::json!("Bearer replacement-secret"),
            ),
            ("x-intercepted".into(), serde_json::json!("yes")),
        ]),
        content: serde_json::json!({"model": "gpt-5", "input": "rewritten"}),
    };
    let dispatch = effective_websocket_dispatch(&source_headers, &request).unwrap();

    assert_eq!(
        dispatch.url.as_deref(),
        Some("https://api.openai.com/v1/responses")
    );
    assert_eq!(dispatch.route, ProviderRoute::OpenAiResponses);
    assert_eq!(
        dispatch
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer replacement-secret")
    );
    assert!(dispatch.headers.get("x-source").is_none());
    assert!(dispatch.headers.get("x-custom-signature").is_none());
    assert_eq!(
        dispatch
            .headers
            .get("x-intercepted")
            .and_then(|value| value.to_str().ok()),
        Some("yes")
    );
    let error = ensure_persistent_dispatch_compatible(&source_headers, &dispatch)
        .unwrap_err()
        .to_string();
    assert!(error.contains("established Responses WebSocket"), "{error}");
}

#[tokio::test]
async fn loopback_websocket_transport_requires_the_runtime_test_capability() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let parsed = reqwest::Url::parse(&format!("ws://{address}/v1/responses")).unwrap();

    let error =
        match connect_upstream_stream(&parsed, None, "127.0.0.1", address.port(), false).await {
            Ok(_) => panic!("loopback ws must require the runtime test capability"),
            Err(error) => error,
        };
    assert!(error.contains("must use wss"), "{error}");

    let stream = connect_upstream_stream(&parsed, None, "127.0.0.1", address.port(), true)
        .await
        .unwrap();
    drop(stream);
}

#[test]
fn websocket_dispatch_targets_are_limited_to_native_wss_hosts() {
    for url in [
        "wss://api.openai.com/v1/responses",
        "wss://chatgpt.com/backend-api/codex/responses",
        "ws://127.0.0.1:12345/responses",
    ] {
        super::super::validate_managed_dispatch_target(
            url,
            ProviderRoute::OpenAiResponses,
            super::super::ManagedDispatchTransport::WebSocket,
            true,
        )
        .unwrap();
    }
    for url in [
        "wss://example.com/v1/responses",
        "wss://api.openai.com:8443/v1/responses",
        "https://api.openai.com/v1/responses",
        "wss://api.anthropic.com/v1/messages",
        "wss://api.openai.com/v1/chat/completions",
    ] {
        assert!(
            super::super::validate_managed_dispatch_target(
                url,
                ProviderRoute::OpenAiResponses,
                super::super::ManagedDispatchTransport::WebSocket,
                true,
            )
            .is_err()
        );
    }
}

#[test]
fn websocket_limits_are_bounded() {
    const {
        assert!(MAX_FRAME_BYTES > 0);
        assert!(MAX_WRITE_BUFFER_BYTES >= MAX_FRAME_BYTES);
        assert!(MAX_QUEUED_EVENT_BYTES >= MAX_FRAME_BYTES);
        assert!(MAX_QUEUED_EVENT_FRAMES > 0);
        assert!(MAX_CONCURRENT_SOCKETS > 0);
    }
    assert!(IDLE_TIMEOUT < RESPONSE_TIMEOUT);
}

#[tokio::test]
async fn websocket_capacity_is_exhausted_and_released_under_concurrent_load() {
    let sockets = Arc::new(Semaphore::new(MAX_CONCURRENT_SOCKETS));
    let mut permits = Vec::new();
    for _ in 0..MAX_CONCURRENT_SOCKETS {
        permits.push(acquire_socket(sockets.clone()).unwrap());
    }
    assert!(acquire_socket(sockets.clone()).is_err());

    permits.pop();
    let replacement = acquire_socket(sockets).unwrap();
    assert_eq!(replacement.num_permits(), 1);
}

#[tokio::test]
async fn blocked_downstream_keeps_a_bounded_upstream_drain_and_forwards_ping() {
    let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel(1);
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move |upgrade: WebSocketUpgrade| {
            let socket_tx = socket_tx.clone();
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    socket_tx.send(socket).await.unwrap();
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
        .await
        .unwrap();
    let socket = socket_rx.recv().await.unwrap();
    let (client_write, mut client_read) = socket.split();
    let client_write = Arc::new(AsyncMutex::new(client_write));
    let blocked_write = client_write.clone().lock_owned().await;

    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_client = tokio::net::TcpStream::connect(upstream_address);
    let upstream_server = upstream_listener.accept();
    let (upstream_client, upstream_server) = tokio::join!(upstream_client, upstream_server);
    let upstream_client = upstream_client.unwrap();
    let (upstream_server, _) = upstream_server.unwrap();
    let upstream_server: crate::claude_desktop::AgentUpstreamStream = Box::new(upstream_server);
    let upstream_socket = UpstreamSocket::from_raw_socket(
        upstream_server,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let (upstream_write, _) = upstream_socket.split();
    let upstream_write = Arc::new(AsyncMutex::new(upstream_write));
    let mut upstream_peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        upstream_client,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress = polled.clone();
    let event_stream = stream! {
        for sequence in 0..(MAX_QUEUED_EVENT_FRAMES + 8) {
            progress.fetch_add(1, Ordering::Release);
            yield Ok(serde_json::json!({
                "type": "response.output_text.delta",
                "sequence_number": sequence,
                "delta": "x"
            }));
        }
    };
    let mut output = LlmJsonStream::new(event_stream);
    let relay = tokio::spawn(async move {
        relay_active_response(
            &mut output,
            &mut client_read,
            &client_write,
            &upstream_write,
        )
        .await
    });

    client
        .send(tokio_tungstenite::tungstenite::Message::Ping(
            vec![1, 2, 3].into(),
        ))
        .await
        .unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(2), upstream_peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        forwarded,
        tokio_tungstenite::tungstenite::Message::Ping(payload)
            if payload.as_ref() == [1, 2, 3]
    ));

    let expected = MAX_QUEUED_EVENT_FRAMES + 1;
    tokio::time::timeout(Duration::from_secs(2), async {
        while polled.load(Ordering::Acquire) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(polled.load(Ordering::Acquire), expected);

    drop(blocked_write);
    let reader = tokio::spawn(async move {
        let mut received = 0;
        while received < MAX_QUEUED_EVENT_FRAMES + 8 {
            if matches!(
                client.next().await.unwrap().unwrap(),
                tokio_tungstenite::tungstenite::Message::Text(_)
            ) {
                received += 1;
            }
        }
    });
    assert_eq!(
        relay.await.unwrap().unwrap(),
        ActiveResponseState::Completed
    );
    reader.await.unwrap();
    server.abort();
}

fn test_wss_identity(
    provider_host: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<rustls::ServerConfig>,
) {
    let certified = rcgen::generate_simple_self_signed(vec![provider_host.into()]).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let ca_bundle = temp.path().join("provider-ca.pem");
    crate::filesystem::atomic_write_private(&ca_bundle, certified.cert.pem().as_bytes()).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certified.cert.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .unwrap();
    (temp, ca_bundle, Arc::new(server_config))
}

#[tokio::test]
async fn websocket_wss_stream_chains_through_an_authenticated_corporate_proxy() {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let provider_host = "api.openai.com";
    let (_temp, ca_bundle, server_config) = test_wss_identity(provider_host);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = proxy_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        request_tx
            .send(String::from_utf8(request).unwrap())
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .unwrap();
        let mut socket = tokio_tungstenite::accept_async(tls).await.unwrap();
        let message = socket.next().await.unwrap().unwrap();
        socket.send(message).await.unwrap();
    });
    let proxy = crate::claude_desktop::AgentUpstreamProxy {
        url: format!("http://proxy-user:p%40ss@{proxy_address}"),
        no_proxy: None,
        ca_bundle: Some(ca_bundle),
    };
    let parsed = reqwest::Url::parse("wss://api.openai.com/v1/responses").unwrap();
    let destination = "93.184.216.34:443".parse().unwrap();
    let stream =
        connect_test_upstream_wss_stream(&parsed, Some(&proxy), provider_host, 443, &[destination])
            .await
            .unwrap();
    let request = parsed.as_str().into_client_request().unwrap();
    let (mut socket, _) = tokio_tungstenite::client_async(request, stream)
        .await
        .unwrap();
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "response.create".into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "response.create"
    );

    let request = request_rx.await.unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode("proxy-user:p@ss");
    assert!(request.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
    assert!(request.contains(&format!("Proxy-Authorization: Basic {encoded}\r\n")));
    assert!(!request.contains("p@ss"));
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn websocket_wss_stream_honors_no_proxy_before_tls() {
    let provider_host = "api.openai.com";
    let (_temp, ca_bundle, server_config) = test_wss_identity(provider_host);
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_address = provider_listener.local_addr().unwrap();
    let provider_task = tokio::spawn(async move {
        let (stream, _) = provider_listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .unwrap();
        let mut socket = tokio_tungstenite::accept_async(tls).await.unwrap();
        let message = socket.next().await.unwrap().unwrap();
        socket.send(message).await.unwrap();
    });
    let unused_proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = crate::claude_desktop::AgentUpstreamProxy {
        url: format!("http://{}", unused_proxy.local_addr().unwrap()),
        no_proxy: Some(provider_host.into()),
        ca_bundle: Some(ca_bundle),
    };
    let parsed = reqwest::Url::parse(&format!(
        "wss://{provider_host}:{}/v1/responses",
        provider_address.port()
    ))
    .unwrap();
    let stream = connect_test_upstream_wss_stream(
        &parsed,
        Some(&proxy),
        provider_host,
        provider_address.port(),
        &[provider_address],
    )
    .await
    .unwrap();
    let (mut socket, _) = tokio_tungstenite::client_async(parsed.as_str(), stream)
        .await
        .unwrap();
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "response.create".into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "response.create"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), unused_proxy.accept())
            .await
            .is_err()
    );
    provider_task.await.unwrap();
}

#[tokio::test]
async fn active_upstream_idle_timeout_resets_after_each_frame() {
    let mut active = futures_util::stream::iter([1_u8, 2, 3])
        .then(|value| async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            value
        })
        .boxed();
    for expected in [1_u8, 2, 3] {
        assert_eq!(
            next_with_idle_timeout(&mut active, Duration::from_millis(20)).await,
            Ok(Some(expected))
        );
    }

    let mut stalled = futures_util::stream::pending::<u8>();
    assert_eq!(
        next_with_idle_timeout(&mut stalled, Duration::from_millis(5)).await,
        Err(())
    );
}

#[test]
fn codex_handshake_metadata_is_forwarded_without_transport_headers() {
    let mut upstream = HeaderMap::new();
    upstream.insert("x-codex-turn-state", "turn-state".parse().unwrap());
    upstream.insert("x-models-etag", "models-v1".parse().unwrap());
    upstream.insert("x-reasoning-included", "true".parse().unwrap());
    upstream.insert("openai-model", "gpt-5".parse().unwrap());
    upstream.insert("x-request-id", "request-1".parse().unwrap());
    upstream.insert("sec-websocket-accept", "upstream-only".parse().unwrap());
    upstream.insert("set-cookie", "secret=upstream".parse().unwrap());
    let mut downstream = HeaderMap::new();

    forward_upstream_handshake_headers(&upstream, &mut downstream);

    for name in UPSTREAM_HANDSHAKE_HEADERS {
        assert_eq!(downstream.get(*name), upstream.get(*name), "{name}");
    }
    assert!(!downstream.contains_key("sec-websocket-accept"));
    assert!(!downstream.contains_key("set-cookie"));
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "tungstenite's handshake callback owns this fixed response error type"
)]
async fn websocket_round_trip_authenticates_reencodes_and_preserves_event_order() {
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let socket = tokio_tungstenite::accept_hdr_async(
            stream,
            move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let captured = ["authorization", "openai-model", "x-codex-turn-state"]
                    .into_iter()
                    .map(|name| {
                        (
                            name,
                            request
                                .headers()
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                request_tx.send(captured).unwrap();
                Ok(response)
            },
        )
        .await
        .unwrap();
        let (mut write, mut read) = socket.split();
        let request = read.next().await.unwrap().unwrap().into_text().unwrap();
        let request: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["type"], "response.create");
        assert_eq!(request["model"], "gpt-5");
        assert_eq!(request["input"], "managed request");
        for event in [
            serde_json::json!({
                "type": "response.created",
                "sequence_number": 0,
                "response": {"id": "resp_ws", "model": "gpt-5"}
            }),
            serde_json::json!({
                "type": "response.completed",
                "sequence_number": 1,
                "response": {
                    "id": "resp_ws",
                    "model": "gpt-5",
                    "status": "completed",
                    "output": []
                }
            }),
        ] {
            write
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    event.to_string().into(),
                ))
                .await
                .unwrap();
        }
    });

    let config = crate::configuration::GatewayConfig {
        openai_base_url: format!("http://{upstream_address}/v1"),
        ..Default::default()
    };
    let app = crate::server::router(config);
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let gateway_task = tokio::spawn(async move {
        axum::serve(gateway_listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let mut request = format!("ws://{gateway_address}/responses")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        "Bearer websocket-provider-key".parse().unwrap(),
    );
    request
        .headers_mut()
        .insert("openai-model", "gpt-5".parse().unwrap());
    request
        .headers_mut()
        .insert("x-codex-turn-state", "turn-state-1".parse().unwrap());
    let (mut client, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    client
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "type": "response.create",
                "model": "gpt-5",
                "input": "managed request"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let mut event_types = Vec::new();
    while event_types.len() < 2 {
        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                let event: Value = serde_json::from_str(&text).unwrap();
                event_types.push(event["type"].as_str().unwrap().to_string());
            }
            tokio_tungstenite::tungstenite::Message::Close(frame) => {
                panic!("managed WebSocket closed before terminal events: {frame:?}");
            }
            _ => {}
        }
    }
    assert_eq!(
        event_types,
        ["response.created", "response.completed"],
        "provider-visible event ordering changed"
    );
    let captured = request_rx.await.unwrap();
    assert_eq!(
        captured["authorization"].as_deref(),
        Some("Bearer websocket-provider-key")
    );
    assert_eq!(captured["openai-model"].as_deref(), Some("gpt-5"));
    assert_eq!(
        captured["x-codex-turn-state"].as_deref(),
        Some("turn-state-1")
    );

    let _ = client.close(None).await;
    shutdown_tx.send(()).unwrap();
    upstream_task.await.unwrap();
    gateway_task.await.unwrap();
}

async fn concurrent_upstream_response(
    listener: std::sync::Arc<tokio::net::TcpListener>,
    release: std::sync::Arc<tokio::sync::Barrier>,
    sessions: tokio::sync::mpsc::Sender<String>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
    let (mut write, mut read) = socket.split();
    let request = read.next().await.unwrap().unwrap().into_text().unwrap();
    let request: Value = serde_json::from_str(&request).unwrap();
    let session_id = request["client_metadata"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    sessions.send(session_id.clone()).await.unwrap();
    release.wait().await;
    for event in [
        serde_json::json!({
            "type": "response.created",
            "sequence_number": 0,
            "response": {"id": format!("resp-{session_id}"), "model": "gpt-5"}
        }),
        serde_json::json!({
            "type": "response.completed",
            "sequence_number": 1,
            "response": {
                "id": format!("resp-{session_id}"),
                "model": "gpt-5",
                "status": "completed",
                "output": []
            }
        }),
    ] {
        write
            .send(tokio_tungstenite::tungstenite::Message::Text(
                event.to_string().into(),
            ))
            .await
            .unwrap();
    }
}

async fn collect_terminal_events<S>(client: &mut S)
where
    S: futures_util::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    let mut terminal = false;
    while !terminal {
        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = message {
            let event: Value = serde_json::from_str(&text).unwrap();
            terminal = event["type"] == "response.completed";
        }
    }
}

#[tokio::test]
async fn concurrent_websockets_keep_distinct_session_instance_lineages() {
    let upstream = std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    let upstream_address = upstream.local_addr().unwrap();
    let release = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let (sessions_tx, mut sessions_rx) = tokio::sync::mpsc::channel(2);
    let upstream_a = tokio::spawn(concurrent_upstream_response(
        upstream.clone(),
        release.clone(),
        sessions_tx.clone(),
    ));
    let upstream_b = tokio::spawn(concurrent_upstream_response(
        upstream,
        release.clone(),
        sessions_tx,
    ));

    let config = crate::configuration::GatewayConfig {
        openai_base_url: format!("http://{upstream_address}/v1"),
        ..Default::default()
    };
    let state = crate::server::AppState::new(config);
    let manager = state.sessions.clone();
    let app = crate::server::router_with_state(state);
    let gateway = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(gateway, app).await.unwrap();
    });

    let mut request_a = format!("ws://{gateway_address}/responses")
        .into_client_request()
        .unwrap();
    request_a.headers_mut().insert(
        "authorization",
        "Bearer websocket-provider-key".parse().unwrap(),
    );
    let request_b = request_a.clone();
    let (mut client_a, _) = tokio_tungstenite::connect_async(request_a).await.unwrap();
    let (mut client_b, _) = tokio_tungstenite::connect_async(request_b).await.unwrap();
    for (client, session_id) in [(&mut client_a, "codex-ws-a"), (&mut client_b, "codex-ws-b")] {
        client
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({
                    "type": "response.create",
                    "model": "gpt-5",
                    "input": "managed request",
                    "client_metadata": {
                        "x-codex-installation-id": "test-installation",
                        "session_id": session_id
                    }
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
    }
    let mut upstream_sessions = vec![
        sessions_rx.recv().await.unwrap(),
        sessions_rx.recv().await.unwrap(),
    ];
    upstream_sessions.sort();
    assert_eq!(upstream_sessions, ["codex-ws-a", "codex-ws-b"]);
    release.wait().await;
    tokio::join!(
        collect_terminal_events(&mut client_a),
        collect_terminal_events(&mut client_b)
    );

    let instance_a = manager.session_instance_id("codex-ws-a").await.unwrap();
    let instance_b = manager.session_instance_id("codex-ws-b").await.unwrap();
    assert_ne!(instance_a, instance_b);
    assert!(!instance_a.is_empty());
    assert!(!instance_b.is_empty());

    let _ = client_a.close(None).await;
    let _ = client_b.close(None).await;
    server.abort();
    upstream_a.await.unwrap();
    upstream_b.await.unwrap();
}
