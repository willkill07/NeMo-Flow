// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::Router;
use axum::extract::State;
use futures_util::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[test]
fn connect_parser_requires_authority_and_port() {
    let uri = "api.anthropic.com:443".parse::<http::Uri>().unwrap();
    assert_eq!(
        parse_connect_authority(&uri).unwrap(),
        ("api.anthropic.com".into(), 443)
    );
    assert!(parse_connect_authority(&"api.anthropic.com".parse().unwrap()).is_err());
    assert!(parse_connect_authority(&"/path".parse().unwrap()).is_err());
    assert_eq!(
        parse_connect_authority(&"[2606:4700:4700::1111]:443".parse().unwrap()).unwrap(),
        ("2606:4700:4700::1111".into(), 443)
    );
}

#[test]
fn private_loopback_and_reserved_addresses_are_not_public() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "203.0.113.1",
        "::1",
        "::127.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:0:127.0.0.1",
        "400::1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "100::1",
        "2001:db8::1",
        "2002:7f00:1::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[test]
fn supported_inference_routes_are_managed() {
    assert_eq!(
        classify_route(&Method::POST, "/v1/messages"),
        Route::Managed
    );
    assert_eq!(
        classify_route(&Method::POST, "/v1/messages/count_tokens"),
        Route::Managed
    );
}

#[test]
fn unsupported_inference_routes_are_rejected() {
    assert!(matches!(
        classify_route(&Method::POST, "/v1/messages/batches"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::POST, "/v1/complete"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::POST, "/v1/unknown-inference"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::GET, "/v1/messages"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::POST, "/v1/messages/batches/one"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::POST, "/v1/completions"),
        Route::Rejected(_)
    ));
}

#[test]
fn control_routes_require_an_audited_method_and_path() {
    assert_eq!(classify_route(&Method::GET, "/v1/models"), Route::Control);
    assert_eq!(
        classify_route(&Method::PATCH, "/api/organizations/test"),
        Route::Control
    );
    assert_eq!(
        classify_route(&Method::DELETE, "/v1/mcp/server"),
        Route::Control
    );
    assert!(matches!(
        classify_route(&Method::TRACE, "/v1/models"),
        Route::Rejected(_)
    ));
    assert!(matches!(
        classify_route(&Method::GET, "/not-allowed"),
        Route::Rejected(_)
    ));
}

#[test]
fn provider_routes_reject_path_confusion_before_classification() {
    for path in [
        "/v1/oauth/../messages/batches",
        "/v1/oauth/%2e%2e/messages/batches",
        "/v1/oauth/%2E%2E%2Fmessages/batches",
        "/v1/oauth//token",
        "/v1/oauth/..%5cmessages/batches",
        "/v1/oauth/%",
    ] {
        for host in ["api.anthropic.com", "api.openai.com", "chatgpt.com"] {
            assert!(
                matches!(
                    classify_provider_route(host, &Method::POST, path),
                    Route::Rejected(_)
                ),
                "{host} {path}"
            );
        }
        assert!(
            matches!(classify_route(&Method::POST, path), Route::Rejected(_)),
            "{path}"
        );
    }
}

#[test]
fn native_provider_routes_are_host_specific_and_fail_closed() {
    for path in [
        "/responses",
        "/v1/responses",
        "/chat/completions",
        "/v1/chat/completions",
    ] {
        assert_eq!(
            classify_provider_route("api.openai.com", &Method::POST, path),
            Route::Managed
        );
    }
    assert_eq!(
        classify_provider_route("api.openai.com", &Method::GET, "/v1/models"),
        Route::Managed
    );
    assert_eq!(
        classify_provider_route("chatgpt.com", &Method::POST, "/backend-api/codex/responses"),
        Route::Managed
    );
    assert_eq!(
        classify_provider_route("chatgpt.com", &Method::GET, "/api/auth/session"),
        Route::Control
    );
    for (host, method, path) in [
        ("api.openai.com", Method::GET, "/v1/responses"),
        ("api.openai.com", Method::POST, "/v1/files"),
        ("chatgpt.com", Method::POST, "/backend-api/codex/unknown"),
        ("chatgpt.com", Method::GET, "/not-a-codex-route"),
    ] {
        assert!(
            matches!(
                classify_provider_route(host, &method, path),
                Route::Rejected(_)
            ),
            "{host} {method} {path}"
        );
    }
}

#[test]
fn agent_credentials_select_only_their_enrolled_provider_hosts() {
    let claude = AuthenticatedRoute::Agent("claude".into());
    let codex = AuthenticatedRoute::Agent("codex".into());
    let hermes = AuthenticatedRoute::Agent("hermes".into());
    let control = AuthenticatedRoute::Control;

    assert!(agent_allows_intercepted_host(&claude, "api.anthropic.com"));
    assert!(!agent_allows_intercepted_host(&claude, "api.openai.com"));
    assert!(agent_allows_intercepted_host(&codex, "api.openai.com"));
    assert!(agent_allows_intercepted_host(&codex, "chatgpt.com"));
    assert!(!agent_allows_intercepted_host(&codex, "api.anthropic.com"));
    for host in INTERCEPTED_HOSTS {
        assert!(agent_allows_intercepted_host(&hermes, host));
        assert!(!agent_allows_intercepted_host(&control, host));
    }
    for route in [&claude, &codex, &control] {
        assert!(!agent_allows_intercepted_host(route, "example.com"));
    }
    assert!(agent_allows_intercepted_host(&hermes, "example.com"));
}

#[test]
fn agent_credentials_select_only_their_enrolled_direct_paths() {
    let claude = AuthenticatedRoute::Agent("claude".into());
    let codex = AuthenticatedRoute::Agent("codex".into());
    let hermes = AuthenticatedRoute::Agent("hermes".into());
    let control = AuthenticatedRoute::Control;
    assert!(direct_path_allowed(&claude, "/v1/messages"));
    assert!(!direct_path_allowed(&claude, "/responses"));
    assert!(direct_path_allowed(&codex, "/responses"));
    assert!(!direct_path_allowed(&codex, "/v1/messages"));
    assert!(direct_path_allowed(&hermes, "/responses"));
    assert!(direct_path_allowed(&hermes, "/v1/messages"));
    assert!(direct_path_allowed(&codex, "/hooks/codex"));
    assert!(!direct_path_allowed(&codex, "/hooks/hermes"));
    assert!(!direct_path_allowed(&control, "/healthz"));
}

#[test]
fn authenticated_hook_route_replaces_untrusted_enrollment_identity() {
    let mut headers = HeaderMap::new();
    headers.insert(ENROLLED_AGENT_HEADER, "spoofed".parse().unwrap());
    set_enrolled_hook_identity(
        &mut headers,
        "/hooks/hermes",
        &AuthenticatedRoute::Agent("hermes".into()),
    );
    assert_eq!(
        headers
            .get(ENROLLED_AGENT_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("hermes")
    );

    set_enrolled_hook_identity(
        &mut headers,
        "/responses",
        &AuthenticatedRoute::Agent("hermes".into()),
    );
    assert!(!headers.contains_key(ENROLLED_AGENT_HEADER));
}

#[test]
fn no_proxy_matching_honors_domain_and_port() {
    assert!(no_proxy_matches(
        Some("localhost .example.com"),
        "api.example.com",
        443,
        &[]
    ));
    assert!(!no_proxy_matches(
        Some("example.com:80"),
        "example.com",
        443,
        &[]
    ));
    assert!(no_proxy_matches(Some("*"), "anything.example", 443, &[]));
    assert!(no_proxy_matches(
        Some("[2606:4700:4700::1111]:443"),
        "2606:4700:4700::1111",
        443,
        &[]
    ));
    assert!(no_proxy_matches(
        Some("2606:4700:4700::1111"),
        "2606:4700:4700::1111",
        443,
        &[]
    ));
    assert!(!no_proxy_matches(
        Some("[2606:4700:4700::1111]:80"),
        "2606:4700:4700::1111",
        443,
        &[]
    ));
    assert!(no_proxy_matches(
        Some("8.8.8.0/24"),
        "dns.example",
        443,
        &["8.8.8.8:443".parse().unwrap()]
    ));
    assert!(!no_proxy_matches(
        Some("8.8.4.0/24"),
        "dns.example",
        443,
        &["8.8.8.8:443".parse().unwrap()]
    ));
}

#[test]
fn proxy_url_credentials_are_separated_from_destination() {
    let (url, auth) = proxy_url_and_auth("https://user:p%40ss@proxy.example:8443").unwrap();
    assert_eq!(url.as_str(), "https://proxy.example:8443/");
    assert_eq!(auth, Some(("user".into(), "p@ss".into())));
}

#[test]
fn proxy_authentication_requires_one_exact_basic_credential() {
    let mut headers = HeaderMap::new();
    let good = base64::engine::general_purpose::STANDARD.encode("relay:secret");
    headers.insert(
        PROXY_AUTHORIZATION,
        format!("Basic {good}").parse().unwrap(),
    );
    assert!(authenticate(&headers, "relay", "secret").is_ok());
    assert!(authenticate(&headers, "relay", "different").is_err());
    headers.append(
        PROXY_AUTHORIZATION,
        format!("Basic {good}").parse().unwrap(),
    );
    assert!(authenticate(&headers, "relay", "secret").is_err());

    for invalid in [
        "Bearer token",
        "Basic",
        "Basic ",
        "Basic not-base64!",
        "Basic Zm9v\n",
    ] {
        let mut headers = HeaderMap::new();
        if let Ok(value) = invalid.parse() {
            headers.insert(PROXY_AUTHORIZATION, value);
        }
        assert!(authenticate(&headers, "relay", "secret").is_err());
    }
}

#[test]
fn persisted_credentials_resolve_to_control_or_one_agent() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state(dir.path(), "credential-routing");
    state.enrollments.insert(
        "codex".into(),
        super::super::state::AgentEnrollment {
            username: "codex-user".into(),
            token: "codex-token".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            upstream_proxy: None,
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    for (credential, expected) in [
        ("control:control-secret", "control"),
        ("codex-user:codex-token", "codex"),
    ] {
        let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let selected = authenticate_state(&headers, &state).unwrap();
        match selected {
            AuthenticatedRoute::Control => assert_eq!(expected, "control"),
            AuthenticatedRoute::Agent(agent) => assert_eq!(agent, expected),
        }
    }

    let mut headers = HeaderMap::new();
    let encoded = base64::engine::general_purpose::STANDARD.encode("codex-user:wrong");
    headers.insert(
        PROXY_AUTHORIZATION,
        format!("Basic {encoded}").parse().unwrap(),
    );
    assert!(authenticate_state(&headers, &state).is_err());
}

#[test]
fn credential_classification_compares_every_enrollment_before_branching() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state(dir.path(), "constant-work-auth");
    for agent in ["claude", "codex", "hermes"] {
        state.enrollments.insert(
            agent.into(),
            super::super::state::AgentEnrollment {
                username: format!("{agent}-user"),
                token: format!("{agent}-token"),
                installed_at: "2026-01-01T00:00:00Z".into(),
                upstream_proxy: None,
                client_ca_bundle_source: None,
                client_ca_bundle_variable: None,
            },
        );
    }

    for credential in [
        "control:control-secret",
        "claude-code-user:claude-code-token",
    ] {
        let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let mut comparisons = 0;
        authenticate_state_with(&headers, &state, |presented, expected| {
            comparisons += 1;
            presented == expected
        })
        .unwrap();
        assert_eq!(comparisons, state.enrollments.len() + 1);
    }
}

#[test]
fn direct_enrollment_never_inherits_shared_or_other_agent_proxy_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state(dir.path(), "route-isolation");
    state.upstream_proxy = Some(UpstreamProxy {
        url: "http://legacy-shared.example:8080".into(),
        no_proxy: None,
        ca_bundle: None,
    });
    state.enrollments.insert(
        "codex".into(),
        super::super::state::AgentEnrollment {
            username: "codex".into(),
            token: "codex-token".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            upstream_proxy: Some(UpstreamProxy {
                url: "http://codex-corporate.example:8080".into(),
                no_proxy: None,
                ca_bundle: None,
            }),
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    let tls = super::super::certificate::server_config(dir.path(), &state.certificate).unwrap();
    let (shutdown, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown).unwrap();

    assert!(runtime.agent_routes["claude"].upstream_proxy.is_none());
    assert_eq!(
        runtime.agent_routes["codex"]
            .upstream_proxy
            .as_ref()
            .unwrap()
            .url,
        "http://codex-corporate.example:8080"
    );
}

#[test]
fn forwarding_preserves_oauth_but_strips_proxy_credentials() {
    let mut headers = HeaderMap::new();
    headers.append(CONNECTION, "x-first, X-Second".parse().unwrap());
    headers.append(CONNECTION, "x-third".parse().unwrap());
    assert!(should_forward_header(
        &http::header::AUTHORIZATION,
        &headers
    ));
    assert!(!should_forward_header(&PROXY_AUTHORIZATION, &headers));
    assert!(!should_forward_header(&PROXY_AUTHENTICATE, &headers));
    assert!(!should_forward_header(
        &http::HeaderName::from_static(AGENT_AUTHORIZATION_HEADER),
        &headers
    ));
    for stripped in [
        CONNECTION,
        TRANSFER_ENCODING,
        HOST,
        TE,
        TRAILER,
        UPGRADE,
        http::HeaderName::from_static("keep-alive"),
        http::HeaderName::from_static("proxy-connection"),
        http::HeaderName::from_static("x-first"),
        http::HeaderName::from_static("x-second"),
        http::HeaderName::from_static("x-third"),
    ] {
        assert!(!should_forward_header(&stripped, &headers));
    }
}

#[test]
fn upstream_client_supports_basic_auth_no_proxy_and_custom_ca() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "upstream-client");
    let proxy = UpstreamProxy {
        url: "https://user:pass@proxy.example:8443".into(),
        no_proxy: Some("localhost example.com".into()),
        ca_bundle: Some(state.certificate.root_pem.clone()),
    };
    upstream_client(Some(&proxy)).unwrap();
    upstream_client(None).unwrap();

    let empty = temp.path().join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    let invalid = UpstreamProxy {
        ca_bundle: Some(empty),
        ..proxy.clone()
    };
    assert!(
        upstream_client(Some(&invalid))
            .unwrap_err()
            .contains("no certificates")
    );
    let invalid = UpstreamProxy {
        url: "::not a URL::".into(),
        ca_bundle: None,
        ..proxy
    };
    assert!(upstream_client(Some(&invalid)).is_err());
}

#[tokio::test]
async fn upstream_clients_do_not_follow_redirects_outside_the_allowlist() {
    let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_address = redirect_listener.local_addr().unwrap();
    let forbidden_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forbidden_address = forbidden_listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = redirect_listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{forbidden_address}/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });

    let response = upstream_client(None)
        .unwrap()
        .get(format!("http://{redirect_address}/start"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), forbidden_listener.accept())
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn managed_http_sender_rejects_non_native_or_non_https_targets() {
    let route = super::super::AgentRouteContext {
        agent: "codex".into(),
        upstream_proxy: None,
    };
    for target in [
        "http://api.openai.com/v1/responses",
        "https://127.0.0.1/v1/responses",
        "https://example.com/v1/responses",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(target)
            .body(Body::empty())
            .unwrap();
        assert!(
            super::super::send_provider_http(&route, request)
                .await
                .unwrap_err()
                .contains("outside the native HTTPS host set")
        );
    }
}

#[tokio::test]
async fn tunnel_idle_timeout_resets_while_either_direction_is_active() {
    let (mut client_first, mut tunnel_first) = tokio::io::duplex(64);
    let (mut tunnel_second, mut client_second) = tokio::io::duplex(64);
    let copy = tokio::spawn(async move {
        copy_bidirectional_with_idle_timeout(
            &mut tunnel_first,
            &mut tunnel_second,
            Duration::from_millis(70),
        )
        .await
    });

    for value in 0_u8..4 {
        client_first.write_all(&[value]).await.unwrap();
        let mut received = [0_u8; 1];
        client_second.read_exact(&mut received).await.unwrap();
        assert_eq!(received, [value]);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    client_first.shutdown().await.unwrap();
    client_second.shutdown().await.unwrap();
    copy.await.unwrap().unwrap();

    let (_client_first, mut tunnel_first) = tokio::io::duplex(8);
    let (mut tunnel_second, _client_second) = tokio::io::duplex(8);
    let error = copy_bidirectional_with_idle_timeout(
        &mut tunnel_first,
        &mut tunnel_second,
        Duration::from_millis(30),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn authority_host_proxy_and_response_helpers_cover_malformed_inputs() {
    for raw in [
        "http://user@example.com:443/path",
        "http://example.com:0/path",
    ] {
        let uri = raw.parse::<http::Uri>().unwrap();
        assert!(parse_connect_authority(&uri).is_err());
    }
    assert!(proxy_url_and_auth("not a url").is_err());
    assert!(proxy_url_and_auth("http://%FF:pass@proxy.example").is_err());

    let mut host = HeaderMap::new();
    host.insert(HOST, "api.anthropic.com:443".parse().unwrap());
    assert!(validate_anthropic_host(&host).is_ok());
    host.insert(HOST, "other.example".parse().unwrap());
    assert!(validate_anthropic_host(&host).is_err());
    host.append(HOST, "api.anthropic.com".parse().unwrap());
    assert!(validate_anthropic_host(&host).is_err());

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let response = text_response(StatusCode::FORBIDDEN, "blocked");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "blocked"
        );
        assert_eq!(
            empty_response(StatusCode::NO_CONTENT).status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(connect_response().status(), StatusCode::OK);
    });
}

#[tokio::test]
async fn upstream_connect_chains_basic_auth_without_cleartext_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
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
        let mut ping = [0_u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let proxy = UpstreamProxy {
        url: format!("http://user:p%40ss@{address}"),
        no_proxy: None,
        ca_bundle: None,
    };

    let destination = "93.184.216.34:443".parse().unwrap();
    let mut tunnel = connect_through_upstream_proxy(&proxy, destination)
        .await
        .unwrap();
    tunnel.write_all(b"ping").await.unwrap();
    let mut pong = [0_u8; 4];
    tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    let request = request_rx.await.unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode("user:p@ss");
    assert!(request.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
    assert!(request.contains(&format!("Proxy-Authorization: Basic {encoded}\r\n")));
    assert!(!request.contains("p@ss"));
    upstream.await.unwrap();
}

#[tokio::test]
async fn upstream_connect_reports_rejection_truncates_credentials_and_handles_closed_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
    });
    let proxy = UpstreamProxy {
        url: format!("http://secret-user:secret-password@{address}"),
        no_proxy: None,
        ca_bundle: None,
    };
    let error = connect_through_upstream_proxy(&proxy, "93.184.216.34:443".parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(error.contains("HTTP 407"));
    assert!(!error.contains("secret-user"));
    assert!(!error.contains("secret-password"));
    task.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        drop(stream);
    });
    let proxy = UpstreamProxy {
        url: format!("http://{address}"),
        no_proxy: None,
        ca_bundle: None,
    };
    assert!(
        connect_through_upstream_proxy(&proxy, "93.184.216.34:443".parse().unwrap())
            .await
            .err()
            .unwrap()
            .contains("closed before completing")
    );
    task.await.unwrap();
}

#[test]
fn upstream_connect_status_never_reflects_untrusted_status_text() {
    assert_eq!(
        upstream_connect_status("HTTP/1.1 200 Connection established\r\n\r\n").unwrap(),
        200
    );
    assert_eq!(
        upstream_connect_status("HTTP/1.0 407 Proxy Authentication Required\r\n\r\n").unwrap(),
        407
    );
    for malformed in [
        "",
        "NOT-HTTP 200 \u{1b}[31msecret\r\n\r\n",
        "HTTP/1.1 nope secret\r\n\r\n",
        "HTTP/2 200 secret\r\n\r\n",
        "HTTP/1.1 999 secret\r\n\r\n",
    ] {
        let error = upstream_connect_status(malformed).unwrap_err();
        assert_eq!(
            error,
            "corporate proxy returned a malformed CONNECT response"
        );
        assert!(!error.contains("secret"));
        assert!(!error.contains('\u{1b}'));
    }
}

#[tokio::test]
async fn https_corporate_proxy_uses_custom_ca_and_fails_cleanly_on_bad_tls() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "https-upstream");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut client_hello = [0_u8; 1024];
        assert!(stream.read(&mut client_hello).await.unwrap() > 0);
    });
    let proxy = UpstreamProxy {
        url: format!("https://{address}"),
        no_proxy: None,
        ca_bundle: Some(state.certificate.root_pem),
    };

    let error = connect_through_upstream_proxy(&proxy, "93.184.216.34:443".parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        error.contains("TLS handshake with corporate proxy"),
        "{error}"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn address_resolution_and_connection_reject_local_or_unreachable_targets() {
    assert!(
        validate_public_addresses(
            "mixed.example",
            &[
                "93.184.216.34:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
        )
        .unwrap_err()
        .contains("private")
    );
    assert!(
        resolve_public_addresses("localhost", 443)
            .await
            .unwrap_err()
            .contains("local hostname")
    );
    assert!(
        resolve_public_addresses("127.0.0.1", 443)
            .await
            .unwrap_err()
            .contains("IP-literal")
    );
    assert!(
        resolve_public_addresses("2606:4700:4700::1111", 443)
            .await
            .unwrap_err()
            .contains("IP-literal")
    );
    assert!(
        resolve_public_addresses("invalid host name", 443)
            .await
            .unwrap_err()
            .contains("failed to resolve")
    );
    assert!(
        connect_addresses(&[])
            .await
            .unwrap_err()
            .contains("no address")
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(
        connect_addresses(&[address])
            .await
            .unwrap_err()
            .contains("could not connect")
    );
}

#[tokio::test]
async fn corporate_proxy_header_reader_enforces_encoding_completion_and_size() {
    let (mut writer, reader) = tokio::io::duplex(CONNECT_HEADER_LIMIT + 32);
    writer
        .write_all(b"HTTP/1.1 200 OK\r\nHeader: value\r\n\r\n")
        .await
        .unwrap();
    let mut reader: BoxStream = Box::new(reader);
    assert!(read_headers(&mut reader).await.unwrap().contains("200 OK"));

    let (writer, reader) = tokio::io::duplex(8);
    drop(writer);
    let mut reader: BoxStream = Box::new(reader);
    assert!(
        read_headers(&mut reader)
            .await
            .unwrap_err()
            .contains("closed before completing")
    );

    let (mut writer, reader) = tokio::io::duplex(8);
    writer.write_all(b"\xff\r\n\r\n").await.unwrap();
    let mut reader: BoxStream = Box::new(reader);
    assert!(
        read_headers(&mut reader)
            .await
            .unwrap_err()
            .contains("not UTF-8")
    );

    let (mut writer, reader) = tokio::io::duplex(CONNECT_HEADER_LIMIT + 1);
    writer
        .write_all(&vec![b'a'; CONNECT_HEADER_LIMIT])
        .await
        .unwrap();
    let mut reader: BoxStream = Box::new(reader);
    assert!(
        read_headers(&mut reader)
            .await
            .unwrap_err()
            .contains("exceed")
    );
}

#[tokio::test]
async fn control_surface_rejects_wrong_auth_and_returns_fenced_health() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "proxy-test");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));

    let wrong = raw_control_request(address, "control:wrong").await;
    assert!(wrong.starts_with("HTTP/1.1 407"), "{wrong}");
    let valid = raw_control_request(address, "control:control-secret").await;
    assert!(valid.starts_with("HTTP/1.1 200"), "{valid}");
    assert!(valid.contains("\"generation\":\"proxy-test\""));
    assert!(valid.contains("\"configuration_fingerprint\":\"configuration\""));
    assert!(!valid.contains("secret"));

    let wrong_host = raw_authenticated_request(
        address,
        "control:control-secret",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n",
    )
    .await;
    assert!(wrong_host.starts_with("HTTP/1.1 405"), "{wrong_host}");
    let missing = raw_authenticated_request(
        address,
        "control:control-secret",
        &format!("GET http://{CONTROL_HOST}/missing HTTP/1.1\r\nHost: {CONTROL_HOST}\r\n"),
    )
    .await;
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    let forbidden_tunnel = raw_authenticated_request(
        address,
        "control:control-secret",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n",
    )
    .await;
    assert!(
        forbidden_tunnel.starts_with("HTTP/1.1 403"),
        "{forbidden_tunnel}"
    );
    let shutdown = raw_authenticated_request(
        address,
        "control:control-secret",
        &format!(
            "POST http://{CONTROL_HOST}{SHUTDOWN_PATH} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nContent-Length: 0\r\n"
        ),
    )
    .await;
    assert!(shutdown.starts_with("HTTP/1.1 204"), "{shutdown}");
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn persistent_proxy_injects_durable_http_auth_only_after_enrollment_auth() {
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let captured_calls = upstream_calls.clone();
    let upstream = Router::new().route(
        "/v1/models",
        axum::routing::get(move |headers: HeaderMap| {
            let captured_calls = captured_calls.clone();
            async move {
                captured_calls.fetch_add(1, Ordering::AcqRel);
                headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("missing")
                    .to_string()
            }
        }),
    );
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });

    let temp = tempfile::tempdir().unwrap();
    let mut state = test_state(temp.path(), "persistent-http-auth");
    let enrollment = state.enrollments.remove("claude").unwrap();
    state.enrollments.insert("codex".into(), enrollment);
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let config = crate::configuration::GatewayConfig {
        openai_base_url: format!("http://{upstream_address}/v1"),
        openai_auth_header: Some("Bearer durable-http-config".into()),
        ..Default::default()
    };
    let dispatcher = crate::server::ManagedProviderDispatcher::for_test(config);
    let (shutdown_tx, _) = watch::channel(false);
    let mut runtime =
        Runtime::new_with_dispatcher(state, tls, dispatcher, shutdown_tx.clone()).unwrap();
    // The production route context deliberately rejects loopback upstreams. This test's local
    // provider observes the managed engine after the outer proxy has already enforced the Codex
    // enrollment credential, so omit only the transport route context.
    runtime.agent_routes = Arc::new(std::collections::BTreeMap::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(serve_plain(listener, runtime));

    let rejected = raw_authenticated_request(
        address,
        "relay:wrong",
        "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n",
    )
    .await;
    assert!(rejected.starts_with("HTTP/1.1 407"), "{rejected}");
    assert_eq!(upstream_calls.load(Ordering::Acquire), 0);

    let accepted = raw_authenticated_request(
        address,
        "relay:secret",
        "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n",
    )
    .await;
    assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
    assert!(
        accepted.contains("Bearer durable-http-config"),
        "{accepted}"
    );
    assert_eq!(upstream_calls.load(Ordering::Acquire), 1);

    shutdown_tx.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    upstream_task.abort();
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "tungstenite's handshake callback owns this fixed response error type"
)]
async fn persistent_proxy_websocket_injects_durable_auth_after_enrollment_auth() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let (headers_tx, headers_rx) = oneshot::channel();
    let (responses_tx, responses_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let socket = tokio_tungstenite::accept_hdr_async(
            stream,
            move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                headers_tx
                    .send((
                        request.headers().get("authorization").cloned(),
                        request
                            .headers()
                            .get(AGENT_AUTHORIZATION_HEADER)
                            .cloned(),
                        request.headers().get(PROXY_AUTHORIZATION).cloned(),
                    ))
                    .unwrap();
                response
                    .headers_mut()
                    .insert("x-codex-turn-state", "persisted-turn".parse().unwrap());
                Ok(response)
            },
        )
        .await
        .unwrap();
        let (mut write, mut read) = socket.split();
        let ping = read.next().await.unwrap().unwrap();
        assert!(matches!(
            ping,
            tokio_tungstenite::tungstenite::Message::Ping(ref payload)
                if payload.as_ref() == b"relay-ping"
        ));
        write.flush().await.unwrap();
        for sequence in 1..=2 {
            let request = read.next().await.unwrap().unwrap().into_text().unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["type"], "response.create");
            write
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::json!({
                        "type": "response.completed",
                        "sequence_number": sequence,
                        "response": {
                            "id": format!("resp_proxy_ws_{sequence}"),
                            "model": "gpt-5",
                            "status": "completed",
                            "output": []
                        }
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();
        }
        responses_tx.send(()).unwrap();
        let _ = release_rx.await;
    });

    let temp = tempfile::tempdir().unwrap();
    let mut state = test_state(temp.path(), "persistent-websocket");
    let enrollment = state.enrollments.remove("claude").unwrap();
    state.enrollments.insert("codex".into(), enrollment);
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let config = crate::configuration::GatewayConfig {
        openai_base_url: format!("http://{upstream_address}/v1"),
        openai_auth_header: Some("Bearer durable-websocket-config".into()),
        ..Default::default()
    };
    let dispatcher = crate::server::ManagedProviderDispatcher::for_test(config);
    let (shutdown_tx, _) = watch::channel(false);
    let configuration_valid = Arc::new(AtomicBool::new(true));
    let verifier_state = configuration_valid.clone();
    let runtime = Runtime::new_with_dispatcher(state, tls, dispatcher, shutdown_tx.clone())
        .unwrap()
        .with_configuration_verifier(move || {
            verifier_state
                .load(Ordering::Acquire)
                .then_some(())
                .ok_or_else(|| "configuration fingerprint changed".to_string())
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(serve_plain(listener, runtime));

    let mut rejected = format!("ws://{address}/responses")
        .into_client_request()
        .unwrap();
    rejected.headers_mut().insert(
        AGENT_AUTHORIZATION_HEADER,
        "Basic d3Jvbmc6Y3JlZGVudGlhbA==".parse().unwrap(),
    );
    match tokio_tungstenite::connect_async(rejected)
        .await
        .unwrap_err()
    {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        }
        error => panic!("unexpected rejected WebSocket error: {error}"),
    }

    let mut request = format!("ws://{address}/responses")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        AGENT_AUTHORIZATION_HEADER,
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("relay:secret")
        )
        .parse()
        .unwrap(),
    );
    let (mut client, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("x-codex-turn-state")
            .and_then(|value| value.to_str().ok()),
        Some("persisted-turn")
    );
    client
        .send(tokio_tungstenite::tungstenite::Message::Ping(
            b"relay-ping".to_vec().into(),
        ))
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        pong,
        tokio_tungstenite::tungstenite::Message::Pong(ref payload)
            if payload.as_ref() == b"relay-ping"
    ));
    for sequence in 1..=2 {
        client
            .send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::json!({
                    "type": "response.create",
                    "model": "gpt-5",
                    "input": format!("managed through persistent proxy {sequence}")
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let event = loop {
            let message = tokio::time::timeout(Duration::from_secs(2), client.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            match message {
                tokio_tungstenite::tungstenite::Message::Text(event) => break event,
                tokio_tungstenite::tungstenite::Message::Ping(_)
                | tokio_tungstenite::tungstenite::Message::Pong(_) => {}
                tokio_tungstenite::tungstenite::Message::Close(frame) => {
                    panic!("persistent managed WebSocket closed unexpectedly: {frame:?}");
                }
                message => panic!("unexpected persistent WebSocket frame: {message:?}"),
            }
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&event).unwrap()["type"],
            "response.completed"
        );
    }
    responses_rx.await.unwrap();
    configuration_valid.store(false, Ordering::Release);
    client
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "type": "response.create",
                "model": "gpt-5",
                "input": "must fail after live configuration changes"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let close = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match close {
        tokio_tungstenite::tungstenite::Message::Close(Some(frame)) => {
            assert_eq!(u16::from(frame.code), 1008);
            assert!(frame.reason.contains("configuration changed"));
            assert!(!frame.reason.contains("fingerprint"));
        }
        message => panic!("expected live configuration fence close, got {message:?}"),
    }

    let (authorization, agent_authorization, proxy_authorization) = headers_rx.await.unwrap();
    assert_eq!(
        authorization.as_ref().and_then(|value| value.to_str().ok()),
        Some("Bearer durable-websocket-config")
    );
    assert!(agent_authorization.is_none());
    assert!(proxy_authorization.is_none());

    let _ = release_tx.send(());
    shutdown_tx.send(true).unwrap();
    upstream_task.await.unwrap();
    proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn unauthenticated_slow_connections_are_bounded_and_expire() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "bounded-connections");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_with_limits(
        listener,
        runtime,
        1,
        Duration::from_millis(75),
        false,
    ));

    let _slow = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut rejected = TcpStream::connect(address).await.unwrap();
    rejected
        .write_all(b"GET /.nemo-relay/healthz HTTP/1.1\r\nHost: nemo-relay.invalid\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), rejected.read_to_end(&mut response)).await;
    assert!(!response.starts_with(b"HTTP/1.1 200"));

    tokio::time::sleep(Duration::from_millis(100)).await;
    let valid = raw_control_request(address, "control:control-secret").await;
    assert!(valid.starts_with("HTTP/1.1 200"), "{valid}");

    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn control_health_fails_closed_when_live_configuration_changes() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "stale-proxy-test");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone())
        .unwrap()
        .with_configuration_verifier(|| Err("configuration fingerprint changed".into()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));

    let response = raw_control_request(address, "control:control-secret").await;
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "unexpected health response: {response}"
    );
    assert!(!response.contains("fingerprint"));

    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn enrolled_routes_fail_closed_when_live_configuration_changes() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "stale-agent-route");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone())
        .unwrap()
        .with_configuration_verifier(|| Err("configuration fingerprint changed".into()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));

    let response = raw_authenticated_request(
        address,
        "relay:secret",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "unexpected enrolled route response: {response}"
    );
    assert!(!response.contains("fingerprint"));

    let shutdown = raw_authenticated_request(
        address,
        "control:control-secret",
        &format!(
            "POST http://{CONTROL_HOST}{SHUTDOWN_PATH} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\nContent-Length: 0\r\n"
        ),
    )
    .await;
    assert!(shutdown.starts_with("HTTP/1.1 204"), "{shutdown}");
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn proxy_rejects_malformed_connect_requests_before_tunneling() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "connect-validation");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));

    for request in [
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nTransfer-Encoding: chunked\r\n",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nContent-Length: 1\r\n",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nContent-Length: invalid\r\n",
        "CONNECT api.anthropic.com HTTP/1.1\r\nHost: api.anthropic.com\r\n",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: other.example:443\r\n",
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nHost: api.anthropic.com:443\r\n",
    ] {
        let response = raw_authenticated_request(address, "relay:secret", request).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    let non_tls = raw_authenticated_request(
        address,
        "relay:secret",
        "CONNECT api.anthropic.com:8443 HTTP/1.1\r\nHost: api.anthropic.com:8443\r\n",
    )
    .await;
    assert!(non_tls.starts_with("HTTP/1.1 403"), "{non_tls}");
    for target in ["localhost:443", "127.0.0.1:443", "example.com:80"] {
        let local = raw_authenticated_request(
            address,
            "relay:secret",
            &format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"),
        )
        .await;
        assert!(local.starts_with("HTTP/1.1 403"), "{local}");
    }
    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn non_hermes_credentials_reject_unknown_connect_destinations() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = test_state(temp.path(), "unknown-connect-policy");
    state.enrollments.insert(
        "codex".into(),
        super::super::state::AgentEnrollment {
            username: "codex-user".into(),
            token: "codex-token".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            upstream_proxy: None,
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state, tls, shutdown_tx.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));

    for credential in ["relay:secret", "codex-user:codex-token"] {
        let response = raw_authenticated_request(
            address,
            credential,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("not enrolled for this provider host"));
    }

    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn intercepted_routes_fail_closed_and_gateway_failure_is_redacted() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "route-policy");
    let root_der = std::fs::read(&state.certificate.root_der).unwrap();
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime =
        Runtime::new_with_gateway(state, tls, shutdown_tx.clone(), "http://127.0.0.1:1".into())
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_plain(listener, runtime));
    let proxy = Proxy::all(format!("http://{address}"))
        .unwrap()
        .basic_auth("relay", "secret");
    let client = Client::builder()
        .proxy(proxy)
        .add_root_certificate(reqwest::Certificate::from_der(&root_der).unwrap())
        .build()
        .unwrap();

    for path in [
        "/v1/messages/batches",
        "/v1/unknown",
        "/not-a-control-route",
    ] {
        let response = client
            .post(format!("https://{INTERCEPTED_HOST}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let wrong_method = client
        .get(format!("https://{INTERCEPTED_HOST}/v1/messages"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::FORBIDDEN);

    let wrong_host = client
        .post(format!("https://{INTERCEPTED_HOST}/v1/messages"))
        .header(HOST, "other.example")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::MISDIRECTED_REQUEST);

    let failed_gateway = client
        .post(format!("https://{INTERCEPTED_HOST}/v1/messages"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(failed_gateway.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        failed_gateway.text().await.unwrap(),
        "Relay upstream request failed"
    );

    drop(client);
    shutdown_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn fixed_control_client_verifies_identity_and_requests_shutdown() {
    let _port_guard = super::super::FIXED_PORT_TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "fixed-control");
    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new(state.clone(), tls, shutdown_tx.clone()).unwrap();
    let listener = TcpListener::bind(super::super::PROXY_BIND).await.unwrap();
    let task = tokio::spawn(serve(listener, runtime));

    let mut unauthenticated_listener = TcpStream::connect(state.bind).await.unwrap();
    unauthenticated_listener
        .write_all(
            b"GET http://nemo-relay.invalid/.nemo-relay/healthz HTTP/1.1\r\nHost: nemo-relay.invalid\r\n\r\n",
        )
        .await
        .unwrap();
    let mut bytes = [0_u8; 32];
    let read = tokio::time::timeout(
        Duration::from_secs(1),
        unauthenticated_listener.read(&mut bytes),
    )
    .await;
    assert!(
        !matches!(read, Ok(Ok(count)) if bytes[..count].starts_with(b"HTTP/")),
        "the listener must authenticate itself with TLS before receiving credentials"
    );

    let health_state = state.clone();
    let reported =
        tokio::task::spawn_blocking(move || control_health(&health_state, Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(reported.generation, "fixed-control");

    let mut wrong = state.clone();
    wrong.generation = "other-generation".into();
    assert!(
        tokio::task::spawn_blocking(move || control_health(&wrong, Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap_err()
            .contains("identity")
    );

    tokio::task::spawn_blocking(move || shutdown(&state, Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn fixed_health_client_rejects_malformed_and_unsuccessful_responses() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "health-error");
    for (response, expected) in [
        (b"\xff".as_slice(), "not valid UTF-8"),
        (b"HTTP/1.1 200 OK\r\n".as_slice(), "malformed"),
        (
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".as_slice(),
            "rejected authenticated request",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot-json".as_slice(),
            "invalid proxy health response",
        ),
    ] {
        let error = parse_health_response(&state, response.to_vec()).unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn control_response_validation_is_bounded_and_requires_no_content() {
    for response in [
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.0 204 No Content\r\n\r\n".as_slice(),
    ] {
        validate_control_response(&mut std::io::Cursor::new(response)).unwrap();
    }
    for (response, expected) in [
        (b"\xff".as_slice(), "not valid UTF-8"),
        (b"HTTP/1.1 204 No Content\r\n".as_slice(), "malformed"),
        (
            b"HTTP/1.1 401 Unauthorized\r\n\r\n".as_slice(),
            "rejected authenticated request",
        ),
    ] {
        let error = validate_control_response(&mut std::io::Cursor::new(response)).unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
    let oversized = vec![b'a'; CONNECT_HEADER_LIMIT + 1];
    assert!(
        validate_control_response(&mut std::io::Cursor::new(oversized))
            .unwrap_err()
            .contains("exceed")
    );
}

#[tokio::test]
async fn intercepted_messages_preserve_oauth_query_body_and_sse_response() {
    let temp = tempfile::tempdir().unwrap();
    let state = test_state(temp.path(), "mitm-test");
    let root_der = std::fs::read(&state.certificate.root_der).unwrap();

    let (capture_tx, capture_rx) = oneshot::channel();
    let capture = Arc::new(Mutex::new(Some(capture_tx)));
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = gateway_listener.local_addr().unwrap();
    let (gateway_shutdown_tx, gateway_shutdown_rx) = oneshot::channel::<()>();
    let app = Router::new()
        .fallback(capture_gateway_request)
        .with_state(capture);
    let gateway_task = tokio::spawn(async move {
        axum::serve(gateway_listener, app)
            .with_graceful_shutdown(async {
                let _ = gateway_shutdown_rx.await;
            })
            .await
    });

    let tls = super::super::certificate::server_config(temp.path(), &state.certificate).unwrap();
    let (shutdown_tx, _) = watch::channel(false);
    let runtime = Runtime::new_with_gateway(
        state,
        tls,
        shutdown_tx.clone(),
        format!("http://{gateway_address}"),
    )
    .unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (stream, _) = proxy_listener.accept().await.unwrap();
        serve_connection(stream, runtime).await
    });

    let body = r#"{"model":"claude-test","messages":[{"role":"user","content":"ping"}]}"#;
    let proxy = Proxy::all(format!("http://{proxy_address}"))
        .unwrap()
        .basic_auth("relay", "secret");
    let client = Client::builder()
        .proxy(proxy)
        .add_root_certificate(reqwest::Certificate::from_der(&root_der).unwrap())
        .build()
        .unwrap();
    let response = client
        .post(format!("https://{INTERCEPTED_HOST}/v1/messages?beta=true"))
        .bearer_auth("subscription-oauth")
        .header(
            AGENT_AUTHORIZATION_HEADER,
            "Basic must-not-reach-the-provider",
        )
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let proxy_result = tokio::time::timeout(Duration::from_secs(2), proxy_task).await;
            panic!("request failed: {error}; proxy connection: {proxy_result:?}");
        }
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    let response = response.text().await.unwrap();
    assert!(response.contains("data: {\"type\":\"message_stop\"}"));

    let captured = tokio::time::timeout(Duration::from_secs(2), capture_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(captured.method, Method::POST);
    assert_eq!(captured.path_and_query, "/v1/messages?beta=true");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer subscription-oauth")
    );
    assert!(captured.proxy_authorization.is_none());
    assert!(captured.agent_authorization.is_none());
    assert_eq!(captured.body, body.as_bytes());

    let _ = shutdown_tx.send(true);
    gateway_shutdown_tx.send(()).unwrap();
    proxy_task.await.unwrap().unwrap();
    gateway_task.await.unwrap().unwrap();
}

struct CapturedRequest {
    method: Method,
    path_and_query: String,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
    agent_authorization: Option<String>,
    body: Vec<u8>,
}

async fn capture_gateway_request(
    State(capture): State<Arc<Mutex<Option<oneshot::Sender<CapturedRequest>>>>>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes().to_vec();
    let captured = CapturedRequest {
        method: parts.method,
        path_and_query: parts
            .uri
            .path_and_query()
            .map_or(parts.uri.path(), |value| value.as_str())
            .to_string(),
        authorization: parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        proxy_authorization: parts
            .headers
            .get(PROXY_AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        agent_authorization: parts
            .headers
            .get(AGENT_AUTHORIZATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body,
    };
    capture.lock().unwrap().take().unwrap().send(captured).ok();
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from("data: {\"type\":\"message_stop\"}\n\n"))
        .unwrap()
}

fn test_state(root: &std::path::Path, generation: &str) -> DesktopState {
    let certificate = super::super::certificate::generate(root, generation).unwrap();
    DesktopState {
        schema_version: super::super::state::STATE_SCHEMA_VERSION,
        generation: generation.into(),
        installed_at: "2026-01-01T00:00:00Z".into(),
        relay_version: env!("CARGO_PKG_VERSION").into(),
        relay_binary: std::env::current_exe().unwrap(),
        install_root: root.to_path_buf(),
        user_config_dir: root.join("config"),
        platform: "macos".into(),
        service_identity: None,
        bind: super::super::PROXY_BIND,
        proxy_username: "control".into(),
        proxy_token: "control-secret".into(),
        upstream_proxy: None,
        gateway_fingerprint: "gateway".into(),
        max_hook_payload_bytes: crate::configuration::DEFAULT_MAX_HOOK_PAYLOAD_BYTES,
        configuration_fingerprint: "configuration".into(),
        certificate,
        settings: super::super::settings::SettingsPatch::default(),
        claude_code_installed: true,
        claude_desktop_installed: false,
        enrollments: std::collections::BTreeMap::from([(
            "claude".into(),
            super::super::state::AgentEnrollment {
                username: "relay".into(),
                token: "secret".into(),
                installed_at: "2026-01-01T00:00:00Z".into(),
                upstream_proxy: None,
                client_ca_bundle_source: None,
                client_ca_bundle_variable: None,
            },
        )]),
    }
}

async fn raw_control_request(address: SocketAddr, credential: &str) -> String {
    raw_authenticated_request(
        address,
        credential,
        &format!("GET http://{CONTROL_HOST}{HEALTH_PATH} HTTP/1.1\r\nHost: {CONTROL_HOST}\r\n"),
    )
    .await
}

async fn raw_authenticated_request(address: SocketAddr, credential: &str, request: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(credential);
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("{request}Proxy-Authorization: Basic {encoded}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}
