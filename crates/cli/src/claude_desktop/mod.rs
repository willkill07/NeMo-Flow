// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::cognitive_complexity)]

//! Persistent, user-scoped proxy enrollment for local coding agents.

mod certificate;
mod operations;
mod platform;
mod proxy;
mod settings;
mod state;

use std::cell::{Cell, RefCell};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::agents::CodingAgent;
use crate::error::CliError;
use crate::installation::{InstallRequest, UninstallRequest};
use operations::{DesktopOperations, SystemOperations};
pub(crate) use settings::sanitize_no_proxy;

pub(crate) const LEGACY_PROXY_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47632);
pub(crate) const AGENT_AUTHORIZATION_HEADER: &str = "x-nemo-relay-agent-authorization";
pub(crate) const ENROLLED_AGENT_HEADER: &str = "x-nemo-relay-enrolled-agent";
#[cfg(test)]
pub(crate) const PROXY_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39_751);
const HEALTH_TIMEOUT: Duration = Duration::from_millis(750);
const START_TIMEOUT: Duration = Duration::from_secs(12);
const PROVIDER_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const USER_PORT_BASE: u16 = 30_000;
const USER_PORT_SPAN: u32 = 20_000;
const USER_PORT_PROBE_COUNT: u16 = 128;
const AGENT_TRANSACTION_FILE_NAME: &str = "agent-proxy-transaction.json";
const CODEX_CA_BUNDLE_FILE_NAME: &str = "codex-ca-bundle.pem";
const CLAUDE_ENROLLMENT: &str = "claude";

fn enrollment_key(agent: CodingAgent) -> &'static str {
    match agent {
        CodingAgent::ClaudeCode => CLAUDE_ENROLLMENT,
        CodingAgent::Codex => "codex",
        CodingAgent::Hermes => "hermes",
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct AgentTransactionJournal {
    schema_version: u32,
    operation: String,
    stage: String,
    agent: String,
    install_root: PathBuf,
    state_path: PathBuf,
    previous_state: Option<state::DesktopState>,
    setup_snapshot: crate::agents::SetupSnapshot,
    #[serde(default)]
    setup_result_snapshot: Option<crate::agents::SetupSnapshot>,
    #[serde(default)]
    marketplace_snapshot: Option<crate::installation::marketplace::DurableMarketplaceSnapshot>,
    #[serde(default)]
    marketplace_result_snapshot:
        Option<crate::installation::marketplace::DurableMarketplaceSnapshot>,
}

#[derive(Clone)]
pub(crate) struct AgentRouteContext {
    pub(crate) agent: String,
    pub(crate) upstream_proxy: Option<settings::UpstreamProxy>,
}

#[derive(Clone)]
pub(crate) struct ConfigurationFence(Arc<dyn Fn() -> Result<(), String> + Send + Sync + 'static>);

impl ConfigurationFence {
    fn new(verifier: Arc<dyn Fn() -> Result<(), String> + Send + Sync + 'static>) -> Self {
        Self(verifier)
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        (self.0)()
    }
}

pub(crate) type AgentUpstreamStream = proxy::BoxStream;
pub(crate) type AgentUpstreamProxy = settings::UpstreamProxy;
#[cfg(test)]
pub(crate) use proxy::connect_test_provider_tls_to_addresses;
#[cfg(any(test, feature = "internal-test-server"))]
pub(crate) use proxy::connect_through_upstream_proxy as connect_test_upstream_proxy;

pub(crate) const fn native_provider_hosts() -> &'static [&'static str] {
    certificate::INTERCEPTED_HOSTS
}

pub(crate) fn managed_native_provider_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let path = match url.path().trim_end_matches('/') {
        "" => "/",
        path => path,
    };
    match host.as_str() {
        "api.openai.com" => matches!(
            path,
            "/" | "/v1"
                | "/responses"
                | "/v1/responses"
                | "/chat/completions"
                | "/v1/chat/completions"
                | "/models"
                | "/v1/models"
        ),
        "chatgpt.com" => matches!(
            path,
            "/backend-api/codex"
                | "/backend-api/codex/responses"
                | "/backend-api/codex/v1/responses"
                | "/backend-api/codex/models"
        ),
        "api.anthropic.com" => matches!(
            path,
            "/" | "/v1" | "/v1/messages" | "/v1/messages/count_tokens"
        ),
        _ => false,
    }
}

fn agent_native_hosts(agent: &str) -> &'static [&'static str] {
    match agent {
        "claude" | "claude-code" | "claude-desktop" => &["api.anthropic.com"],
        "codex" => &["api.openai.com", "chatgpt.com"],
        "hermes" => certificate::INTERCEPTED_HOSTS,
        _ => &[],
    }
}

fn enrollment_native_hosts(
    enrollments: &std::collections::BTreeMap<String, state::AgentEnrollment>,
) -> Vec<&'static str> {
    let mut hosts = std::collections::BTreeSet::new();
    for agent in enrollments.keys() {
        hosts.extend(agent_native_hosts(agent));
    }
    hosts.into_iter().collect()
}

fn required_native_hosts(
    enrollments: &std::collections::BTreeMap<String, state::AgentEnrollment>,
    adding: CodingAgent,
) -> Vec<&'static str> {
    let mut hosts = enrollment_native_hosts(enrollments)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    hosts.extend(agent_native_hosts(adding.install_arg()));
    hosts.into_iter().collect()
}

pub(crate) async fn connect_provider_tls(
    proxy: Option<&settings::UpstreamProxy>,
    host: &str,
    port: u16,
) -> Result<AgentUpstreamStream, String> {
    proxy::connect_provider_tls(proxy, host, port).await
}

pub(crate) async fn send_provider_http(
    route: &AgentRouteContext,
    mut request: http::Request<axum::body::Body>,
) -> Result<http::Response<hyper::body::Incoming>, String> {
    let uri = request.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| "managed provider request URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if uri.scheme_str() != Some("https")
        || uri.port_u16().is_some_and(|port| port != 443)
        || !native_provider_hosts().contains(&host.as_str())
    {
        return Err("managed provider request target is outside the native HTTPS host set".into());
    }
    let stream = connect_provider_tls(route.upstream_proxy.as_ref(), &host, 443).await?;
    let (mut sender, connection) = tokio::time::timeout(
        PROVIDER_HEADER_TIMEOUT,
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)),
    )
    .await
    .map_err(|_| "provider HTTP handshake timed out".to_string())?
    .map_err(|error| format!("provider HTTP handshake failed: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!(
                target: "nemo_relay.gateway",
                event = "provider_http_connection_closed",
                error_kind = "transport";
                "Managed provider HTTP connection closed: {error}"
            );
        }
    });
    *request.uri_mut() = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .parse()
        .map_err(|error| format!("managed provider request path is invalid: {error}"))?;
    request.headers_mut().insert(
        http::header::HOST,
        http::HeaderValue::from_str(&host)
            .map_err(|_| "managed provider host is not a valid HTTP header".to_string())?,
    );
    tokio::time::timeout(PROVIDER_HEADER_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| "provider HTTP response headers timed out".to_string())?
        .map_err(|error| format!("provider HTTP request failed: {error}"))
}

#[cfg(test)]
static FIXED_PORT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct InstallProgress {
    trust_installed: bool,
    service_registration_attempted: bool,
    plugin_added: bool,
    locator_written: bool,
}

struct DesktopRollbackSnapshots<'a> {
    settings: &'a crate::filesystem::FileSnapshot,
    provider_backup: &'a crate::filesystem::FileSnapshot,
    settings_result: Option<&'a crate::filesystem::FileSnapshot>,
    provider_backup_result: Option<&'a crate::filesystem::FileSnapshot>,
    marketplace: Option<&'a crate::installation::marketplace::DurableMarketplaceSnapshot>,
    marketplace_result: Option<&'a crate::installation::marketplace::DurableMarketplaceSnapshot>,
    marketplace_dir: Option<&'a Path>,
}

#[derive(Default)]
struct RollbackErrors(Vec<String>);

impl RollbackErrors {
    fn record(&mut self, result: Result<(), String>) {
        if let Err(error) = result {
            self.0.push(error);
        }
    }

    fn finish(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self.0.join("; "))
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

struct PendingGenerationCleanup {
    certificate: state::CertificateState,
    install_root: PathBuf,
    generation: String,
    armed: bool,
}

struct PreparedEnrollment {
    platform: platform::Platform,
    existing: Option<state::DesktopState>,
    installed: state::DesktopState,
    rotation_required: bool,
    generation_cleanup: Option<PendingGenerationCleanup>,
}

impl PendingGenerationCleanup {
    fn new(installed: &state::DesktopState) -> Self {
        Self::for_generation(
            &installed.certificate,
            &installed.install_root,
            &installed.generation,
        )
    }

    fn for_generation(
        certificate: &state::CertificateState,
        install_root: &Path,
        generation: &str,
    ) -> Self {
        Self {
            certificate: certificate.clone(),
            install_root: install_root.to_path_buf(),
            generation: generation.to_owned(),
            armed: true,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGenerationCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(_error) =
            remove_uncommitted_generation(&self.certificate, &self.install_root, &self.generation)
        {
            log::warn!(
                target: "nemo_relay.installation",
                event = "uncommitted_proxy_generation_cleanup_failed",
                generation = self.generation.as_str(),
                error_kind = "generation_cleanup_failed";
                "Failed to clean up an uncommitted coding-agent proxy generation"
            );
        }
    }
}

fn remove_uncommitted_generation(
    certificate: &state::CertificateState,
    install_root: &Path,
    generation: &str,
) -> Result<(), String> {
    remove_signer_then_generation(certificate, install_root, generation)
}

#[derive(Debug, Clone)]
pub(crate) struct LaunchRequest {
    pub(crate) folder: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyServiceRequest {
    pub(crate) state: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentProxyEnrollment {
    pub(crate) gateway_url: String,
    pub(crate) authorization: String,
    pub(crate) proxy_url: String,
    pub(crate) root_ca_pem: PathBuf,
    pub(crate) max_hook_payload_bytes: usize,
    pub(crate) generation: String,
    pub(crate) configuration_fingerprint: String,
}

pub(crate) fn enrollment(agent: CodingAgent) -> Result<Option<AgentProxyEnrollment>, String> {
    enrollment_at(agent, None)
}

pub(crate) fn enrollment_at(
    agent: CodingAgent,
    install_dir: Option<&Path>,
) -> Result<Option<AgentProxyEnrollment>, String> {
    enrollment_named(enrollment_key(agent), install_dir)
}

pub(crate) fn claude_plugin_enrollment() -> Result<Option<AgentProxyEnrollment>, String> {
    hook_enrollment(CodingAgent::ClaudeCode)
}

/// Resolves the credential used by an installed lifecycle hook. Claude Code and Claude Desktop
/// share one plugin, so its canonical Claude hook remains deliverable when either owner is the
/// only enrolled Claude client.
pub(crate) fn hook_enrollment(agent: CodingAgent) -> Result<Option<AgentProxyEnrollment>, String> {
    let path = state::resolve_state_path(None)?;
    if !path.exists() {
        return Ok(None);
    }
    let installed = state::read(&path)?;
    Ok(hook_enrollment_from_state(&installed, agent))
}

fn hook_enrollment_from_state(
    installed: &state::DesktopState,
    agent: CodingAgent,
) -> Option<AgentProxyEnrollment> {
    if agent == CodingAgent::ClaudeCode {
        return enrollment_from_state(installed, CLAUDE_ENROLLMENT);
    }
    enrollment_from_state(installed, agent.install_arg())
}

fn enrollment_named(
    agent: &str,
    install_dir: Option<&Path>,
) -> Result<Option<AgentProxyEnrollment>, String> {
    let path = state::resolve_state_path(install_dir)?;
    if !path.exists() {
        return Ok(None);
    }
    let installed = state::read(&path)?;
    Ok(enrollment_from_state(&installed, agent))
}

fn enrollment_from_state(
    installed: &state::DesktopState,
    agent: &str,
) -> Option<AgentProxyEnrollment> {
    let agent_state = installed.enrollments.get(agent)?;
    let basic = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{}:{}", agent_state.username, agent_state.token),
    );
    Some(AgentProxyEnrollment {
        gateway_url: format!("https://{}", installed.bind),
        authorization: format!("Basic {basic}"),
        proxy_url: format!(
            "https://{}:{}@{}",
            agent_state.username, agent_state.token, installed.bind
        ),
        root_ca_pem: installed.certificate.root_pem.clone(),
        max_hook_payload_bytes: installed.max_hook_payload_bytes,
        generation: installed.generation.clone(),
        configuration_fingerprint: installed.configuration_fingerprint.clone(),
    })
}

/// Proves that the currently reachable authenticated service is the exact generation and
/// configuration from which an installed hook obtained its enrollment.
pub(crate) fn verify_hook_enrollment_health(
    agent: CodingAgent,
    enrollment: &AgentProxyEnrollment,
) -> Result<(), String> {
    verify_hook_enrollment_health_with(&SystemOperations, agent, enrollment)
}

fn verify_hook_enrollment_health_with(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    enrollment: &AgentProxyEnrollment,
) -> Result<(), String> {
    let path = state::resolve_state_path(None)?;
    let installed = state::read(&path)?;
    let current = hook_enrollment_from_state(&installed, agent).ok_or_else(|| {
        format!(
            "{} is no longer enrolled in the per-user coding-agent proxy",
            agent.label()
        )
    })?;
    if current.authorization != enrollment.authorization
        || current.gateway_url != enrollment.gateway_url
        || current.generation != enrollment.generation
        || current.configuration_fingerprint != enrollment.configuration_fingerprint
    {
        return Err(format!(
            "{} hook enrollment changed while the hook was starting",
            agent.label()
        ));
    }
    let health = operations.health(&installed)?;
    if health.generation != enrollment.generation
        || health.configuration_fingerprint != enrollment.configuration_fingerprint
        || health.gateway_url != enrollment.gateway_url
    {
        return Err(format!(
            "{} hook could not prove the enrolled proxy service identity",
            agent.label()
        ));
    }
    Ok(())
}

pub(crate) fn diagnose_enrollment_at(
    agent: CodingAgent,
    install_dir: Option<&Path>,
) -> Result<String, String> {
    ensure_selected_enrollment_root(install_dir, &[agent.install_arg()], "doctor")?;
    let path = state::resolve_state_path(install_dir)?;
    if !path.exists() {
        return Err(format!(
            "{} is not enrolled in the per-user coding-agent proxy; run `nemo-relay install {}`",
            agent.label(),
            agent.install_arg()
        ));
    }
    let installed = state::read(&path)?;
    if !installed.enrollments.contains_key(agent.install_arg()) {
        return Err(format!(
            "{} is not enrolled in the per-user coding-agent proxy; run `nemo-relay install {}`",
            agent.label(),
            agent.install_arg()
        ));
    }
    if certificate::requires_rotation_for_hosts(
        &installed.install_root,
        &installed.certificate,
        &enrollment_native_hosts(&installed.enrollments),
    ) {
        return Err(
            "coding-agent proxy CA is expired, corrupt, or stale; reinstall with --force".into(),
        );
    }
    shared_transaction_journal_status()?;
    transaction_journal_status(&installed, false)?;
    certificate::validate_installed_identity(&installed.install_root, &installed.certificate)?;
    certificate::leaf_cache_summary(&installed.certificate)?;
    private_state_files(&installed)?;
    if let Some(upstream) = installed
        .enrollments
        .get(agent.install_arg())
        .and_then(|enrollment| enrollment.upstream_proxy.as_ref())
    {
        settings::validate_upstream_proxy(&upstream.url, upstream.no_proxy.clone())?;
        proxy::upstream_client(Some(upstream))?;
    }
    let expected = current_configuration_fingerprint(&installed)?;
    if expected != installed.configuration_fingerprint {
        return Err(
            "coding-agent proxy configuration fingerprint changed; reinstall with --force".into(),
        );
    }
    let operations = SystemOperations;
    let platform = platform::Platform::parse(&installed.platform)?;
    match (platform, agent) {
        (platform::Platform::Linux, CodingAgent::ClaudeCode) => {
            operations.trust_status(
                platform,
                &installed.certificate,
                linux_ca_bundle(&installed),
            )?;
        }
        (platform::Platform::Linux, CodingAgent::Codex) => {
            verify_codex_ca_bundle(&installed)?;
        }
        (platform::Platform::Linux, CodingAgent::Hermes) => {
            // Hermes verifies its copied CA bundle with the rest of its owned environment in
            // `diagnose_persistent`.
        }
        (platform, _) => {
            operations.trust_status(platform, &installed.certificate, None)?;
        }
    }
    operations.service_status(&installed)?;
    let health = operations.health(&installed)?;
    if health.generation != installed.generation
        || health.configuration_fingerprint != installed.configuration_fingerprint
    {
        return Err("coding-agent proxy service identity does not match installed state".into());
    }
    Ok(format!(
        "enrolled on {} with generation {}",
        installed.bind, installed.generation
    ))
}

pub(crate) fn resolved_marketplace_install_dir(
    install_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let state_path = state::resolve_state_path(install_dir)?;
    let proxy_root = state_path
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("agent-proxy"))
        .ok_or_else(|| {
            format!(
                "coding-agent proxy state path is outside an agent-proxy root: {}",
                state_path.display()
            )
        })?;
    proxy_root.parent().map(Path::to_path_buf).ok_or_else(|| {
        format!(
            "coding-agent proxy root has no marketplace parent: {}",
            proxy_root.display()
        )
    })
}

pub(crate) fn trust_configuration_notice() -> String {
    match platform::Platform::current() {
        Ok(platform::Platform::MacOs) => {
            "install the Relay CA in the current user's macOS login Keychain trust settings".into()
        }
        Ok(platform::Platform::Windows) => {
            "install the Relay CA in the Windows CurrentUser Root trust store".into()
        }
        Ok(platform::Platform::Linux) => {
            "configure an agent-scoped Relay CA bundle (the Linux system trust store is unchanged)"
                .into()
        }
        Err(_) => "configure the platform-specific Relay CA trust boundary".into(),
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ProxyStateSnapshot {
    state_path: PathBuf,
    state: Option<state::DesktopState>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ClaudeDesktopHostSnapshot {
    setup: crate::agents::SetupSnapshot,
    #[serde(default)]
    setup_result: Option<crate::agents::SetupSnapshot>,
    install_root: PathBuf,
    marketplace_dir: PathBuf,
}

pub(crate) struct BatchOperationLock {
    _lock: crate::installation::operation_lock::PluginOperationLock,
}

pub(crate) struct BatchResourceRetirementGuard;

thread_local! {
    static BATCH_OPERATION_DEPTH: Cell<u32> = const { Cell::new(0) };
    static BATCH_RESOURCE_RETIREMENT_DEPTH: Cell<u32> = const { Cell::new(0) };
    static BATCH_RESOURCE_RETIREMENT_RECORDER: RefCell<Option<RetirementRecorder>> =
        const { RefCell::new(None) };
}

type RetirementRecorder = Rc<dyn Fn(DeferredProxyRetirement) -> Result<(), String>>;

impl Drop for BatchOperationLock {
    fn drop(&mut self) {
        BATCH_OPERATION_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

impl Drop for BatchResourceRetirementGuard {
    fn drop(&mut self) {
        BATCH_RESOURCE_RETIREMENT_DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            if next == 0 {
                BATCH_RESOURCE_RETIREMENT_RECORDER.with(|recorder| recorder.borrow_mut().take());
            }
        });
    }
}

pub(crate) fn batch_operation_lock() -> Result<BatchOperationLock, String> {
    let directory = proxy_operation_lock_directory()?;
    let lock = crate::installation::operation_lock::PluginOperationLock::acquire(
        "agent-proxy-batch",
        &directory,
        &directory,
        crate::installation::operation_lock::DEFAULT_OPERATION_LOCK_TIMEOUT,
    )?;
    BATCH_OPERATION_DEPTH.with(|depth| depth.set(depth.get() + 1));
    Ok(BatchOperationLock { _lock: lock })
}

pub(crate) fn defer_batch_resource_retirement(
    recorder: impl Fn(DeferredProxyRetirement) -> Result<(), String> + 'static,
) -> BatchResourceRetirementGuard {
    let recorder = Rc::new(recorder) as RetirementRecorder;
    BATCH_RESOURCE_RETIREMENT_DEPTH.with(|depth| {
        if depth.get() == 0 {
            BATCH_RESOURCE_RETIREMENT_RECORDER.with(|slot| *slot.borrow_mut() = Some(recorder));
        }
        depth.set(depth.get() + 1);
    });
    BatchResourceRetirementGuard
}

fn batch_resource_retirement_deferred() -> bool {
    BATCH_RESOURCE_RETIREMENT_DEPTH.with(|depth| depth.get() > 0)
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct DeferredProxyRetirement {
    state: state::DesktopState,
}

impl DeferredProxyRetirement {
    pub(crate) fn same_resource(&self, other: &Self) -> bool {
        self.state.state_path() == other.state.state_path()
            && self.state.generation == other.state.generation
    }
}

pub(crate) fn finalize_batch_resource_retirements(
    retirements: &[DeferredProxyRetirement],
) -> Result<(), String> {
    let operations = SystemOperations;
    let mut inactive_roots = Vec::new();
    for retirement in retirements {
        validate_deferred_proxy_retirement(retirement)?;
        let previous = &retirement.state;
        let state_path = previous.state_path();
        let current = state_path
            .exists()
            .then(|| state::read(&state_path))
            .transpose()?;
        if current
            .as_ref()
            .is_some_and(|active| active.generation == previous.generation)
        {
            continue;
        }
        let platform = platform::Platform::parse(&previous.platform)?;
        operations.remove_trust(platform, &previous.certificate)?;
        retire_generation(previous)?;
        if current.is_none() && !inactive_roots.contains(&previous.install_root) {
            inactive_roots.push(previous.install_root.clone());
        }
    }
    for root in inactive_roots {
        cleanup_unreferenced_generations(&root, None)?;
        remove_fresh_install_root(&root)?;
    }
    Ok(())
}

fn validate_deferred_proxy_retirement(retirement: &DeferredProxyRetirement) -> Result<(), String> {
    let previous = &retirement.state;
    if previous
        .install_root
        .file_name()
        .and_then(|name| name.to_str())
        != Some("agent-proxy")
        || previous.state_path() != previous.install_root.join(state::STATE_FILE_NAME)
    {
        return Err("batch retirement contains unsafe coding-agent proxy paths".into());
    }
    Ok(())
}

fn defer_proxy_retirement(previous: &state::DesktopState) -> Result<bool, String> {
    if !batch_resource_retirement_deferred() {
        return Ok(false);
    }
    BATCH_RESOURCE_RETIREMENT_RECORDER.with(|recorder| {
        let recorder = recorder.borrow();
        let recorder = recorder
            .as_ref()
            .ok_or_else(|| "batch retirement recorder is unavailable".to_string())?;
        recorder(DeferredProxyRetirement {
            state: previous.clone(),
        })
    })?;
    Ok(true)
}

pub(crate) fn snapshot_proxy_state(
    install_dir: Option<&Path>,
) -> Result<ProxyStateSnapshot, String> {
    let state_path = state::selected_state_path(install_dir);
    let state = state_path
        .exists()
        .then(|| state::read(&state_path))
        .transpose()?;
    Ok(ProxyStateSnapshot { state_path, state })
}

pub(crate) fn snapshot_claude_desktop_host(
    install_dir: Option<&Path>,
) -> Result<ClaudeDesktopHostSnapshot, String> {
    let install_root = state::install_root(install_dir);
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no marketplace parent".to_string())?
        .to_path_buf();
    Ok(ClaudeDesktopHostSnapshot {
        setup: crate::agents::snapshot_setup(CodingAgent::ClaudeCode)?,
        setup_result: None,
        install_root,
        marketplace_dir,
    })
}

impl ClaudeDesktopHostSnapshot {
    pub(crate) fn capture_result(&mut self) -> Result<(), String> {
        self.setup_result = Some(crate::agents::capture_current_setup_snapshot(&self.setup)?);
        Ok(())
    }
}

pub(crate) fn restore_claude_desktop_host(
    snapshot: &ClaudeDesktopHostSnapshot,
) -> Result<(), String> {
    if !snapshot.install_root.is_absolute()
        || snapshot
            .install_root
            .file_name()
            .and_then(|name| name.to_str())
            != Some("agent-proxy")
        || snapshot.marketplace_dir.join("agent-proxy") != snapshot.install_root
    {
        return Err("Claude Desktop batch snapshot contains an unsafe marketplace path".into());
    }
    crate::agents::restore_setup_snapshot_cas(&snapshot.setup, snapshot.setup_result.as_ref())
}

pub(crate) fn restore_proxy_state_snapshot(snapshot: &ProxyStateSnapshot) -> Result<(), String> {
    let operations = SystemOperations;
    let _operation_lock = desktop_operation_lock()?;
    recover_pending_agent_transaction(&operations)?;
    let install_root = snapshot
        .state_path
        .parent()
        .ok_or_else(|| "proxy state snapshot path has no install root".to_string())?;
    if state::journal_path(install_root).exists() {
        let platform = operations.platform()?;
        recover_interrupted_operation(&operations, install_root, &snapshot.state_path, platform)?;
    }
    let current = snapshot
        .state_path
        .exists()
        .then(|| state::read(&snapshot.state_path))
        .transpose()?;
    if install_root.file_name().and_then(|name| name.to_str()) != Some("agent-proxy")
        || snapshot
            .state
            .as_ref()
            .is_some_and(|state| state.state_path() != snapshot.state_path)
    {
        return Err("proxy batch snapshot contains unsafe state paths".into());
    }
    restore_proxy_state(
        &operations,
        snapshot.state.as_ref(),
        current.as_ref(),
        &snapshot.state_path,
    )?;
    cleanup_unreferenced_generations(
        install_root,
        snapshot
            .state
            .as_ref()
            .map(|state| state.generation.as_str()),
    )?;
    if snapshot.state.is_none() {
        remove_fresh_install_root(install_root)?;
    }
    Ok(())
}

pub(crate) fn verify_claude_settings() -> Result<(), String> {
    let path = state::resolve_state_path(None)?;
    let installed = state::read(&path)?;
    if !installed.claude_enrolled() {
        return Err("no Claude client owns the shared proxy settings".into());
    }
    settings::matches(&installed.settings)
}

pub(crate) fn enroll_agent_transactionally<T>(
    agent: CodingAgent,
    command: &InstallRequest,
    setup_snapshot: &crate::agents::SetupSnapshot,
    install_host: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    enroll_agent_transactionally_with(
        &SystemOperations,
        agent,
        command,
        setup_snapshot,
        install_host,
    )
}

fn enroll_agent_transactionally_with<T>(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &InstallRequest,
    setup_snapshot: &crate::agents::SetupSnapshot,
    install_host: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    state::ensure_no_legacy_state(command.install_dir.as_deref()).map_err(CliError::Install)?;
    let root = state::install_root(command.install_dir.as_deref());
    let path = state::selected_state_path(command.install_dir.as_deref());
    let _operation_lock = desktop_operation_lock().map_err(CliError::Install)?;
    recover_pending_agent_transaction(operations).map_err(CliError::Install)?;
    let previous = path
        .exists()
        .then(|| state::read(&path))
        .transpose()
        .map_err(CliError::Install)?;
    let marketplace_snapshot =
        capture_agent_marketplace_snapshot(agent, command.install_dir.as_deref(), setup_snapshot)
            .map_err(CliError::Install)?;
    let mut journal = AgentTransactionJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "preparing-proxy".into(),
        agent: agent.install_arg().into(),
        install_root: root.clone(),
        state_path: path.clone(),
        previous_state: previous.clone(),
        setup_snapshot: setup_snapshot.clone(),
        setup_result_snapshot: None,
        marketplace_snapshot,
        marketplace_result_snapshot: None,
    };
    write_agent_transaction(&journal).map_err(CliError::Install)?;
    let (_, pending_retirement) =
        match enroll_agent_locked(operations, agent, command, true, root, path.clone()) {
            Ok(enrollment) => enrollment,
            Err(error) => {
                return recover_failed_agent_transaction(operations, CliError::Install(error));
            }
        };
    journal.stage = "proxy-active".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    let host_result = install_host();
    if let Err(snapshot_error) = persist_agent_host_result(&mut journal) {
        let error = match host_result {
            Ok(_) => CliError::Install(snapshot_error),
            Err(operation_error) => CliError::Install(format!(
                "{operation_error}; additionally failed to persist the host result snapshot: {snapshot_error}"
            )),
        };
        return recover_failed_agent_transaction(operations, error);
    }
    let host_result = match host_result {
        Ok(result) => result,
        Err(error) => return recover_failed_agent_transaction(operations, error),
    };
    journal.stage = "host-configured".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    journal.stage = "committed".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    finalize_deferred_enrollment(operations, pending_retirement.as_ref(), &path)
        .map_err(CliError::Install)?;
    remove_agent_transaction().map_err(CliError::Install)?;
    Ok(host_result)
}

fn recover_failed_agent_transaction<T>(
    operations: &dyn DesktopOperations,
    error: CliError,
) -> Result<T, CliError> {
    match recover_pending_agent_transaction(operations) {
        Ok(()) => Err(CliError::Install(format!(
            "{error}; restored the previous proxy and host configuration"
        ))),
        Err(rollback) => Err(CliError::Install(format!(
            "{error}; durable transaction recovery also failed: {rollback}"
        ))),
    }
}

fn persist_agent_host_result(journal: &mut AgentTransactionJournal) -> Result<(), String> {
    let setup_result_snapshot =
        crate::agents::capture_current_setup_snapshot(&journal.setup_snapshot)?;
    let marketplace_result_snapshot = journal
        .marketplace_snapshot
        .as_ref()
        .map(|snapshot| snapshot.capture_current())
        .transpose()?;
    journal.setup_result_snapshot = Some(setup_result_snapshot);
    journal.marketplace_result_snapshot = marketplace_result_snapshot;
    write_agent_transaction(journal)
}

fn agent_transaction_path() -> Result<PathBuf, String> {
    active_user_config_dir().map(|directory| directory.join(AGENT_TRANSACTION_FILE_NAME))
}

fn write_agent_transaction(journal: &AgentTransactionJournal) -> Result<(), String> {
    let path = agent_transaction_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "agent transaction path has no parent".to_string())?;
    state::ensure_private_directory(parent)?;
    let mut bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&path, &bytes)
}

fn read_agent_transaction() -> Result<Option<AgentTransactionJournal>, String> {
    let path = agent_transaction_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        &path,
        "coding-agent proxy transaction journal",
    )?;
    let journal = serde_json::from_slice::<AgentTransactionJournal>(&bytes)
        .map_err(|error| format!("invalid {}: {error}", path.display()))?;
    validate_agent_transaction(&journal)?;
    Ok(Some(journal))
}

fn validate_agent_transaction(journal: &AgentTransactionJournal) -> Result<(), String> {
    let valid_stage = match journal.operation.as_str() {
        "install" => matches!(
            journal.stage.as_str(),
            "preparing-proxy" | "proxy-active" | "host-configured" | "committed"
        ),
        "uninstall" => matches!(
            journal.stage.as_str(),
            "removing-host" | "host-removed" | "proxy-removed" | "committed"
        ),
        _ => false,
    };
    if journal.schema_version != state::STATE_SCHEMA_VERSION
        || !matches!(journal.operation.as_str(), "install" | "uninstall")
        || !valid_stage
        || !CodingAgent::ALL
            .iter()
            .any(|agent| agent.install_arg() == journal.agent)
    {
        return Err("coding-agent proxy transaction journal has invalid identity metadata".into());
    }
    if journal
        .install_root
        .file_name()
        .and_then(|name| name.to_str())
        != Some("agent-proxy")
        || journal.state_path != journal.install_root.join(state::STATE_FILE_NAME)
    {
        return Err(format!(
            "coding-agent proxy transaction journal contains unsafe paths under {}",
            journal.install_root.display()
        ));
    }
    if let Some(previous) = journal.previous_state.as_ref()
        && previous.state_path() != journal.state_path
    {
        return Err("coding-agent proxy transaction prior state path does not match".into());
    }
    Ok(())
}

fn remove_agent_transaction() -> Result<(), String> {
    state::remove_file_if_present(&agent_transaction_path()?)
}

fn recover_pending_agent_transaction(operations: &dyn DesktopOperations) -> Result<(), String> {
    let Some(journal) = read_agent_transaction()? else {
        return Ok(());
    };
    if journal.stage == "committed" {
        finalize_committed_agent_transaction(operations, &journal)?;
        remove_agent_transaction()?;
        println!(
            "finished committed {} transaction for {}",
            journal.operation, journal.agent
        );
        return Ok(());
    }
    let current = journal
        .state_path
        .exists()
        .then(|| state::read(&journal.state_path))
        .transpose()?;
    if let Some(current) = current.as_ref() {
        operations.shutdown_proxy(current);
        operations.stop_service(current)?;
    }
    if let Some(snapshot) = journal.marketplace_snapshot.as_ref() {
        crate::installation::marketplace::restore_marketplace_snapshot_cas(
            snapshot,
            journal.marketplace_result_snapshot.as_ref(),
        )?;
    }
    crate::agents::restore_setup_snapshot_cas(
        &journal.setup_snapshot,
        journal.setup_result_snapshot.as_ref(),
    )?;
    restore_agent_transaction_proxy(operations, &journal, current.as_ref())?;
    cleanup_unreferenced_generations(
        &journal.install_root,
        journal
            .previous_state
            .as_ref()
            .map(|state| state.generation.as_str()),
    )?;
    remove_agent_transaction()?;
    if journal.previous_state.is_none() {
        remove_fresh_install_root(&journal.install_root)?;
    }
    println!(
        "recovered interrupted {} transaction for {}",
        journal.operation, journal.agent
    );
    Ok(())
}

fn finalize_committed_agent_transaction(
    operations: &dyn DesktopOperations,
    journal: &AgentTransactionJournal,
) -> Result<(), String> {
    match journal.operation.as_str() {
        "install" => {
            let current = state::read(&journal.state_path)?;
            if !current.enrollments.contains_key(&journal.agent) {
                return Err(format!(
                    "committed install for {} does not match active proxy state",
                    journal.agent
                ));
            }
            finalize_deferred_enrollment(
                operations,
                journal.previous_state.as_ref(),
                &journal.state_path,
            )
        }
        "uninstall" => {
            let current = journal
                .state_path
                .exists()
                .then(|| state::read(&journal.state_path))
                .transpose()?;
            if current
                .as_ref()
                .is_some_and(|state| state.enrollments.contains_key(&journal.agent))
            {
                return Err(format!(
                    "committed uninstall for {} still appears in active proxy state",
                    journal.agent
                ));
            }
            if current.is_some() {
                return Ok(());
            }
            let Some(previous) = journal.previous_state.as_ref() else {
                return Ok(());
            };
            if defer_proxy_retirement(previous)? {
                return Ok(());
            }
            retire_generation(previous)?;
            remove_fresh_install_root(&journal.install_root)
        }
        _ => Err("unsupported committed agent transaction".into()),
    }
}

fn restore_agent_transaction_proxy(
    operations: &dyn DesktopOperations,
    journal: &AgentTransactionJournal,
    current: Option<&state::DesktopState>,
) -> Result<(), String> {
    restore_proxy_state(
        operations,
        journal.previous_state.as_ref(),
        current,
        &journal.state_path,
    )
}

fn restore_proxy_state(
    operations: &dyn DesktopOperations,
    previous: Option<&state::DesktopState>,
    current: Option<&state::DesktopState>,
    state_path: &Path,
) -> Result<(), String> {
    match (previous, current) {
        (Some(previous), Some(current)) => {
            let platform = platform::Platform::parse(&current.platform)?;
            let trust_preexisting =
                previous.certificate.root_sha256 == current.certificate.root_sha256;
            rollback_agent_enrollment(
                operations,
                platform,
                Some(previous),
                current,
                state_path,
                trust_preexisting,
            )
        }
        (Some(previous), None) => restore_removed_enrollment(
            operations,
            platform::Platform::parse(&previous.platform)?,
            previous,
            state_path,
        ),
        (None, Some(current)) => rollback_agent_enrollment(
            operations,
            platform::Platform::parse(&current.platform)?,
            None,
            current,
            state_path,
            false,
        ),
        (None, None) => Ok(()),
    }
}

fn cleanup_unreferenced_generations(root: &Path, keep: Option<&str>) -> Result<(), String> {
    let directory = root.join("generations");
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to inspect proxy generations at {}: {error}",
                directory.display()
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "failed to inspect proxy generations at {}: {error}",
                directory.display()
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        let generation = entry.file_name().into_string().map_err(|_| {
            format!(
                "proxy generation name under {} is not valid Unicode",
                directory.display()
            )
        })?;
        if !file_type.is_dir() || generation.is_empty() || keep == Some(generation.as_str()) {
            continue;
        }
        certificate::remove_signer_for_generation(&generation)?;
        remove_generation(root, &generation)?;
    }
    Ok(())
}

fn finalize_deferred_enrollment(
    operations: &dyn DesktopOperations,
    previous: Option<&state::DesktopState>,
    path: &Path,
) -> Result<(), String> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let installed = state::read(path)?;
    if installed.generation == previous.generation {
        return Ok(());
    }
    if installed.enrollments.contains_key("hermes") {
        let enrollment = enrollment_from_state(&installed, "hermes")
            .ok_or_else(|| "Hermes proxy enrollment disappeared during rotation".to_string())?;
        crate::agents::refresh_hermes_proxy_environment(&enrollment)?;
    }
    if defer_proxy_retirement(previous)? {
        return Ok(());
    }
    let platform = platform::Platform::parse(&installed.platform)?;
    operations.remove_trust(platform, &previous.certificate)?;
    retire_generation(previous)
}

fn retire_generation(previous: &state::DesktopState) -> Result<(), String> {
    remove_signer_then_generation(
        &previous.certificate,
        &previous.install_root,
        &previous.generation,
    )
}

fn remove_signer_then_generation(
    certificate: &state::CertificateState,
    install_root: &Path,
    generation: &str,
) -> Result<(), String> {
    certificate::remove_signer(certificate)?;
    remove_generation(install_root, generation)
}

#[cfg(test)]
fn enroll_agent_with(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &InstallRequest,
) -> Result<AgentProxyEnrollment, String> {
    state::ensure_no_legacy_state(command.install_dir.as_deref())?;
    let root = state::install_root(command.install_dir.as_deref());
    let path = state::selected_state_path(command.install_dir.as_deref());
    if command.dry_run {
        println!(
            "enroll {} in the per-user coding-agent proxy and mutate current-user trust",
            agent.label()
        );
        return Err("dry-run enrollment has no runtime endpoint".into());
    }
    let _operation_lock = desktop_operation_lock()?;
    enroll_agent_locked(operations, agent, command, false, root, path)
        .map(|(enrollment, _)| enrollment)
}

fn enroll_agent_locked(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &InstallRequest,
    defer_previous_retirement: bool,
    root: PathBuf,
    path: PathBuf,
) -> Result<(AgentProxyEnrollment, Option<state::DesktopState>), String> {
    let mut prepared = prepare_enrollment(operations, agent, command, &root, &path)?;
    let installed = &mut prepared.installed;
    let enrollment_key = enrollment_key(agent);
    let prior_enrollment = installed.enrollments.get(enrollment_key).cloned();
    let token = match prior_enrollment.as_ref() {
        Some(prior) => prior.token.clone(),
        None => crate::provider_auth::ProxyCredential::generate()
            .map_err(|error| error.to_string())?
            .expose()
            .to_string(),
    };
    let username = prior_enrollment.as_ref().map_or_else(
        || format!("nemo-relay-{enrollment_key}"),
        |prior| prior.username.clone(),
    );
    let provisional_url = format!("https://{username}:{token}@{}", installed.bind);
    let host_environment = crate::agents::persistent_proxy_environment(agent)?;
    let upstream = settings::process_upstream_proxy_with_host_environment(
        &host_environment,
        &provisional_url,
        installed
            .enrollments
            .get(enrollment_key)
            .and_then(|enrollment| enrollment.upstream_proxy.as_ref()),
    )?;
    let (client_ca_bundle_source, client_ca_bundle_variable) = codex_ca_bundle_source(
        agent,
        prepared.platform,
        &installed.install_root,
        prior_enrollment.as_ref(),
    )?;
    installed.enrollments.insert(
        enrollment_key.into(),
        state::AgentEnrollment {
            username,
            token,
            installed_at: prior_enrollment
                .as_ref()
                .map(|prior| prior.installed_at.clone())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            upstream_proxy: upstream.clone(),
            client_ca_bundle_source,
            client_ca_bundle_variable,
        },
    );
    if agent == CodingAgent::ClaudeCode {
        installed.claude_code_installed = true;
    }
    if prepared.rotation_required {
        let generation = uuid::Uuid::now_v7().to_string();
        installed.certificate = certificate::generate_for_hosts(
            &installed.install_root,
            &generation,
            &enrollment_native_hosts(&installed.enrollments),
        )?;
        installed.generation = generation;
        installed.installed_at = chrono::Utc::now().to_rfc3339();
        prepared.generation_cleanup = Some(PendingGenerationCleanup::new(installed));
    }
    complete_agent_enrollment(
        operations,
        agent,
        defer_previous_retirement,
        &path,
        prepared,
    )
}

fn prepare_enrollment(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &InstallRequest,
    root: &Path,
    path: &Path,
) -> Result<PreparedEnrollment, String> {
    let active_path = state::resolve_state_path(None)?;
    if active_path != path && active_path.exists() {
        return Err(format!(
            "the per-user coding-agent proxy is already registered at {}; uninstall it before selecting {}",
            active_path.display(),
            path.display()
        ));
    }
    let platform = operations.platform()?;
    operations.validate_supported_platform(platform)?;
    let existing = if path.exists() {
        Some(state::read(path).map_err(|error| {
            format!(
                "{error}; legacy wrapper/MCP gateway state is not migrated in place. Run `nemo-relay uninstall {}` with the old Relay binary, then rerun `nemo-relay install {}`",
                agent.install_arg(),
                agent.install_arg()
            )
        })?)
    } else {
        None
    };
    let mut installed = if let Some(existing) = existing.as_ref() {
        existing.clone()
    } else {
        create_proxy_state(operations, platform, root, agent)?
    };
    if existing.is_some() && command.force {
        refresh_proxy_bootstrap_identity(operations, &mut installed)?;
    }
    let generation_cleanup = existing
        .is_none()
        .then(|| PendingGenerationCleanup::new(&installed));
    if ((agent == CodingAgent::ClaudeCode && installed.claude_code_installed)
        || (agent != CodingAgent::ClaudeCode
            && installed.enrollments.contains_key(enrollment_key(agent))))
        && !command.force
    {
        return Err(format!(
            "{} is already enrolled; use `nemo-relay install {} --force` to refresh it",
            agent.label(),
            agent.install_arg()
        ));
    }
    let required_hosts = required_native_hosts(&installed.enrollments, agent);
    let rotation_required = existing.as_ref().is_some_and(|state| {
        certificate::requires_rotation_for_hosts(
            &state.install_root,
            &state.certificate,
            &required_hosts,
        )
    });
    if rotation_required && installed.claude_desktop_installed {
        return Err(
            "the coding-agent proxy CA is expired, corrupt, or does not cover the current native host set; close every enrolled agent and run `nemo-relay install claude-desktop --force` so Claude settings and trust rotate transactionally"
                .into(),
        );
    }
    if rotation_required {
        ensure_enrolled_agents_stopped(
            operations,
            platform,
            &installed,
            Some(agent),
            "coding-agent proxy certificate rotation",
        )?;
    }
    Ok(PreparedEnrollment {
        platform,
        existing,
        installed,
        rotation_required,
        generation_cleanup,
    })
}

fn refresh_proxy_bootstrap_identity(
    operations: &dyn DesktopOperations,
    installed: &mut state::DesktopState,
) -> Result<(), String> {
    let relay_binary = operations.relay_binary()?;
    let (gateway_fingerprint, anthropic, max_hook_payload_bytes) =
        operations.persistent_gateway_identity_at(&installed.user_config_dir)?;
    if anthropic.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err(
            "the coding-agent proxy requires the native Anthropic upstream https://api.anthropic.com"
                .into(),
        );
    }
    installed.relay_binary = relay_binary;
    installed.relay_version = env!("CARGO_PKG_VERSION").into();
    installed.gateway_fingerprint = gateway_fingerprint;
    installed.max_hook_payload_bytes = max_hook_payload_bytes;
    Ok(())
}

fn create_proxy_state(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    root: &Path,
    first_agent: CodingAgent,
) -> Result<state::DesktopState, String> {
    state::ensure_unowned_root_available(root)?;
    operations.ensure_no_foreign_service(platform, root)?;
    state::ensure_private_directory(root)?;
    let relay_binary = operations.relay_binary()?;
    let (gateway_fingerprint, anthropic, max_hook_payload_bytes) =
        operations.persistent_gateway_identity()?;
    if anthropic.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err(
            "the coding-agent proxy requires the native Anthropic upstream https://api.anthropic.com"
                .into(),
        );
    }
    let generation = uuid::Uuid::now_v7().to_string();
    let bind = select_proxy_bind()?;
    let service_identity = operations.service_identity(platform)?;
    let proxy_token = crate::provider_auth::ProxyCredential::generate()
        .map_err(|error| error.to_string())?
        .expose()
        .to_string();
    let certificate = certificate::generate_for_hosts(
        root,
        &generation,
        agent_native_hosts(first_agent.install_arg()),
    )?;
    let mut generation_cleanup =
        PendingGenerationCleanup::for_generation(&certificate, root, &generation);
    let user_config_dir = crate::configuration::user_config_dir()
        .ok_or_else(|| "cannot determine NeMo Relay user configuration directory".to_string())?;
    let configuration_fingerprint = configuration_fingerprint(
        &generation,
        &relay_binary,
        &user_config_dir,
        &gateway_fingerprint,
        &certificate.root_sha256,
        bind,
        service_identity.as_deref(),
        None,
        &Default::default(),
    )?;
    let installed = state::DesktopState {
        schema_version: state::STATE_SCHEMA_VERSION,
        generation,
        installed_at: chrono::Utc::now().to_rfc3339(),
        relay_version: env!("CARGO_PKG_VERSION").into(),
        relay_binary,
        install_root: root.to_path_buf(),
        user_config_dir,
        platform: platform.as_str().into(),
        service_identity,
        bind,
        proxy_username: "nemo-relay-control".into(),
        proxy_token,
        upstream_proxy: None,
        gateway_fingerprint,
        max_hook_payload_bytes,
        configuration_fingerprint,
        certificate,
        settings: Default::default(),
        claude_code_installed: false,
        claude_desktop_installed: false,
        enrollments: Default::default(),
    };
    generation_cleanup.commit();
    Ok(installed)
}

fn complete_agent_enrollment(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    defer_previous_retirement: bool,
    path: &Path,
    prepared: PreparedEnrollment,
) -> Result<(AgentProxyEnrollment, Option<state::DesktopState>), String> {
    let PreparedEnrollment {
        platform,
        existing,
        mut installed,
        rotation_required,
        mut generation_cleanup,
    } = prepared;
    let claude_credential =
        enrollment_claude_credential(agent, rotation_required, existing.as_ref(), &installed);
    let mut claude_settings = prepare_enrollment_configuration(
        operations,
        platform,
        path,
        claude_credential,
        rotation_required,
        &mut installed,
        &mut generation_cleanup,
    )?;
    let trust_preexisting = operations
        .trust_status(platform, &installed.certificate, None)
        .is_ok();
    stop_previous_enrollment(operations, existing.as_ref())?;
    if let Err(error) = activate_enrollment(EnrollmentActivation {
        operations,
        platform,
        path,
        installed: &mut installed,
        existing: existing.as_ref(),
        claude_credential,
        claude_settings: &mut claude_settings,
        trust_preexisting,
        refresh_hermes: rotation_required && !defer_previous_retirement,
    }) {
        return Err(rollback_activation(
            operations,
            platform,
            existing.as_ref(),
            &installed,
            path,
            trust_preexisting,
            &mut generation_cleanup,
            error,
        ));
    }
    finish_enrollment(
        operations,
        platform,
        agent,
        defer_previous_retirement,
        rotation_required,
        existing.as_ref(),
        &installed,
        &mut generation_cleanup,
    )
}

fn enrollment_claude_credential(
    agent: CodingAgent,
    rotation_required: bool,
    existing: Option<&state::DesktopState>,
    installed: &state::DesktopState,
) -> Option<&'static str> {
    if agent == CodingAgent::ClaudeCode {
        return Some(CLAUDE_ENROLLMENT);
    }
    if !rotation_required || installed.settings.fields.is_empty() {
        return None;
    }
    existing
        .filter(|state| state.claude_enrolled())
        .or_else(|| installed.claude_enrolled().then_some(installed))
        .map(|_| CLAUDE_ENROLLMENT)
}

#[allow(clippy::too_many_arguments)]
fn prepare_enrollment_configuration(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    path: &Path,
    claude_credential: Option<&str>,
    rotation_required: bool,
    installed: &mut state::DesktopState,
    generation_cleanup: &mut Option<PendingGenerationCleanup>,
) -> Result<Option<settings::PreparedSettings>, String> {
    let result =
        prepare_enrollment_settings(operations, platform, path, claude_credential, installed);
    let settings = match result {
        Ok(settings) => settings,
        Err(error) => {
            return cleanup_configuration_prepare_error(
                installed,
                generation_cleanup,
                rotation_required,
                error,
            );
        }
    };
    installed.configuration_fingerprint = configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &installed.user_config_dir,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )?;
    Ok(settings)
}

fn prepare_enrollment_settings(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    path: &Path,
    claude_credential: Option<&str>,
    installed: &mut state::DesktopState,
) -> Result<Option<settings::PreparedSettings>, String> {
    let Some(credential) = claude_credential else {
        return Ok(None);
    };
    let prepared =
        prepare_shared_claude_settings(operations, platform, installed, path, credential)?;
    let upstream = prepared.upstream_proxy.clone();
    installed.settings = prepared.patch.clone();
    if let Some(enrollment) = installed.enrollments.get_mut(credential) {
        enrollment.upstream_proxy = upstream.clone();
    }
    installed.upstream_proxy = upstream.or_else(|| installed.upstream_proxy.clone());
    Ok(Some(prepared))
}

fn cleanup_configuration_prepare_error(
    installed: &state::DesktopState,
    generation_cleanup: &mut Option<PendingGenerationCleanup>,
    rotation_required: bool,
    error: String,
) -> Result<Option<settings::PreparedSettings>, String> {
    if !rotation_required {
        return Err(error);
    }
    let cleanup = remove_uncommitted_generation(
        &installed.certificate,
        &installed.install_root,
        &installed.generation,
    );
    if cleanup.is_ok()
        && let Some(generation_cleanup) = generation_cleanup.as_mut()
    {
        generation_cleanup.commit();
    }
    Err(match cleanup {
        Ok(()) => error,
        Err(cleanup) => {
            format!("{error}; failed to clean up the uncommitted CA rotation: {cleanup}")
        }
    })
}

fn stop_previous_enrollment(
    operations: &dyn DesktopOperations,
    previous: Option<&state::DesktopState>,
) -> Result<(), String> {
    let Some(previous) = previous else {
        return Ok(());
    };
    operations.shutdown_proxy(previous);
    operations.stop_service(previous)
}

struct EnrollmentActivation<'a> {
    operations: &'a dyn DesktopOperations,
    platform: platform::Platform,
    path: &'a Path,
    installed: &'a mut state::DesktopState,
    existing: Option<&'a state::DesktopState>,
    claude_credential: Option<&'a str>,
    claude_settings: &'a mut Option<settings::PreparedSettings>,
    trust_preexisting: bool,
    refresh_hermes: bool,
}

fn activate_enrollment(context: EnrollmentActivation<'_>) -> Result<(), String> {
    let EnrollmentActivation {
        operations,
        platform,
        path,
        installed,
        existing,
        claude_credential,
        claude_settings,
        trust_preexisting,
        refresh_hermes,
    } = context;
    if let Some(prepared) = claude_settings.as_mut() {
        settings::apply(prepared)?;
        installed.settings = prepared.patch.clone();
    }
    state::write(installed)?;
    sync_codex_ca_bundle(installed)?;
    if !trust_preexisting {
        println!("{}", trust_configuration_notice());
        operations.install_trust(platform, &installed.certificate)?;
    }
    if existing.is_none() {
        start_fresh_service_with_bind_retry(
            operations,
            platform,
            path,
            installed,
            claude_credential,
            claude_settings,
        )?;
    } else {
        operations.register_service(installed)?;
        operations.start_service(installed)?;
        operations.wait_for_health(installed)?;
    }
    state::write_locator(path)?;
    if refresh_hermes && installed.enrollments.contains_key("hermes") {
        let enrollment = enrollment_from_state(installed, "hermes")
            .ok_or_else(|| "Hermes proxy enrollment disappeared during rotation".to_string())?;
        crate::agents::refresh_hermes_proxy_environment(&enrollment)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rollback_activation(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    existing: Option<&state::DesktopState>,
    installed: &state::DesktopState,
    path: &Path,
    trust_preexisting: bool,
    generation_cleanup: &mut Option<PendingGenerationCleanup>,
    error: String,
) -> String {
    let rollback = rollback_agent_enrollment(
        operations,
        platform,
        existing,
        installed,
        path,
        trust_preexisting,
    );
    if rollback.is_ok()
        && let Some(generation_cleanup) = generation_cleanup.as_mut()
    {
        generation_cleanup.commit();
    }
    match rollback {
        Ok(()) => format!("{error}; restored the previous proxy enrollment state"),
        Err(rollback) => format!("{error}; enrollment rollback also failed: {rollback}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_enrollment(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    agent: CodingAgent,
    defer_previous_retirement: bool,
    rotation_required: bool,
    existing: Option<&state::DesktopState>,
    installed: &state::DesktopState,
    generation_cleanup: &mut Option<PendingGenerationCleanup>,
) -> Result<(AgentProxyEnrollment, Option<state::DesktopState>), String> {
    let pending_retirement = (rotation_required && defer_previous_retirement)
        .then(|| existing.cloned())
        .flatten();
    retire_previous_enrollment(
        operations,
        platform,
        rotation_required && !defer_previous_retirement,
        existing,
    )?;
    if let Some(generation_cleanup) = generation_cleanup.as_mut() {
        generation_cleanup.commit();
    }
    print_codex_linux_trust(platform, agent, installed);
    let enrollment = enrollment_from_state(installed, enrollment_key(agent))
        .ok_or_else(|| "proxy enrollment disappeared after activation".to_string())?;
    Ok((enrollment, pending_retirement))
}

fn retire_previous_enrollment(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    retire: bool,
    previous: Option<&state::DesktopState>,
) -> Result<(), String> {
    let Some(previous) = previous.filter(|_| retire) else {
        return Ok(());
    };
    operations.remove_trust(platform, &previous.certificate)?;
    retire_generation(previous)
}

fn print_codex_linux_trust(
    platform: platform::Platform,
    agent: CodingAgent,
    installed: &state::DesktopState,
) {
    if platform == platform::Platform::Linux && agent == CodingAgent::Codex {
        println!(
            "Codex TLS trust: set CODEX_CA_CERTIFICATE={} in every Codex launch environment, then restart Codex",
            codex_ca_bundle_path(&installed.install_root).display()
        );
    }
}

fn start_fresh_service_with_bind_retry(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    state_path: &Path,
    installed: &mut state::DesktopState,
    claude_credential: Option<&str>,
    claude_settings: &mut Option<settings::PreparedSettings>,
) -> Result<(), String> {
    for attempt in 0..usize::from(USER_PORT_PROBE_COUNT) {
        operations.register_service(installed)?;
        operations.start_service(installed)?;
        let Err(health_error) = operations.wait_for_health(installed) else {
            return Ok(());
        };
        operations.stop_service(installed).map_err(|stop_error| {
            format!("{health_error}; failed to stop the unhealthy proxy service: {stop_error}")
        })?;
        if !proxy_bind_is_occupied(installed.bind)? {
            return Err(health_error);
        }
        if attempt + 1 == usize::from(USER_PORT_PROBE_COUNT) {
            return Err(format!(
                "{health_error}; exhausted per-user endpoint retries after a bind handoff race"
            ));
        }
        reselect_fresh_proxy_endpoint(
            operations,
            platform,
            state_path,
            installed,
            claude_credential,
            claude_settings,
        )?;
    }
    unreachable!("fresh proxy endpoint retry loop returns on every terminal outcome")
}

fn proxy_bind_is_occupied(address: SocketAddr) -> Result<bool, String> {
    match std::net::TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Ok(true),
        Err(error) => Err(format!(
            "failed to inspect unhealthy coding-agent proxy address {address}: {error}"
        )),
    }
}

fn reselect_fresh_proxy_endpoint(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    state_path: &Path,
    installed: &mut state::DesktopState,
    claude_credential: Option<&str>,
    claude_settings: &mut Option<settings::PreparedSettings>,
) -> Result<(), String> {
    let previous = installed.bind;
    installed.bind = select_proxy_bind()?;
    if let Some(credential) = claude_credential {
        let mut prepared = prepare_shared_claude_settings(
            operations, platform, installed, state_path, credential,
        )?;
        settings::apply(&mut prepared)?;
        let upstream = prepared.upstream_proxy.clone();
        installed.settings = prepared.patch.clone();
        if let Some(enrollment) = installed.enrollments.get_mut(credential) {
            enrollment.upstream_proxy = upstream.clone();
        }
        installed.upstream_proxy = upstream.or_else(|| installed.upstream_proxy.clone());
        *claude_settings = Some(prepared);
    }
    installed.configuration_fingerprint = configuration_fingerprint(
        &installed.generation,
        &installed.relay_binary,
        &installed.user_config_dir,
        &installed.gateway_fingerprint,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )?;
    state::write(installed)?;
    sync_codex_ca_bundle(installed)?;
    println!(
        "coding-agent proxy endpoint {previous} was occupied during service handoff; retrying at {}",
        installed.bind
    );
    Ok(())
}

fn prepare_shared_claude_settings(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    installed: &state::DesktopState,
    state_path: &Path,
    credential: &str,
) -> Result<settings::PreparedSettings, String> {
    let settings_path = operations.settings_path()?;
    let ca_path = shared_claude_ca_path(platform, installed, &settings_path)?;
    let proxy_url = installed
        .proxy_url_for(credential)
        .ok_or_else(|| format!("Claude credential {credential} is not enrolled"))?;
    settings::retarget(
        &settings_path,
        &proxy_url,
        state_path,
        &ca_path,
        platform.as_str(),
        installed
            .enrollments
            .get(credential)
            .and_then(|enrollment| enrollment.upstream_proxy.as_ref()),
        &installed.settings,
    )
}

fn shared_claude_ca_path(
    platform: platform::Platform,
    installed: &state::DesktopState,
    settings_path: &Path,
) -> Result<PathBuf, String> {
    if platform != platform::Platform::Linux {
        return Ok(installed.certificate.root_pem.clone());
    }
    let combined = installed
        .certificate
        .root_pem
        .parent()
        .expect("generated root has a parent")
        .join("claude-ca-bundle.pem");
    let existing = installed.settings.original_ca_bundle.clone().map_or_else(
        || settings::existing_ca_bundle_path(settings_path),
        |path| Ok(Some(path)),
    )?;
    let root_pem = std::fs::read_to_string(&installed.certificate.root_pem).map_err(|error| {
        format!(
            "failed to read {}: {error}",
            installed.certificate.root_pem.display()
        )
    })?;
    settings::compose_linux_ca_bundle(&combined, &root_pem, existing.as_deref())?;
    Ok(combined)
}

fn codex_ca_bundle_path(install_root: &Path) -> PathBuf {
    install_root.join(CODEX_CA_BUNDLE_FILE_NAME)
}

fn codex_ca_bundle_source(
    agent: CodingAgent,
    platform: platform::Platform,
    install_root: &Path,
    prior: Option<&state::AgentEnrollment>,
) -> Result<(Option<PathBuf>, Option<String>), String> {
    if agent != CodingAgent::Codex || platform != platform::Platform::Linux {
        return Ok((None, None));
    }
    if let Some(prior) = prior {
        return Ok((
            prior.client_ca_bundle_source.clone(),
            prior.client_ca_bundle_variable.clone(),
        ));
    }
    let stable = codex_ca_bundle_path(install_root);
    for name in ["CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"] {
        let Some(raw) = std::env::var_os(name) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let selected = PathBuf::from(raw);
        let absolute = if selected.is_absolute() {
            selected
        } else {
            std::env::current_dir()
                .map_err(|error| format!("failed to resolve {name}: {error}"))?
                .join(selected)
        };
        if absolute == stable || absolute.starts_with(install_root.join("generations")) {
            return Ok((None, None));
        }
        let canonical = absolute.canonicalize().map_err(|error| {
            format!(
                "failed to resolve Codex CA bundle selected by {name} at {}: {error}",
                absolute.display()
            )
        })?;
        return Ok((Some(canonical), Some(name.into())));
    }
    Ok((None, None))
}

fn expected_codex_ca_bundle(installed: &state::DesktopState) -> Result<Vec<u8>, String> {
    const MAX_CLIENT_CA_BYTES: usize = 16 * 1024 * 1024;

    let root = crate::filesystem::bounded::read_bounded_regular_file(
        &installed.certificate.root_pem,
        "coding-agent proxy root certificate",
    )?;
    let source = installed
        .enrollments
        .get("codex")
        .and_then(|enrollment| enrollment.client_ca_bundle_source.as_deref())
        .map(|path| {
            crate::filesystem::bounded::read_bounded_regular_file(
                path,
                "pre-existing Codex CA bundle",
            )
        })
        .transpose()?
        .unwrap_or_default();
    if source.len().saturating_add(root.len()) > MAX_CLIENT_CA_BYTES {
        return Err(format!(
            "combined Codex CA bundle exceeds the {MAX_CLIENT_CA_BYTES}-byte limit"
        ));
    }
    let mut combined = source;
    if !combined.is_empty() && !combined.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&root);
    Ok(combined)
}

fn sync_codex_ca_bundle(installed: &state::DesktopState) -> Result<(), String> {
    let path = codex_ca_bundle_path(&installed.install_root);
    if installed.platform != platform::Platform::Linux.as_str()
        || !installed.enrollments.contains_key("codex")
    {
        return state::remove_file_if_present(&path);
    }
    let bytes = expected_codex_ca_bundle(installed)?;
    crate::filesystem::atomic_write_private(&path, &bytes)
}

fn verify_codex_ca_bundle(installed: &state::DesktopState) -> Result<String, String> {
    let stable = codex_ca_bundle_path(&installed.install_root);
    let expected = expected_codex_ca_bundle(installed)?;
    let actual = crate::filesystem::bounded::read_bounded_regular_file(
        &stable,
        "Relay-managed Codex CA bundle",
    )?;
    if actual != expected {
        return Err(format!(
            "Relay-managed Codex CA bundle {} differs from the active proxy generation; reinstall Codex with --force",
            stable.display()
        ));
    }
    let selected = ["CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"]
        .into_iter()
        .find_map(|name| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(|value| (name, PathBuf::from(value)))
        })
        .ok_or_else(|| {
            format!(
                "Codex on Linux requires `CODEX_CA_CERTIFICATE={}` before Codex starts; set it in the Codex launch environment and restart Codex",
                stable.display()
            )
        })?;
    let selected_path = if selected.1.is_absolute() {
        selected.1
    } else {
        std::env::current_dir()
            .map_err(|error| format!("failed to resolve {}: {error}", selected.0))?
            .join(selected.1)
    };
    let selected_bytes = crate::filesystem::bounded::read_bounded_regular_file(
        &selected_path,
        &format!("Codex CA bundle selected by {}", selected.0),
    )?;
    let root = crate::filesystem::bounded::read_bounded_regular_file(
        &installed.certificate.root_pem,
        "coding-agent proxy root certificate",
    )?;
    if !selected_bytes
        .windows(root.len())
        .any(|candidate| candidate == root)
    {
        return Err(format!(
            "{}={} does not contain the active Relay root CA; point CODEX_CA_CERTIFICATE at {} and restart Codex",
            selected.0,
            selected_path.display(),
            stable.display()
        ));
    }
    Ok(format!(
        "{} selects a bundle containing the active Relay root CA",
        selected.0
    ))
}

fn rollback_agent_enrollment(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    previous: Option<&state::DesktopState>,
    attempted: &state::DesktopState,
    state_path: &Path,
    trust_preexisting: bool,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    operations.shutdown_proxy(attempted);
    errors.record(operations.stop_service(attempted));
    if let Some(previous) = previous {
        if attempted.settings != previous.settings {
            if previous.settings.fields.is_empty() {
                errors.record(settings::restore(&attempted.settings).map(|_| ()));
            } else {
                errors.record(settings::apply_installed(&previous.settings));
            }
        }
        errors.record(state::write(previous));
        errors.record(sync_codex_ca_bundle(previous));
        if operations
            .trust_status(platform, &previous.certificate, None)
            .is_err()
        {
            errors.record(operations.install_trust(platform, &previous.certificate));
        }
        if !trust_preexisting
            && previous.certificate.root_sha256 != attempted.certificate.root_sha256
        {
            errors.record(operations.remove_trust(platform, &attempted.certificate));
            errors.record(remove_signer_then_generation(
                &attempted.certificate,
                &attempted.install_root,
                &attempted.generation,
            ));
        }
        errors.record(operations.register_service(previous));
        errors.record(operations.start_service(previous));
        errors.record(operations.wait_for_health(previous));
        errors.record(state::write_locator(state_path));
    } else {
        if !attempted.settings.fields.is_empty() {
            errors.record(settings::restore(&attempted.settings).map(|_| ()));
        }
        errors.record(operations.unregister_service(attempted));
        if !trust_preexisting {
            errors.record(operations.remove_trust(platform, &attempted.certificate));
        }
        errors.record(state::remove_locator_if_matches(state_path));
        errors.record(state::remove_file_if_present(state_path));
        errors.record(state::remove_file_if_present(&codex_ca_bundle_path(
            &attempted.install_root,
        )));
        errors.record(remove_signer_then_generation(
            &attempted.certificate,
            &attempted.install_root,
            &attempted.generation,
        ));
        errors.record(remove_fresh_install_root(&attempted.install_root));
    }
    errors.finish()
}

pub(crate) fn unenroll_agent_transactionally<T>(
    agent: CodingAgent,
    command: &UninstallRequest,
    setup_snapshot: Option<&crate::agents::SetupSnapshot>,
    uninstall_host: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    unenroll_agent_transactionally_with(
        &SystemOperations,
        agent,
        command,
        setup_snapshot,
        uninstall_host,
    )
}

fn unenroll_agent_transactionally_with<T>(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &UninstallRequest,
    setup_snapshot: Option<&crate::agents::SetupSnapshot>,
    uninstall_host: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    if command.dry_run {
        return uninstall_host();
    }
    let setup_snapshot = setup_snapshot
        .ok_or_else(|| CliError::Install("uninstall setup snapshot is missing".into()))?;
    let _operation_lock = desktop_operation_lock().map_err(CliError::Install)?;
    recover_pending_agent_transaction(operations).map_err(CliError::Install)?;
    let path =
        state::resolve_state_path(command.install_dir.as_deref()).map_err(CliError::Install)?;
    ensure_selected_enrollment_root(
        command.install_dir.as_deref(),
        &[enrollment_key(agent)],
        "uninstall",
    )
    .map_err(CliError::Install)?;
    let previous = path
        .exists()
        .then(|| state::read(&path))
        .transpose()
        .map_err(CliError::Install)?;
    let marketplace_snapshot =
        capture_agent_marketplace_snapshot(agent, command.install_dir.as_deref(), setup_snapshot)
            .map_err(CliError::Install)?;
    let mut journal = AgentTransactionJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "uninstall".into(),
        stage: "removing-host".into(),
        agent: agent.install_arg().into(),
        install_root: state::install_root(command.install_dir.as_deref()),
        state_path: path,
        previous_state: previous,
        setup_snapshot: setup_snapshot.clone(),
        setup_result_snapshot: None,
        marketplace_snapshot,
        marketplace_result_snapshot: None,
    };
    write_agent_transaction(&journal).map_err(CliError::Install)?;
    let result = uninstall_host();
    if let Err(snapshot_error) = persist_agent_host_result(&mut journal) {
        let error = match result {
            Ok(_) => CliError::Install(snapshot_error),
            Err(operation_error) => CliError::Install(format!(
                "{operation_error}; additionally failed to persist the host result snapshot: {snapshot_error}"
            )),
        };
        return recover_failed_agent_transaction(operations, error);
    }
    let result = match result {
        Ok(result) => result,
        Err(error) => return recover_failed_agent_transaction(operations, error),
    };
    journal.stage = "host-removed".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    if let Err(error) = unenroll_agent_locked(operations, agent, command) {
        return recover_failed_agent_transaction(operations, error);
    }
    journal.stage = "proxy-removed".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    journal.stage = "committed".into();
    if let Err(error) = write_agent_transaction(&journal) {
        return recover_failed_agent_transaction(operations, CliError::Install(error));
    }
    finalize_committed_agent_transaction(operations, &journal).map_err(CliError::Install)?;
    remove_agent_transaction().map_err(CliError::Install)?;
    Ok(result)
}

pub(crate) fn ensure_selected_enrollment_root(
    install_dir: Option<&Path>,
    enrollment_names: &[&str],
    operation: &str,
) -> Result<(), String> {
    if install_dir.is_none() {
        return Ok(());
    }
    let selected_path = state::resolve_state_path(install_dir)?;
    let active_path = state::resolve_state_path(None)?;
    if active_path == selected_path || !active_path.exists() {
        return Ok(());
    }
    let active = state::read(&active_path)?;
    let mut matched = enrollment_names
        .iter()
        .filter(|name| active.enrollments.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return Ok(());
    }
    matched.sort_unstable();
    Err(format!(
        "{} is enrolled at {}; rerun {operation} with the matching --install-dir instead of {}",
        matched.join(", "),
        active_path.display(),
        selected_path.display()
    ))
}

fn capture_agent_marketplace_snapshot(
    agent: CodingAgent,
    install_dir: Option<&Path>,
    setup_snapshot: &crate::agents::SetupSnapshot,
) -> Result<Option<crate::installation::marketplace::DurableMarketplaceSnapshot>, String> {
    if !matches!(agent, CodingAgent::Codex | CodingAgent::ClaudeCode) {
        return Ok(None);
    }
    #[cfg(test)]
    if matches!(setup_snapshot, crate::agents::SetupSnapshot::Test) {
        return Ok(None);
    }
    let _ = setup_snapshot;
    let selected = install_dir.map_or_else(
        crate::installation::marketplace::default_marketplace_install_dir,
        Path::to_path_buf,
    );
    let absolute = if selected.is_absolute() {
        selected
    } else {
        std::env::current_dir()
            .map_err(|error| format!("failed to resolve marketplace directory: {error}"))?
            .join(selected)
    };
    let absolute = absolute.canonicalize().unwrap_or(absolute);
    crate::installation::marketplace::capture_marketplace_snapshot(agent, &absolute).map(Some)
}

fn unenroll_agent_locked(
    operations: &dyn DesktopOperations,
    agent: CodingAgent,
    command: &UninstallRequest,
) -> Result<(), CliError> {
    let path =
        state::resolve_state_path(command.install_dir.as_deref()).map_err(CliError::Install)?;
    if !path.exists() {
        return Ok(());
    }
    let mut installed = state::read(&path).map_err(CliError::Install)?;
    let previous = installed.clone();
    let removed_enrollment = if agent == CodingAgent::ClaudeCode {
        if !installed.claude_code_installed {
            return Ok(());
        }
        installed.claude_code_installed = false;
        if installed.claude_desktop_installed {
            installed
                .enrollments
                .get(CLAUDE_ENROLLMENT)
                .cloned()
                .expect("installed Claude surface has a Claude enrollment")
        } else {
            installed
                .enrollments
                .remove(CLAUDE_ENROLLMENT)
                .expect("installed Claude surface has a Claude enrollment")
        }
    } else {
        let Some(removed) = installed.enrollments.remove(agent.install_arg()) else {
            return Ok(());
        };
        removed
    };
    let restore_claude_settings = agent == CodingAgent::ClaudeCode
        && !installed.claude_desktop_installed
        && !installed.settings.fields.is_empty();
    let platform = platform::Platform::parse(&installed.platform).map_err(CliError::Install)?;
    operations.shutdown_proxy(&installed);
    operations
        .stop_service(&installed)
        .map_err(CliError::Install)?;
    if installed.enrollments.is_empty() {
        let result = (|| {
            if restore_claude_settings {
                settings::restore(&installed.settings)?;
            }
            operations.unregister_service(&installed)?;
            operations.remove_trust(platform, &installed.certificate)?;
            sync_codex_ca_bundle(&installed)?;
            state::remove_locator_if_matches(&path)?;
            state::remove_file_if_present(&path)
        })();
        if let Err(error) = result {
            let rollback = restore_removed_enrollment(operations, platform, &previous, &path);
            return Err(CliError::Install(match rollback {
                Ok(()) => format!("{error}; restored the removed proxy enrollment"),
                Err(rollback) => {
                    format!("{error}; enrollment restoration also failed: {rollback}")
                }
            }));
        }
    } else {
        if restore_claude_settings {
            if let Err(error) = settings::restore(&installed.settings) {
                let rollback = restore_removed_enrollment(operations, platform, &previous, &path);
                return Err(CliError::Install(match rollback {
                    Ok(()) => format!("{error}; restored the removed proxy enrollment"),
                    Err(rollback) => {
                        format!("{error}; enrollment restoration also failed: {rollback}")
                    }
                }));
            }
            installed.settings = Default::default();
        }
        installed.upstream_proxy = installed
            .enrollments
            .values()
            .find_map(|enrollment| enrollment.upstream_proxy.clone());
        installed.configuration_fingerprint = configuration_fingerprint(
            &installed.generation,
            &installed.relay_binary,
            &installed.user_config_dir,
            &installed.gateway_fingerprint,
            &installed.certificate.root_sha256,
            installed.bind,
            installed.service_identity.as_deref(),
            installed.upstream_proxy.as_ref(),
            &installed.enrollments,
        )
        .map_err(CliError::Install)?;
        let result = state::write(&installed)
            .and_then(|_| sync_codex_ca_bundle(&installed))
            .and_then(|_| operations.register_service(&installed))
            .and_then(|_| operations.start_service(&installed))
            .and_then(|_| operations.wait_for_health(&installed));
        if let Err(error) = result {
            let rollback = restore_removed_enrollment(operations, platform, &previous, &path);
            return Err(CliError::Install(match rollback {
                Ok(()) => format!("{error}; restored the removed proxy enrollment"),
                Err(rollback) => {
                    format!("{error}; enrollment restoration also failed: {rollback}")
                }
            }));
        }
    }
    for notice in
        codex_ca_uninstall_notices(agent, platform, &previous.install_root, &removed_enrollment)
    {
        println!("{notice}");
    }
    Ok(())
}

fn codex_ca_uninstall_notices(
    agent: CodingAgent,
    platform: platform::Platform,
    install_root: &Path,
    enrollment: &state::AgentEnrollment,
) -> Vec<String> {
    if agent != CodingAgent::Codex || platform != platform::Platform::Linux {
        return Vec::new();
    }
    let mut notices = vec![format!(
        "Codex TLS cleanup: remove CODEX_CA_CERTIFICATE={} from every Codex launch environment before restarting Codex",
        codex_ca_bundle_path(install_root).display()
    )];
    if let (Some(variable), Some(source)) = (
        enrollment.client_ca_bundle_variable.as_deref(),
        enrollment.client_ca_bundle_source.as_deref(),
    ) {
        notices.push(format!(
            "Codex TLS cleanup: restore the pre-enrollment {variable}={} value",
            source.display()
        ));
    } else {
        notices.push(
            "Codex TLS cleanup: no pre-enrollment Codex CA variable was recorded; leave CODEX_CA_CERTIFICATE unset unless another integration requires it"
                .into(),
        );
    }
    notices
}

fn restore_removed_enrollment(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    previous: &state::DesktopState,
    state_path: &Path,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    errors.record(state::ensure_private_directory(&previous.install_root));
    errors.record(state::write(previous));
    errors.record(sync_codex_ca_bundle(previous));
    if !previous.settings.fields.is_empty() {
        errors.record(settings::apply_installed(&previous.settings));
    }
    if operations
        .trust_status(platform, &previous.certificate, None)
        .is_err()
    {
        errors.record(operations.install_trust(platform, &previous.certificate));
    }
    errors.record(operations.register_service(previous));
    errors.record(operations.start_service(previous));
    errors.record(operations.wait_for_health(previous));
    errors.record(state::write_locator(state_path));
    errors.finish()
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorCheck {
    name: String,
    ok: bool,
    details: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DoctorReport {
    schema_version: u32,
    integration: &'static str,
    platform: String,
    state_path: PathBuf,
    ok: bool,
    effective_protection: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn push(&mut self, name: impl Into<String>, result: Result<String, String>) {
        match result {
            Ok(details) => self.checks.push(DoctorCheck {
                name: name.into(),
                ok: true,
                details,
            }),
            Err(details) => self.checks.push(DoctorCheck {
                name: name.into(),
                ok: false,
                details,
            }),
        }
    }

    fn finish(mut self) -> Self {
        self.ok = self.checks.iter().all(|check| check.ok);
        self.effective_protection = self.ok;
        self
    }
}

pub(crate) fn install(command: InstallRequest) -> Result<ExitCode, CliError> {
    install_inner(command).map_err(CliError::Install)?;
    Ok(ExitCode::SUCCESS)
}

fn install_inner(command: InstallRequest) -> Result<(), String> {
    install_with(&SystemOperations, command)
}

fn install_with(operations: &dyn DesktopOperations, command: InstallRequest) -> Result<(), String> {
    let preflight = desktop_install_preflight(operations, &command)?;
    if command.dry_run {
        print_desktop_install_dry_run(&preflight);
        return Ok(());
    }
    execute_desktop_install(operations, &command, preflight)
}

struct DesktopInstallPreflight {
    platform: platform::Platform,
    install_root: PathBuf,
    state_path: PathBuf,
    marketplace_dir: PathBuf,
    old_state: Option<state::DesktopState>,
}

fn desktop_install_preflight(
    operations: &dyn DesktopOperations,
    command: &InstallRequest,
) -> Result<DesktopInstallPreflight, String> {
    state::ensure_no_legacy_state(command.install_dir.as_deref())?;
    let platform = operations.platform()?;
    let install_root = state::install_root(command.install_dir.as_deref());
    let state_path = state::selected_state_path(command.install_dir.as_deref());
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "coding-agent proxy install root has no parent".to_string())?
        .to_path_buf();
    let active_state_path = state::resolve_state_path(None)?;
    if active_state_path != state_path && active_state_path.exists() {
        return Err(format!(
            "Claude Desktop protection is already registered at {}; uninstall it before selecting {}",
            active_state_path.display(),
            state_path.display()
        ));
    }
    let journal_exists = state::journal_path(&install_root).exists();
    let old_state = state_path
        .exists()
        .then(|| state::read(&state_path))
        .transpose()?;
    if journal_exists && !command.force {
        return Err(format!(
            "an incomplete Claude Desktop installation journal exists at {}; close Claude and rerun with `nemo-relay install claude-desktop --force` to restore the prior generation before upgrading",
            state::journal_path(&install_root).display()
        ));
    }
    if old_state
        .as_ref()
        .is_some_and(|state| state.claude_desktop_installed)
        && !command.force
        && !journal_exists
    {
        return Err(format!(
            "Claude Desktop protection is already installed at {}; use `nemo-relay install claude-desktop --force` to rotate and upgrade it",
            state_path.display()
        ));
    }
    if old_state.is_none() && operations.plugin_exists(&marketplace_dir) {
        return Err(format!(
            "legacy Claude Code plugin or MCP-gateway state exists at {}; this release does not migrate it in place. Close Claude clients, uninstall the integration with the old Relay binary, then rerun `nemo-relay install claude-desktop`",
            marketplace_dir.display()
        ));
    }
    Ok(DesktopInstallPreflight {
        platform,
        install_root,
        state_path,
        marketplace_dir,
        old_state,
    })
}

fn print_desktop_install_dry_run(preflight: &DesktopInstallPreflight) {
    println!("validate Claude Desktop and terminal Claude Code are closed");
    println!(
        "write owner-only Claude Desktop state at {}",
        preflight.state_path.display()
    );
    println!(
        "select and persist an available per-user authenticated loopback proxy port from {USER_PORT_BASE}-{}",
        u32::from(USER_PORT_BASE) + USER_PORT_SPAN - 1
    );
    println!(
        "issue a constrained certificate for {}",
        certificate::INTERCEPTED_HOST
    );
    println!("{}", trust_configuration_notice());
    println!("transactionally update ~/.claude/settings.json");
    println!("install or reuse the Claude Code marketplace plugin");
    println!(
        "register the {} per-user login service",
        preflight.platform.as_str()
    );
}

fn execute_desktop_install(
    operations: &dyn DesktopOperations,
    command: &InstallRequest,
    preflight: DesktopInstallPreflight,
) -> Result<(), String> {
    let DesktopInstallPreflight {
        platform,
        install_root,
        state_path,
        marketplace_dir,
        mut old_state,
    } = preflight;
    let platform_details = operations.validate_supported_platform(platform)?;
    let application = operations.application_identity(platform)?;
    if old_state.is_none() {
        state::ensure_unowned_root_available(&install_root)?;
        operations.ensure_no_foreign_service(platform, &install_root)?;
    }
    let _operation_lock = desktop_operation_lock()?;
    if let Some(installed) = old_state.as_ref() {
        ensure_enrolled_agents_stopped(
            operations,
            platform,
            installed,
            Some(CodingAgent::ClaudeCode),
            "Claude Desktop installation and certificate rotation",
        )?;
    } else {
        ensure_claude_stopped(operations, platform, "installation")?;
    }
    if state::journal_path(&install_root).exists() {
        recover_interrupted_operation(operations, &install_root, &state_path, platform)?;
    }
    old_state = state_path
        .exists()
        .then(|| state::read(&state_path))
        .transpose()?;
    if old_state
        .as_ref()
        .is_some_and(|state| state.claude_desktop_installed)
        && !command.force
    {
        return Err(format!(
            "Claude Desktop protection was installed by another operation at {}; use --force to rotate it",
            state_path.display()
        ));
    }
    log::info!(
        target: "nemo_relay.installation",
        event = "install_preflight_complete",
        platform = platform.as_str(),
        platform_details = platform_details.as_str(),
        application = application.as_str();
        "Claude Desktop install preflight completed"
    );

    let relay_binary = operations.relay_binary()?;
    let user_config_dir = match old_state.as_ref() {
        Some(state) => state.user_config_dir.clone(),
        None => crate::configuration::user_config_dir().ok_or_else(|| {
            "cannot determine NeMo Relay user configuration directory".to_string()
        })?,
    };
    let (gateway_fingerprint, anthropic_base_url, max_hook_payload_bytes) =
        operations.persistent_gateway_identity_at(&user_config_dir)?;
    if anthropic_base_url.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err(format!(
            "the coding-agent proxy does not support a custom Anthropic upstream ({anthropic_base_url}); restore the native Anthropic upstream before installing"
        ));
    }

    let marketplace_preexisting = operations.plugin_exists(&marketplace_dir);
    let settings_path = operations.settings_path()?;
    let settings_snapshot = crate::filesystem::snapshot_optional_file(&settings_path)?;
    let provider_backup_snapshot =
        crate::filesystem::snapshot_optional_file(&crate::filesystem::backup_path(&settings_path))?;
    let marketplace_snapshot = operations.marketplace_snapshot(&marketplace_dir)?;
    state::ensure_private_directory(&install_root)?;
    let generation = uuid::Uuid::now_v7().to_string();
    let mut journal = state::InstallJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "install".into(),
        stage: "preparing".into(),
        generation: generation.clone(),
        old_state: old_state.clone(),
        settings_snapshot: Some(settings_snapshot.clone()),
        provider_backup_snapshot: Some(provider_backup_snapshot.clone()),
        marketplace_snapshot,
        settings_result_snapshot: None,
        provider_backup_result_snapshot: None,
        marketplace_result_snapshot: None,
    };
    state::write_journal(&install_root, &journal)?;

    let prepared = prepare_desktop_generation(
        operations,
        platform,
        &install_root,
        &state_path,
        &settings_path,
        &generation,
        &relay_binary,
        &gateway_fingerprint,
        max_hook_payload_bytes,
        old_state.as_ref(),
        &mut journal,
    );
    let (mut new_state, ca_path) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let recovery =
                recover_interrupted_operation(operations, &install_root, &state_path, platform);
            return Err(match recovery {
                Ok(()) => format!("{error}; restored the previous Claude Desktop generation"),
                Err(recovery) => format!("{error}; rollback also failed: {recovery}"),
            });
        }
    };

    let mut progress = InstallProgress::default();
    let result = activate_desktop_generation(
        operations,
        platform,
        command,
        &install_root,
        &state_path,
        &marketplace_dir,
        marketplace_preexisting,
        &settings_path,
        &provider_backup_snapshot,
        &ca_path,
        &mut journal,
        &mut new_state,
        &mut progress,
    );

    if let Err(error) = result {
        let snapshots = DesktopRollbackSnapshots {
            settings: &settings_snapshot,
            provider_backup: &provider_backup_snapshot,
            settings_result: journal.settings_result_snapshot.as_ref(),
            provider_backup_result: journal.provider_backup_result_snapshot.as_ref(),
            marketplace: journal.marketplace_snapshot.as_ref(),
            marketplace_result: journal.marketplace_result_snapshot.as_ref(),
            marketplace_dir: Some(&marketplace_dir),
        };
        let rollback = rollback_install(
            operations,
            &new_state,
            old_state.as_ref(),
            &snapshots,
            &progress,
        );
        return Err(match rollback {
            Ok(()) => format!("{error}; restored the previous Claude Desktop generation"),
            Err(rollback) => format!("{error}; rollback also failed: {rollback}"),
        });
    }

    if let Some(old) = old_state.as_ref() {
        finish_replaced_proxy_generation(operations, platform, old, &new_state)?;
    }
    state::remove_file_if_present(&state::journal_path(&install_root))?;
    println!(
        "installed Claude Desktop protection generation {} at {}",
        new_state.generation,
        install_root.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prepare_desktop_generation(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    install_root: &Path,
    state_path: &Path,
    settings_path: &Path,
    generation: &str,
    relay_binary: &Path,
    gateway_fingerprint: &str,
    max_hook_payload_bytes: usize,
    old_state: Option<&state::DesktopState>,
    journal: &mut state::InstallJournal,
) -> Result<(state::DesktopState, PathBuf), String> {
    if let Some(old) = old_state {
        operations.shutdown_proxy(old);
        operations.stop_service(old)?;
        settings::restore(&old.settings)?;
    }

    let existing_enrollments = old_state
        .map(|state| &state.enrollments)
        .cloned()
        .unwrap_or_default();
    let certificate_hosts = required_native_hosts(&existing_enrollments, CodingAgent::ClaudeCode);
    let certificate =
        certificate::generate_for_hosts(install_root, generation, &certificate_hosts)?;
    let proxy_token = crate::provider_auth::ProxyCredential::generate()
        .map_err(|error| error.to_string())?
        .expose()
        .to_string();
    let proxy_username = "nemo-relay-control".to_string();
    let bind = old_state.map_or_else(select_proxy_bind, |state| Ok(state.bind))?;
    let service_identity = match old_state {
        Some(state) => state.service_identity.clone(),
        None => operations.service_identity(platform)?,
    };
    let mut enrollments = existing_enrollments;
    let existing_claude = enrollments.get(CLAUDE_ENROLLMENT).cloned();
    let enrollment_token = existing_claude.as_ref().map_or_else(
        || {
            crate::provider_auth::ProxyCredential::generate()
                .map_err(|error| error.to_string())
                .map(|credential| credential.expose().to_string())
        },
        |enrollment| Ok(enrollment.token.clone()),
    )?;
    let enrollment_username = existing_claude.as_ref().map_or_else(
        || "nemo-relay-claude".to_string(),
        |enrollment| enrollment.username.clone(),
    );
    enrollments.insert(
        CLAUDE_ENROLLMENT.into(),
        state::AgentEnrollment {
            username: enrollment_username,
            token: enrollment_token,
            installed_at: chrono::Utc::now().to_rfc3339(),
            upstream_proxy: None,
            client_ca_bundle_source: None,
            client_ca_bundle_variable: None,
        },
    );
    let configuration_enrollment = enrollments
        .get(CLAUDE_ENROLLMENT)
        .expect("Claude enrollment was inserted above");
    let provisional_proxy_url = format!(
        "https://{}:{}@{bind}",
        configuration_enrollment.username, configuration_enrollment.token
    );
    let ca_path = prepare_desktop_ca_path(platform, &certificate, settings_path, old_state)?;
    let provisional_settings = settings::prepare(
        settings_path,
        &provisional_proxy_url,
        state_path,
        &ca_path,
        platform.as_str(),
        old_state.and_then(|state| state.upstream_proxy.as_ref()),
    )?;
    enrollments
        .get_mut(CLAUDE_ENROLLMENT)
        .expect("Claude enrollment was inserted above")
        .upstream_proxy = provisional_settings.upstream_proxy.clone();
    let user_config_dir = match old_state {
        Some(state) => state.user_config_dir.clone(),
        None => crate::configuration::user_config_dir().ok_or_else(|| {
            "cannot determine NeMo Relay user configuration directory".to_string()
        })?,
    };
    let configuration_fingerprint = configuration_fingerprint(
        generation,
        relay_binary,
        &user_config_dir,
        gateway_fingerprint,
        &certificate.root_sha256,
        bind,
        service_identity.as_deref(),
        provisional_settings.upstream_proxy.as_ref(),
        &enrollments,
    )?;
    let new_state = state::DesktopState {
        schema_version: state::STATE_SCHEMA_VERSION,
        generation: generation.into(),
        installed_at: chrono::Utc::now().to_rfc3339(),
        relay_version: env!("CARGO_PKG_VERSION").into(),
        relay_binary: relay_binary.into(),
        install_root: install_root.into(),
        user_config_dir,
        platform: platform.as_str().into(),
        service_identity,
        bind,
        proxy_username,
        proxy_token,
        upstream_proxy: provisional_settings.upstream_proxy.clone(),
        gateway_fingerprint: gateway_fingerprint.into(),
        max_hook_payload_bytes,
        configuration_fingerprint,
        certificate,
        settings: settings::SettingsPatch {
            settings_path: settings_path.into(),
            original_settings_absent: !settings_path.exists(),
            fields: Default::default(),
            previous_permissions: None,
            original_ca_bundle: None,
        },
        claude_code_installed: old_state.is_some_and(|state| state.claude_code_installed),
        claude_desktop_installed: true,
        enrollments,
    };
    state::write(&new_state)?;
    sync_codex_ca_bundle(&new_state)?;
    journal.stage = "prepared".into();
    state::write_journal(install_root, journal)?;
    Ok((new_state, ca_path))
}

fn prepare_desktop_ca_path(
    platform: platform::Platform,
    certificate: &state::CertificateState,
    settings_path: &Path,
    old_state: Option<&state::DesktopState>,
) -> Result<PathBuf, String> {
    if platform != platform::Platform::Linux {
        return Ok(certificate.root_pem.clone());
    }
    let combined = certificate
        .root_pem
        .parent()
        .expect("generated root has a parent")
        .join("claude-ca-bundle.pem");
    let existing = match old_state.filter(|state| state.claude_desktop_installed) {
        Some(state) => state.settings.original_ca_bundle.clone(),
        None => settings::existing_ca_bundle_path(settings_path)?,
    };
    let root_pem = std::fs::read_to_string(&certificate.root_pem)
        .map_err(|error| format!("failed to read {}: {error}", certificate.root_pem.display()))?;
    settings::compose_linux_ca_bundle(&combined, &root_pem, existing.as_deref())?;
    Ok(combined)
}

#[allow(clippy::too_many_arguments)]
fn activate_desktop_generation(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    command: &InstallRequest,
    install_root: &Path,
    state_path: &Path,
    marketplace_dir: &Path,
    marketplace_preexisting: bool,
    settings_path: &Path,
    provider_backup_snapshot: &crate::filesystem::FileSnapshot,
    ca_path: &Path,
    journal: &mut state::InstallJournal,
    new_state: &mut state::DesktopState,
    progress: &mut InstallProgress,
) -> Result<(), String> {
    println!("{}", trust_configuration_notice());
    operations.install_trust(platform, &new_state.certificate)?;
    progress.trust_installed = true;
    journal.stage = "certificate_trusted".into();
    state::write_journal(install_root, journal)?;

    progress.service_registration_attempted = true;
    if journal.old_state.is_none() {
        let mut no_claude_settings = None;
        start_fresh_service_with_bind_retry(
            operations,
            platform,
            state_path,
            new_state,
            None,
            &mut no_claude_settings,
        )?;
    } else {
        operations.register_service(new_state)?;
        operations.start_service(new_state)?;
        operations.wait_for_health(new_state)?;
    }
    journal.stage = "proxy_healthy".into();
    state::write_journal(install_root, journal)?;

    // Marketplace hook generation discovers the active proxy through this locator. Publish it
    // only after authenticated health succeeds, and keep it under the install rollback journal so
    // a failed plugin or settings step restores the previous locator exactly.
    state::write_locator(state_path)?;
    progress.locator_written = true;
    operations.install_plugin(
        marketplace_dir,
        marketplace_preexisting,
        command.skip_doctor,
    )?;
    restore_shared_desktop_provider_backup(
        marketplace_preexisting,
        settings_path,
        provider_backup_snapshot,
    )?;
    progress.plugin_added = !marketplace_preexisting;
    journal.marketplace_result_snapshot = operations.marketplace_snapshot(marketplace_dir)?;
    journal.provider_backup_result_snapshot = Some(crate::filesystem::snapshot_optional_file(
        &crate::filesystem::backup_path(settings_path),
    )?);
    journal.stage = "plugin_ready".into();
    state::write_journal(install_root, journal)?;

    let mut final_settings = settings::prepare(
        settings_path,
        &new_state.proxy_url(),
        state_path,
        ca_path,
        platform.as_str(),
        new_state.upstream_proxy.as_ref(),
    )?;
    if final_settings.upstream_proxy != new_state.upstream_proxy {
        return Err(
            "Claude corporate proxy settings changed during installation; rolled back instead of committing an ambiguous route"
                .into(),
        );
    }
    settings::apply(&mut final_settings)?;
    snapshot_desktop_file_results(journal, settings_path)?;
    new_state.settings = final_settings.patch;
    state::write(new_state)?;
    journal.stage = "settings_applied".into();
    state::write_journal(install_root, journal)?;

    verify_and_commit_desktop_install(
        operations,
        command,
        install_root,
        state_path,
        marketplace_dir,
        journal,
        new_state,
    )
}

fn restore_shared_desktop_provider_backup(
    marketplace_preexisting: bool,
    settings_path: &Path,
    provider_backup_snapshot: &crate::filesystem::FileSnapshot,
) -> Result<(), String> {
    if !marketplace_preexisting {
        return Ok(());
    }
    let installed_backup =
        crate::filesystem::snapshot_optional_file(&crate::filesystem::backup_path(settings_path))?;
    crate::filesystem::restore_file_snapshot_cas(provider_backup_snapshot, Some(&installed_backup))
}

#[allow(clippy::too_many_arguments)]
fn verify_and_commit_desktop_install(
    operations: &dyn DesktopOperations,
    command: &InstallRequest,
    install_root: &Path,
    state_path: &Path,
    marketplace_dir: &Path,
    journal: &mut state::InstallJournal,
    new_state: &state::DesktopState,
) -> Result<(), String> {
    settings::matches(&new_state.settings)?;
    operations.wait_for_health(new_state)?;
    if !command.skip_doctor {
        journal.stage = "verifying".into();
        state::write_journal(install_root, journal)?;
        operations.post_install_doctor(marketplace_dir)?;
    }
    if new_state.enrollments.contains_key("hermes") {
        let enrollment = enrollment_from_state(new_state, "hermes")
            .ok_or_else(|| "Hermes proxy enrollment disappeared during rotation".to_string())?;
        crate::agents::refresh_hermes_proxy_environment(&enrollment)?;
    }
    state::write_locator(state_path)?;
    journal.stage = "committed".into();
    state::write_journal(install_root, journal)
}

struct DesktopOperationLock {
    _batch: Option<crate::installation::operation_lock::PluginOperationLock>,
    _desktop: crate::installation::operation_lock::PluginOperationLock,
}

fn desktop_operation_lock() -> Result<DesktopOperationLock, String> {
    let directory = proxy_operation_lock_directory()?;
    let batch_held = BATCH_OPERATION_DEPTH.with(|depth| depth.get() > 0);
    let batch = (!batch_held)
        .then(|| {
            crate::installation::operation_lock::PluginOperationLock::acquire(
                "agent-proxy-batch",
                &directory,
                &directory,
                crate::installation::operation_lock::DEFAULT_OPERATION_LOCK_TIMEOUT,
            )
        })
        .transpose()?;
    let desktop = crate::installation::operation_lock::PluginOperationLock::acquire(
        CLAUDE_ENROLLMENT,
        &directory,
        &directory,
        crate::installation::operation_lock::DEFAULT_OPERATION_LOCK_TIMEOUT,
    )?;
    Ok(DesktopOperationLock {
        _batch: batch,
        _desktop: desktop,
    })
}

fn proxy_operation_lock_directory() -> Result<PathBuf, String> {
    active_user_config_dir().map(|directory| directory.join("plugin-operations"))
}

fn ensure_claude_stopped(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    action: &str,
) -> Result<(), String> {
    let active = operations.active_claude_processes(platform)?;
    if active.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "close Claude Desktop and terminal Claude Code before {action}; still running: {}",
            active.join(", ")
        ))
    }
}

fn ensure_enrolled_agents_stopped(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    installed: &state::DesktopState,
    additional: Option<CodingAgent>,
    action: &str,
) -> Result<(), String> {
    let mut enrolled = installed.enrollments.keys().cloned().collect::<Vec<_>>();
    if let Some(agent) = additional
        && !enrolled.iter().any(|name| name == agent.install_arg())
    {
        enrolled.push(agent.install_arg().into());
    }
    let active = operations.active_agent_processes(platform, &enrolled)?;
    if active.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "close every enrolled coding agent before {action}; still running: {}",
            active.join(", ")
        ))
    }
}

fn recover_interrupted_operation(
    operations: &dyn DesktopOperations,
    install_root: &Path,
    state_path: &Path,
    current_platform: platform::Platform,
) -> Result<(), String> {
    let journal = state::read_journal(install_root)?;
    if let Some(old) = journal.old_state.as_ref()
        && platform::Platform::parse(&old.platform)? != current_platform
    {
        return Err("Claude Desktop journal belongs to a different operating system".into());
    }
    let current = state_path
        .exists()
        .then(|| state::read(state_path))
        .transpose()?;
    if journal.operation == "install" && journal.stage == "preparing" {
        if let Some(old) = journal.old_state.as_ref() {
            restore_protected_generation(operations, old, current_platform)?;
        } else {
            if let Some(current) = current.as_ref() {
                if current.generation != journal.generation {
                    return Err(format!(
                        "refusing to recover preparation generation {} over state generation {}",
                        journal.generation, current.generation
                    ));
                }
                state::remove_locator_if_matches(&current.state_path())?;
                state::remove_file_if_present(state_path)?;
            }
        }
        if let Some(current) = current.as_ref() {
            certificate::remove_signer(&current.certificate)?;
        } else {
            certificate::remove_signer_for_generation(&journal.generation)?;
        }
        remove_generation(install_root, &journal.generation)?;
        restore_desktop_journal_snapshots(&journal)?;
        state::remove_file_if_present(&state::journal_path(install_root))?;
        if journal.old_state.is_none() {
            remove_fresh_install_root(install_root)?;
        }
        println!(
            "recovered interrupted Claude Desktop install preparation for generation {}",
            journal.generation
        );
        return Ok(());
    }
    if is_committed_desktop_uninstall(&journal) {
        return finish_committed_desktop_uninstall(
            &journal,
            current.as_ref(),
            install_root,
            state_path,
        );
    }
    if journal.operation == "install" && journal.stage == "committed" {
        let active = current.as_ref().ok_or_else(|| {
            "committed Claude Desktop install has no active proxy state".to_string()
        })?;
        if active.generation != journal.generation || !active.claude_desktop_installed {
            return Err(
                "committed Claude Desktop install does not match the active enrollment state"
                    .into(),
            );
        }
        if active.enrollments.contains_key("hermes") {
            let enrollment = enrollment_from_state(active, "hermes").ok_or_else(|| {
                "Hermes proxy enrollment disappeared during committed rotation".to_string()
            })?;
            crate::agents::refresh_hermes_proxy_environment(&enrollment)?;
        }
        if let Some(old) = journal.old_state.as_ref() {
            finish_replaced_proxy_generation(operations, current_platform, old, active)?;
        }
        state::write_locator(state_path)?;
        state::remove_file_if_present(&state::journal_path(install_root))?;
        println!(
            "finished committed Claude Desktop install for generation {}",
            journal.generation
        );
        return Ok(());
    }
    if let Some(current) = current.as_ref()
        && current.generation != journal.generation
        && journal.operation == "install"
    {
        return Err(format!(
            "refusing to recover journal generation {} over active generation {}",
            journal.generation, current.generation
        ));
    }

    match journal.operation.as_str() {
        "install" => {
            if let Some(new_state) = current.as_ref() {
                operations.shutdown_proxy(new_state);
                operations.unregister_service(new_state)?;
                if !new_state.settings.fields.is_empty() {
                    settings::restore(&new_state.settings)?;
                }
                operations.remove_trust(current_platform, &new_state.certificate)?;
                if !new_state.claude_code_installed {
                    uninstall_plugin_if_present(operations, install_root)?;
                }
                state::remove_locator_if_matches(&new_state.state_path())?;
                state::remove_file_if_present(&new_state.state_path())?;
            }
            if let Some(new_state) = current.as_ref() {
                certificate::remove_signer(&new_state.certificate)?;
            } else {
                certificate::remove_signer_for_generation(&journal.generation)?;
            }
            remove_generation(install_root, &journal.generation)?;
            if let Some(old) = journal.old_state.as_ref() {
                restore_protected_generation(operations, old, current_platform)?;
            }
        }
        "uninstall" => {
            let old = journal.old_state.as_ref().ok_or_else(|| {
                "interrupted Claude Desktop uninstall journal has no prior generation".to_string()
            })?;
            restore_protected_generation(operations, old, current_platform)?;
        }
        operation => {
            return Err(format!(
                "unsupported Claude Desktop journal operation {operation}"
            ));
        }
    }
    restore_desktop_journal_snapshots(&journal)?;
    state::remove_file_if_present(&state::journal_path(install_root))?;
    if journal.operation == "install" && journal.old_state.is_none() && current.is_some() {
        remove_fresh_install_root(install_root)?;
    }
    println!(
        "recovered interrupted Claude Desktop {} operation for generation {}",
        journal.operation, journal.generation
    );
    Ok(())
}

fn restore_desktop_journal_snapshots(journal: &state::InstallJournal) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Some(snapshot) = journal.marketplace_snapshot.as_ref()
        && let Err(error) = crate::installation::marketplace::restore_marketplace_snapshot_cas(
            snapshot,
            journal.marketplace_result_snapshot.as_ref(),
        )
    {
        errors.push(error);
    }
    for (snapshot, expected) in [
        (
            journal.settings_snapshot.as_ref(),
            journal.settings_result_snapshot.as_ref(),
        ),
        (
            journal.provider_backup_snapshot.as_ref(),
            journal.provider_backup_result_snapshot.as_ref(),
        ),
    ] {
        if let Some(snapshot) = snapshot
            && let Err(error) = crate::filesystem::restore_file_snapshot_cas(snapshot, expected)
        {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn snapshot_desktop_file_results(
    journal: &mut state::InstallJournal,
    settings_path: &Path,
) -> Result<(), String> {
    journal.settings_result_snapshot =
        Some(crate::filesystem::snapshot_optional_file(settings_path)?);
    journal.provider_backup_result_snapshot = Some(crate::filesystem::snapshot_optional_file(
        &crate::filesystem::backup_path(settings_path),
    )?);
    Ok(())
}

fn is_committed_desktop_uninstall(journal: &state::InstallJournal) -> bool {
    journal.operation == "uninstall"
        && matches!(
            journal.stage.as_str(),
            "committed" | "committed_final" | "committed_retained"
        )
}

fn finish_committed_desktop_uninstall(
    journal: &state::InstallJournal,
    current: Option<&state::DesktopState>,
    install_root: &Path,
    state_path: &Path,
) -> Result<(), String> {
    let old = journal.old_state.as_ref().ok_or_else(|| {
        "committed Claude Desktop uninstall journal has no prior generation".to_string()
    })?;
    if old.install_root != install_root
        || install_root.file_name().and_then(|name| name.to_str()) != Some("agent-proxy")
    {
        return Err(format!(
            "refusing to finish uninstall from unexpected root {}",
            install_root.display()
        ));
    }
    if retained_desktop_proxy(journal, old) {
        return finish_retained_desktop_proxy_uninstall(journal, current, install_root, state_path);
    }
    let retirement_deferred = defer_proxy_retirement(old)?;
    state::remove_locator_if_matches(&old.state_path())?;
    if !retirement_deferred {
        certificate::remove_signer(&old.certificate)?;
        remove_generation(&old.install_root, &old.generation)?;
    }
    state::remove_file_if_present(&old.state_path())?;
    state::remove_file_if_present(&state::journal_path(install_root))?;
    if !retirement_deferred {
        remove_fresh_install_root(install_root)?;
    }
    println!(
        "finished interrupted Claude Desktop uninstall for generation {}",
        journal.generation
    );
    Ok(())
}

fn retained_desktop_proxy(journal: &state::InstallJournal, old: &state::DesktopState) -> bool {
    journal.stage == "committed_retained"
        || (journal.stage == "committed" && old.enrollments.len() > 1)
}

fn finish_retained_desktop_proxy_uninstall(
    journal: &state::InstallJournal,
    current: Option<&state::DesktopState>,
    install_root: &Path,
    state_path: &Path,
) -> Result<(), String> {
    let active = current
        .ok_or_else(|| "retained-proxy uninstall commit has no active proxy state".to_string())?;
    if active.generation != journal.generation
        || active.enrollments.is_empty()
        || active.claude_desktop_installed
    {
        return Err(
            "retained-proxy uninstall commit does not match the active enrollment state".into(),
        );
    }
    state::write_locator(state_path)?;
    state::remove_file_if_present(&state::journal_path(install_root))?;
    println!(
        "finished interrupted Claude Desktop uninstall while retaining proxy generation {}",
        journal.generation
    );
    Ok(())
}

fn restore_protected_generation(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    current_platform: platform::Platform,
) -> Result<(), String> {
    ensure_plugin_installed(operations, &installed.install_root)?;
    state::write(installed)?;
    sync_codex_ca_bundle(installed)?;
    settings::apply_installed(&installed.settings)?;
    operations.install_trust(current_platform, &installed.certificate)?;
    activate_service(operations, installed)?;
    state::write_locator(&installed.state_path())?;
    refresh_retained_hermes(installed)
}

fn activate_service(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
) -> Result<(), String> {
    operations.register_service(installed)?;
    operations.start_service(installed)?;
    operations.wait_for_health(installed)
}

fn ensure_plugin_installed(
    operations: &dyn DesktopOperations,
    install_root: &Path,
) -> Result<(), String> {
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    let exists = operations.plugin_exists(&marketplace_dir);
    operations.install_plugin(&marketplace_dir, exists, true)
}

fn uninstall_plugin_if_present(
    operations: &dyn DesktopOperations,
    install_root: &Path,
) -> Result<(), String> {
    let marketplace_dir = install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    if !operations.plugin_exists(&marketplace_dir) {
        return Ok(());
    }
    operations.uninstall_plugin(&marketplace_dir)
}

fn rollback_install(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    snapshots: &DesktopRollbackSnapshots<'_>,
    progress: &InstallProgress,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    let current_platform = platform::Platform::parse(&new_state.platform)?;
    let service_unregistered = undo_new_install_effects(
        operations,
        new_state,
        snapshots,
        progress,
        current_platform,
        &mut errors,
    );
    if let Some(snapshot) = snapshots.marketplace {
        errors.record(
            crate::installation::marketplace::restore_marketplace_snapshot_cas(
                snapshot,
                snapshots.marketplace_result,
            ),
        );
    }
    if errors.is_empty() {
        restore_install_predecessor(
            operations,
            new_state,
            old_state,
            current_platform,
            &mut errors,
        );
    }
    if errors.is_empty() {
        cleanup_failed_install(
            new_state,
            old_state,
            progress,
            service_unregistered,
            &mut errors,
        );
    }
    errors.finish()
}

fn undo_new_install_effects(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    snapshots: &DesktopRollbackSnapshots<'_>,
    progress: &InstallProgress,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) -> bool {
    operations.shutdown_proxy(new_state);
    let service_unregistered = if progress.service_registration_attempted {
        let result = operations.unregister_service(new_state);
        let succeeded = result.is_ok();
        errors.record(result);
        succeeded
    } else {
        true
    };
    if progress.plugin_added
        && snapshots.marketplace.is_none()
        && let Some(marketplace_dir) = snapshots.marketplace_dir
    {
        errors.record(operations.uninstall_plugin(marketplace_dir));
    }
    errors.record(crate::filesystem::restore_file_snapshot_cas(
        snapshots.settings,
        snapshots.settings_result,
    ));
    errors.record(crate::filesystem::restore_file_snapshot_cas(
        snapshots.provider_backup,
        snapshots.provider_backup_result,
    ));
    if progress.trust_installed {
        errors.record(operations.remove_trust(current_platform, &new_state.certificate));
    }
    service_unregistered
}

fn restore_install_predecessor(
    operations: &dyn DesktopOperations,
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) {
    if let Some(old) = old_state {
        restore_generation_best_effort(operations, old, current_platform, errors);
        return;
    }
    errors.record(state::remove_file_if_present(&new_state.state_path()));
}

fn restore_generation_best_effort(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    current_platform: platform::Platform,
    errors: &mut RollbackErrors,
) {
    errors.record(ensure_plugin_installed(operations, &installed.install_root));
    errors.record(state::write(installed));
    errors.record(sync_codex_ca_bundle(installed));
    errors.record(settings::apply_installed(&installed.settings));
    errors.record(operations.install_trust(current_platform, &installed.certificate));
    errors.record(activate_service(operations, installed));
    errors.record(state::write_locator(&installed.state_path()));
    errors.record(refresh_retained_hermes(installed));
}

fn refresh_retained_hermes(installed: &state::DesktopState) -> Result<(), String> {
    if !installed.enrollments.contains_key("hermes") {
        return Ok(());
    }
    let enrollment = enrollment_from_state(installed, "hermes")
        .ok_or_else(|| "Hermes proxy enrollment disappeared during restoration".to_string())?;
    crate::agents::refresh_hermes_proxy_environment(&enrollment)
}

fn cleanup_failed_install(
    new_state: &state::DesktopState,
    old_state: Option<&state::DesktopState>,
    progress: &InstallProgress,
    service_unregistered: bool,
    errors: &mut RollbackErrors,
) {
    if old_state.is_none() && progress.locator_written {
        let _ = state::remove_locator_if_matches(&new_state.state_path());
    }
    errors.record(remove_signer_then_generation(
        &new_state.certificate,
        &new_state.install_root,
        &new_state.generation,
    ));
    if errors.is_empty() {
        errors.record(state::remove_file_if_present(&state::journal_path(
            &new_state.install_root,
        )));
        if old_state.is_none() && service_unregistered {
            errors.record(remove_fresh_install_root(&new_state.install_root));
        }
    }
}

pub(crate) fn uninstall(command: UninstallRequest) -> Result<ExitCode, CliError> {
    uninstall_inner(command).map_err(CliError::Install)?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn is_enrolled(install_dir: Option<&Path>) -> Result<bool, String> {
    let path = state::resolve_state_path(install_dir)?;
    if !path.exists() {
        return Ok(false);
    }
    Ok(state::read(&path)?.claude_desktop_installed)
}

fn uninstall_inner(command: UninstallRequest) -> Result<(), String> {
    uninstall_with(&SystemOperations, command)
}

fn uninstall_with(
    operations: &dyn DesktopOperations,
    command: UninstallRequest,
) -> Result<(), String> {
    ensure_selected_enrollment_root(
        command.install_dir.as_deref(),
        &[CLAUDE_ENROLLMENT],
        "uninstall",
    )?;
    let path = state::resolve_state_path(command.install_dir.as_deref())?;
    let mut installed = state::read(&path)?;
    if !installed.claude_desktop_installed {
        return Err("Claude Desktop is not enrolled in the per-user coding-agent proxy".into());
    }
    let platform = platform::Platform::parse(&installed.platform)?;
    if command.dry_run {
        platform::unregister_service(&installed, true)?;
        platform::remove_trust(platform, &installed.certificate, true)?;
        println!(
            "restore Relay-managed fields in {}",
            installed.settings.settings_path.display()
        );
        println!("remove {}", installed.install_root.display());
        return Ok(());
    }
    if installed
        .install_root
        .file_name()
        .and_then(|name| name.to_str())
        != Some("agent-proxy")
    {
        return Err(format!(
            "refusing to remove unexpected install root {}",
            installed.install_root.display()
        ));
    }
    let _operation_lock = desktop_operation_lock()?;
    ensure_claude_stopped(operations, platform, "uninstalling")?;
    if state::journal_path(&installed.install_root).exists() {
        recover_interrupted_operation(operations, &installed.install_root, &path, platform)?;
        if !path.exists() {
            println!(
                "finished the interrupted Claude Desktop uninstall from {}",
                installed.install_root.display()
            );
            return Ok(());
        }
        installed = state::read(&path)?;
    }
    let settings_snapshot =
        crate::filesystem::snapshot_optional_file(&installed.settings.settings_path)?;
    let provider_backup_snapshot = crate::filesystem::snapshot_optional_file(
        &crate::filesystem::backup_path(&installed.settings.settings_path),
    )?;
    let marketplace_dir = installed
        .install_root
        .parent()
        .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?
        .to_path_buf();
    let marketplace_snapshot = operations.marketplace_snapshot(&marketplace_dir)?;
    let mut journal = state::InstallJournal {
        schema_version: state::STATE_SCHEMA_VERSION,
        operation: "uninstall".into(),
        stage: "started".into(),
        generation: installed.generation.clone(),
        old_state: Some(installed.clone()),
        settings_snapshot: Some(settings_snapshot.clone()),
        provider_backup_snapshot: Some(provider_backup_snapshot.clone()),
        marketplace_snapshot,
        settings_result_snapshot: None,
        provider_backup_result_snapshot: None,
        marketplace_result_snapshot: None,
    };
    state::write_journal(&installed.install_root, &journal)?;
    let final_enrollment = !installed.claude_code_installed && installed.enrollments.len() == 1;
    let retain_claude_plugin = installed.claude_code_installed;

    let result = (|| {
        operations.shutdown_proxy(&installed);
        if final_enrollment {
            operations.unregister_service(&installed)?;
        } else {
            operations.stop_service(&installed)?;
        }
        if !retain_claude_plugin {
            let retained = settings::restore(&installed.settings)?;
            if !retained.is_empty() {
                println!(
                    "retained concurrent Claude settings edits for {}",
                    retained.join(", ")
                );
            }
            snapshot_desktop_file_results(&mut journal, &installed.settings.settings_path)?;
            state::write_journal(&installed.install_root, &journal)?;
        }
        if final_enrollment {
            operations.remove_trust(platform, &installed.certificate)?;
        }
        if !retain_claude_plugin {
            let marketplace_dir = installed
                .install_root
                .parent()
                .ok_or_else(|| "Claude Desktop install root has no parent".to_string())?;
            operations.uninstall_plugin(marketplace_dir)?;
            journal.marketplace_result_snapshot =
                operations.marketplace_snapshot(marketplace_dir)?;
            snapshot_desktop_file_results(&mut journal, &installed.settings.settings_path)?;
            state::write_journal(&installed.install_root, &journal)?;
        }
        if final_enrollment {
            state::remove_locator_if_matches(&installed.state_path())?;
        } else {
            installed.claude_desktop_installed = false;
            if retain_claude_plugin {
                snapshot_desktop_file_results(&mut journal, &installed.settings.settings_path)?;
                state::write_journal(&installed.install_root, &journal)?;
            } else {
                installed.enrollments.remove(CLAUDE_ENROLLMENT);
                installed.settings = Default::default();
            }
            installed.upstream_proxy = installed
                .enrollments
                .values()
                .find_map(|enrollment| enrollment.upstream_proxy.clone());
            installed.configuration_fingerprint = configuration_fingerprint(
                &installed.generation,
                &installed.relay_binary,
                &installed.user_config_dir,
                &installed.gateway_fingerprint,
                &installed.certificate.root_sha256,
                installed.bind,
                installed.service_identity.as_deref(),
                installed.upstream_proxy.as_ref(),
                &installed.enrollments,
            )?;
            state::write(&installed)?;
            sync_codex_ca_bundle(&installed)?;
            operations.register_service(&installed)?;
            operations.start_service(&installed)?;
            operations.wait_for_health(&installed)?;
        }
        journal.marketplace_result_snapshot = operations.marketplace_snapshot(&marketplace_dir)?;
        snapshot_desktop_file_results(&mut journal, &installed.settings.settings_path)?;
        journal.stage = if final_enrollment {
            "committed_final"
        } else {
            "committed_retained"
        }
        .into();
        state::write_journal(&installed.install_root, &journal)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let snapshots = DesktopRollbackSnapshots {
            settings: &settings_snapshot,
            provider_backup: &provider_backup_snapshot,
            settings_result: journal.settings_result_snapshot.as_ref(),
            provider_backup_result: journal.provider_backup_result_snapshot.as_ref(),
            marketplace: journal.marketplace_snapshot.as_ref(),
            marketplace_result: journal.marketplace_result_snapshot.as_ref(),
            marketplace_dir: None,
        };
        let rollback = rollback_uninstall(operations, &installed, platform, &snapshots);
        return Err(if rollback.is_ok() {
            format!("{error}; restored Claude Desktop protection")
        } else {
            format!(
                "{error}; rollback also failed: {}",
                rollback.expect_err("rollback error was checked")
            )
        });
    }
    let root = installed.install_root.clone();
    if !final_enrollment {
        state::remove_file_if_present(&state::journal_path(&root))?;
        println!(
            "uninstalled Claude Desktop protection; retained the shared coding-agent proxy at {}",
            root.display()
        );
        return Ok(());
    }
    let retirement_deferred = defer_proxy_retirement(&installed)?;
    if !retirement_deferred {
        certificate::remove_signer(&installed.certificate)?;
        remove_generation(&installed.install_root, &installed.generation)?;
    }
    state::remove_file_if_present(&installed.state_path())?;
    state::remove_file_if_present(&state::journal_path(&root))?;
    if !retirement_deferred {
        remove_fresh_install_root(&root)?;
    }
    println!(
        "uninstalled Claude Desktop protection from {}",
        root.display()
    );
    Ok(())
}

fn finish_replaced_proxy_generation(
    operations: &dyn DesktopOperations,
    platform: platform::Platform,
    previous: &state::DesktopState,
    active: &state::DesktopState,
) -> Result<(), String> {
    if previous.generation == active.generation || defer_proxy_retirement(previous)? {
        return Ok(());
    }
    operations.remove_trust(platform, &previous.certificate)?;
    retire_generation(previous)
}

fn rollback_uninstall(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    platform: platform::Platform,
    snapshots: &DesktopRollbackSnapshots<'_>,
) -> Result<(), String> {
    let mut errors = RollbackErrors::default();
    errors.record(crate::filesystem::restore_file_snapshot_cas(
        snapshots.settings,
        snapshots.settings_result,
    ));
    errors.record(crate::filesystem::restore_file_snapshot_cas(
        snapshots.provider_backup,
        snapshots.provider_backup_result,
    ));
    if let Some(snapshot) = snapshots.marketplace {
        errors.record(
            crate::installation::marketplace::restore_marketplace_snapshot_cas(
                snapshot,
                snapshots.marketplace_result,
            ),
        );
    }
    if errors.is_empty() {
        restore_generation_best_effort(operations, installed, platform, &mut errors);
    }
    if errors.is_empty() {
        errors.record(state::remove_file_if_present(&state::journal_path(
            &installed.install_root,
        )));
    }
    errors.finish()
}

pub(crate) async fn launch(command: LaunchRequest) -> Result<ExitCode, CliError> {
    launch_with(&SystemOperations, command).await
}

async fn launch_with(
    operations: &dyn DesktopOperations,
    command: LaunchRequest,
) -> Result<ExitCode, CliError> {
    let state_path = state::resolve_state_path(None).map_err(CliError::Install)?;
    let installed = state::read(&state_path).map_err(CliError::Install)?;
    let mut report = doctor_report_with(operations, installed.install_root.parent())
        .map_err(CliError::Install)?;
    if !report.ok && report_allows_proxy_start(&report) {
        operations
            .start_service(&installed)
            .map_err(CliError::Launch)?;
        operations
            .wait_for_health(&installed)
            .map_err(CliError::Launch)?;
        report = doctor_report_with(operations, installed.install_root.parent())
            .map_err(CliError::Install)?;
    }
    if !report.ok {
        render_doctor(&report);
        return Err(CliError::Launch(
            "Claude Desktop protection is unhealthy; Claude was not launched. Run `nemo-relay doctor claude-desktop`."
                .into(),
        ));
    }
    let folder = command
        .folder
        .unwrap_or(std::env::current_dir().map_err(CliError::Io)?)
        .canonicalize()
        .map_err(|error| CliError::Launch(format!("failed to resolve Claude folder: {error}")))?;
    if !folder.is_dir() {
        return Err(CliError::Launch(format!(
            "Claude Desktop folder is not a directory: {}",
            folder.display()
        )));
    }
    let url = deep_link(&folder)?;
    operations
        .open_deep_link(
            platform::Platform::parse(&installed.platform).map_err(CliError::Launch)?,
            &url,
        )
        .map_err(CliError::Launch)?;
    Ok(ExitCode::SUCCESS)
}

fn report_allows_proxy_start(report: &DoctorReport) -> bool {
    report
        .checks
        .iter()
        .all(|check| check.ok || check.name == "proxy_identity")
}

pub(crate) fn doctor(
    install_dir: Option<PathBuf>,
    json_output: bool,
) -> Result<ExitCode, CliError> {
    doctor_with(&SystemOperations, install_dir.as_deref(), json_output)
}

pub(crate) fn doctor_report_json(install_dir: Option<&Path>) -> Result<Value, CliError> {
    let report = doctor_report_with(&SystemOperations, install_dir).map_err(CliError::Install)?;
    serde_json::to_value(report).map_err(|error| CliError::Install(error.to_string()))
}

fn doctor_with(
    operations: &dyn DesktopOperations,
    install_dir: Option<&Path>,
    json_output: bool,
) -> Result<ExitCode, CliError> {
    let report = doctor_report_with(operations, install_dir).map_err(CliError::Install)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| CliError::Install(error.to_string()))?
        );
    } else {
        render_doctor(&report);
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn doctor_report_with(
    operations: &dyn DesktopOperations,
    install_dir: Option<&Path>,
) -> Result<DoctorReport, String> {
    doctor_report_with_verifying_install(operations, install_dir, false)
}

fn doctor_report_with_verifying_install(
    operations: &dyn DesktopOperations,
    install_dir: Option<&Path>,
    allow_verifying_install: bool,
) -> Result<DoctorReport, String> {
    ensure_selected_enrollment_root(install_dir, &[CLAUDE_ENROLLMENT], "doctor")?;
    let state_path = state::resolve_state_path(install_dir)?;
    let installed = state::read(&state_path)?;
    let platform = platform::Platform::parse(&installed.platform)?;
    let mut report = DoctorReport {
        schema_version: 1,
        integration: "claude-desktop",
        platform: installed.platform.clone(),
        state_path: state_path.clone(),
        ok: false,
        effective_protection: false,
        checks: Vec::new(),
    };
    report.push(
        "transaction_journal",
        transaction_journal_status(&installed, allow_verifying_install),
    );
    report.push(
        "shared_transaction_journals",
        shared_transaction_journal_status(),
    );
    report.push(
        "application_identity",
        operations.application_identity(platform),
    );
    report.push(
        "platform_support",
        operations.validate_supported_platform(platform),
    );
    report.push(
        "service_registration",
        operations.service_status(&installed),
    );
    report.push(
        "certificate_files",
        certificate::validate_installed_identity(&installed.install_root, &installed.certificate)
            .map(|_| "root CA and protected signer form the installed identity".into()),
    );
    report.push(
        "certificate_expiry",
        certificate::expiry_days(&installed.certificate).and_then(|days| {
            if days <= 0 {
                Err("interception certificate is expired; reinstall with --force".into())
            } else if days <= certificate::EXPIRY_WARNING_DAYS {
                Ok(format!(
                    "certificate expires in {days} days; rotate with `nemo-relay install claude-desktop --force`"
                ))
            } else {
                Ok(format!("certificate expires in {days} days"))
            }
        }),
    );
    report.push(
        "leaf_certificate_cache",
        certificate::leaf_cache_summary(&installed.certificate),
    );
    report.push(
        "certificate_trust",
        operations.trust_status(
            platform,
            &installed.certificate,
            linux_ca_bundle(&installed),
        ),
    );
    report.push(
        "file_permissions",
        private_state_files(&installed)
            .map(|_| "state, CA material, and generated leaf keys are owner-only".into()),
    );
    report.push(
        "claude_settings",
        settings::matches(&installed.settings).map(|_| {
            "authenticated proxy, fail-closed mode, CA, and base-URL policy are effective".into()
        }),
    );
    report.push(
        "upstream_proxy",
        installed.upstream_proxy.as_ref().map_or_else(
            || Ok("direct public upstream".into()),
            |proxy| {
                settings::validate_upstream_proxy(&proxy.url, proxy.no_proxy.clone())?;
                proxy::upstream_client(Some(proxy))?;
                Ok(format!("chained through {}", proxy.redacted_url()))
            },
        ),
    );
    for check in operations.plugin_checks(install_dir)? {
        report.checks.push(check);
    }
    report.push(
        "proxy_identity",
        operations.health(&installed).map(|health| {
            format!(
                "generation {} on gateway {} and proxy {}",
                health.generation, health.gateway_url, health.proxy_url
            )
        }),
    );
    report.push(
        "gateway_configuration",
        current_configuration_fingerprint_with(operations, &installed).and_then(|actual| {
            if actual == installed.configuration_fingerprint {
                Ok("persistent proxy configuration fingerprint matches".into())
            } else {
                Err("persistent Relay configuration changed; reinstall with --force".into())
            }
        }),
    );
    Ok(report.finish())
}

fn transaction_journal_status(
    installed: &state::DesktopState,
    allow_verifying_install: bool,
) -> Result<String, String> {
    let journal_path = state::journal_path(&installed.install_root);
    if !journal_path.exists() {
        return Ok("no interrupted install or uninstall operation".into());
    }
    if allow_verifying_install {
        let journal = state::read_journal(&installed.install_root)?;
        if journal.operation == "install"
            && journal.stage == "verifying"
            && journal.generation == installed.generation
        {
            return Ok("current installation generation is being verified".into());
        }
    }
    Err(
        "an interrupted operation requires `nemo-relay install claude-desktop --force` recovery"
            .into(),
    )
}

fn shared_transaction_journal_status() -> Result<String, String> {
    let directory = active_user_config_dir()?;
    let interrupted = [
        AGENT_TRANSACTION_FILE_NAME,
        "agent-proxy-batch-transaction.json",
    ]
    .into_iter()
    .map(|name| directory.join(name))
    .find(|path| path.exists());
    match interrupted {
        Some(path) => Err(format!(
            "interrupted coding-agent proxy transaction exists at {}; rerun the intended install or uninstall command to recover it before using enrolled agents",
            path.display()
        )),
        None => Ok("no interrupted shared agent or batch transaction".into()),
    }
}

pub(crate) fn active_user_config_dir() -> Result<PathBuf, String> {
    state::active_user_config_dir()
}

fn plugin_checks(install_dir: Option<&Path>, relay: &Path) -> Result<Vec<DoctorCheck>, String> {
    let options =
        crate::installation::marketplace::plugin_doctor_options(install_dir.map(Path::to_path_buf));
    let readiness = crate::installation::marketplace::collect_marketplace_readiness_with_relay(
        CodingAgent::ClaudeCode,
        &options,
        relay,
    );
    Ok(readiness
        .checks
        .into_iter()
        .filter(|check| check.name != "claude provider routing")
        .map(|check| DoctorCheck {
            name: format!(
                "plugin_{}",
                check.name.to_ascii_lowercase().replace(' ', "_")
            ),
            ok: check.ok,
            details: check.details,
        })
        .collect())
}

fn render_doctor(report: &DoctorReport) {
    println!("Claude Desktop protection");
    for check in &report.checks {
        println!(
            "{} {:<28} {}",
            if check.ok { "ok" } else { "failed" },
            check.name,
            check.details
        );
    }
    println!(
        "{} effective protection",
        if report.effective_protection {
            "ok"
        } else {
            "failed"
        }
    );
}

pub(crate) async fn run_proxy_service(command: ProxyServiceRequest) -> Result<ExitCode, CliError> {
    let installed = state::read(&command.state).map_err(CliError::Launch)?;
    if installed.state_path() != command.state {
        return Err(CliError::Launch(
            "coding-agent proxy state path does not match its install root".into(),
        ));
    }
    certificate::validate_installed_identity(&installed.install_root, &installed.certificate)
        .map_err(CliError::Launch)?;
    let relay_identity =
        RelayBinaryIdentity::capture(&installed.relay_binary).map_err(CliError::Launch)?;
    verify_live_proxy_configuration(&SystemOperations, &installed, &relay_identity)
        .map_err(CliError::Launch)?;
    let tls = certificate::server_config(&installed.install_root, &installed.certificate)
        .map_err(CliError::Launch)?;
    let resolved = crate::configuration::resolve_persistent_server_config_at(
        &Default::default(),
        &installed.user_config_dir,
    )?;
    let fingerprint = resolved
        .bootstrap_fingerprint
        .clone()
        .ok_or_else(|| CliError::Launch("persistent proxy fingerprint is missing".into()))?;
    if fingerprint != installed.gateway_fingerprint {
        return Err(CliError::Launch(
            "persistent proxy identity changed; reinstall Claude Desktop protection with --force"
                .into(),
        ));
    }
    let dynamic = crate::plugins::lifecycle::active_persistent_dynamic_plugin_components(
        &resolved,
        &installed.user_config_dir,
    )?;
    let proxy_listener = TcpListener::bind(installed.bind).await.map_err(|error| {
        CliError::Launch(format!(
            "refusing to adopt listener at {}; coding-agent proxy bind failed: {error}",
            installed.bind
        ))
    })?;
    let upstream = proxy::upstream_client(None).map_err(CliError::Launch)?;
    let engine =
        crate::server::ManagedProviderEngine::initialize(resolved.gateway, dynamic, upstream)
            .await?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let verifier_state = installed.clone();
    let runtime = proxy::Runtime::new_with_dispatcher(
        installed.clone(),
        tls,
        engine.dispatcher(),
        shutdown_tx.clone(),
    )
    .map_err(CliError::Launch)?
    .with_configuration_verifier(move || {
        verify_live_proxy_configuration(&SystemOperations, &verifier_state, &relay_identity)
    });
    let mut proxy_task = tokio::spawn(proxy::serve(proxy_listener, runtime));

    let outcome = tokio::select! {
        biased;
        signal = platform_shutdown_signal() => signal,
        changed = shutdown_rx.changed() => changed.map_err(|_| "proxy control channel closed".to_string()),
        result = &mut proxy_task => Err(task_failure("proxy", result)),
    };
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        if !proxy_task.is_finished() {
            let _ = (&mut proxy_task).await;
        }
    })
    .await;
    engine.shutdown().await?;
    outcome.map_err(CliError::Launch)?;
    Ok(ExitCode::SUCCESS)
}

fn verify_live_proxy_configuration(
    operations: &dyn DesktopOperations,
    expected: &state::DesktopState,
    relay_identity: &RelayBinaryIdentity,
) -> Result<(), String> {
    relay_identity.verify(&expected.relay_binary)?;
    let current = state::read(&expected.state_path())?;
    private_state_files(&current)?;
    if current.generation != expected.generation
        || current.configuration_fingerprint != expected.configuration_fingerprint
    {
        return Err("persistent coding-agent proxy state changed after startup".into());
    }
    let actual = current_configuration_fingerprint_with_relay_sha256(
        operations,
        &current,
        &relay_identity.sha256,
    )?;
    if actual == current.configuration_fingerprint {
        Ok(())
    } else {
        Err("coding-agent proxy configuration fingerprint is stale; reinstall with --force".into())
    }
}

fn task_failure<T: std::fmt::Display>(
    name: &str,
    result: Result<Result<(), T>, tokio::task::JoinError>,
) -> String {
    match result {
        Ok(Ok(())) => format!("Claude Desktop {name} stopped unexpectedly"),
        Ok(Err(error)) => format!("Claude Desktop {name} failed: {error}"),
        Err(error) => format!("Claude Desktop {name} task failed: {error}"),
    }
}

async fn platform_shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| format!("failed to register SIGTERM handler: {error}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|error| format!("failed to wait for Ctrl-C: {error}")),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("failed to wait for service shutdown: {error}"))
    }
}

fn persistent_gateway_identity() -> Result<(String, String, usize), String> {
    let resolved = crate::configuration::resolve_persistent_server_config(&Default::default())
        .map_err(|error| error.to_string())?;
    persistent_gateway_identity_from(resolved)
}

fn persistent_gateway_identity_at(
    user_config_dir: &Path,
) -> Result<(String, String, usize), String> {
    let resolved = crate::configuration::resolve_persistent_server_config_at(
        &Default::default(),
        user_config_dir,
    )
    .map_err(|error| error.to_string())?;
    persistent_gateway_identity_from(resolved)
}

fn persistent_gateway_identity_from(
    resolved: crate::configuration::ResolvedConfig,
) -> Result<(String, String, usize), String> {
    Ok((
        resolved
            .bootstrap_fingerprint
            .ok_or_else(|| "persistent proxy fingerprint is missing".to_string())?,
        resolved.gateway.anthropic_base_url,
        resolved.gateway.max_hook_payload_bytes,
    ))
}

fn current_configuration_fingerprint(installed: &state::DesktopState) -> Result<String, String> {
    current_configuration_fingerprint_with(&SystemOperations, installed)
}

fn current_configuration_fingerprint_with(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
) -> Result<String, String> {
    let relay_sha256 = relay_binary_sha256(&installed.relay_binary)?;
    current_configuration_fingerprint_with_relay_sha256(operations, installed, &relay_sha256)
}

fn current_configuration_fingerprint_with_relay_sha256(
    operations: &dyn DesktopOperations,
    installed: &state::DesktopState,
    relay_sha256: &str,
) -> Result<String, String> {
    let (gateway, anthropic, max_hook_payload_bytes) =
        operations.persistent_gateway_identity_at(&installed.user_config_dir)?;
    if anthropic.trim_end_matches('/') != "https://api.anthropic.com" {
        return Err("persistent Anthropic upstream is no longer api.anthropic.com".into());
    }
    if max_hook_payload_bytes != installed.max_hook_payload_bytes {
        return Err("persistent Relay hook payload limit changed".into());
    }
    configuration_fingerprint_from_relay_sha256(
        &installed.generation,
        &installed.relay_binary,
        &installed.user_config_dir,
        relay_sha256,
        &gateway,
        &installed.certificate.root_sha256,
        installed.bind,
        installed.service_identity.as_deref(),
        installed.upstream_proxy.as_ref(),
        &installed.enrollments,
    )
}

#[allow(clippy::too_many_arguments)]
fn configuration_fingerprint(
    generation: &str,
    relay_binary: &Path,
    user_config_dir: &Path,
    gateway_fingerprint: &str,
    root_sha256: &str,
    bind: SocketAddr,
    service_identity: Option<&str>,
    upstream_proxy: Option<&settings::UpstreamProxy>,
    enrollments: &std::collections::BTreeMap<String, state::AgentEnrollment>,
) -> Result<String, String> {
    let relay_sha256 = relay_binary_sha256(relay_binary)?;
    configuration_fingerprint_from_relay_sha256(
        generation,
        relay_binary,
        user_config_dir,
        &relay_sha256,
        gateway_fingerprint,
        root_sha256,
        bind,
        service_identity,
        upstream_proxy,
        enrollments,
    )
}

#[allow(clippy::too_many_arguments)]
fn configuration_fingerprint_from_relay_sha256(
    generation: &str,
    relay_binary: &Path,
    user_config_dir: &Path,
    relay_sha256: &str,
    gateway_fingerprint: &str,
    root_sha256: &str,
    bind: SocketAddr,
    service_identity: Option<&str>,
    upstream_proxy: Option<&settings::UpstreamProxy>,
    enrollments: &std::collections::BTreeMap<String, state::AgentEnrollment>,
) -> Result<String, String> {
    let upstream_ca_sha256 =
        corporate_ca_sha256(upstream_proxy, "global corporate proxy CA bundle")?;
    let fingerprinted_enrollments = enrollments
        .iter()
        .map(|(agent, enrollment)| {
            let description = format!("{agent} corporate proxy CA bundle");
            let ca_sha256 = corporate_ca_sha256(enrollment.upstream_proxy.as_ref(), &description)?;
            Ok((
                agent.clone(),
                json!({
                    "enrollment": enrollment,
                    "upstream_ca_sha256": ca_sha256,
                }),
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;
    let document = json!({
        "schema": state::STATE_SCHEMA_VERSION,
        "generation": generation,
        "relay_version": env!("CARGO_PKG_VERSION"),
        "relay_binary": relay_binary,
        "user_config_dir": user_config_dir,
        "relay_binary_sha256": relay_sha256,
        "gateway_fingerprint": gateway_fingerprint,
        "root_sha256": root_sha256,
        "bind": bind,
        "service_identity": service_identity,
        "upstream_proxy": upstream_proxy,
        "upstream_ca_sha256": upstream_ca_sha256,
        "enrollments": fingerprinted_enrollments,
    });
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("failed to encode configuration fingerprint: {error}"))?;
    Ok(digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn relay_binary_sha256(path: &Path) -> Result<String, String> {
    let mut context = ring::digest::Context::new(&SHA256);
    crate::filesystem::bounded::stream_bounded_regular_file(
        path,
        "nemo-relay executable",
        |chunk| context.update(chunk),
    )?;
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Clone, Eq, PartialEq)]
struct RelayBinaryIdentity {
    sha256: String,
    metadata: RelayBinaryMetadata,
}

#[derive(Clone, Eq, PartialEq)]
struct RelayBinaryMetadata {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl RelayBinaryIdentity {
    fn capture(path: &Path) -> Result<Self, String> {
        let before = RelayBinaryMetadata::capture(path)?;
        let sha256 = relay_binary_sha256(path)?;
        let after = RelayBinaryMetadata::capture(path)?;
        if before != after {
            return Err(format!(
                "nemo-relay executable {} changed while its identity was being captured",
                path.display()
            ));
        }
        Ok(Self {
            sha256,
            metadata: after,
        })
    }

    fn verify(&self, path: &Path) -> Result<(), String> {
        if RelayBinaryMetadata::capture(path)? == self.metadata {
            Ok(())
        } else {
            Err(format!(
                "nemo-relay executable {} changed after proxy startup",
                path.display()
            ))
        }
    }
}

impl RelayBinaryMetadata {
    fn capture(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!(
                "failed to inspect nemo-relay executable {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "nemo-relay executable {} must be a regular file",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
            })
        }
    }
}

fn corporate_ca_sha256(
    proxy: Option<&settings::UpstreamProxy>,
    description: &str,
) -> Result<Option<String>, String> {
    proxy
        .and_then(|proxy| proxy.ca_bundle.as_deref())
        .map(|path| {
            crate::filesystem::bounded::read_bounded_regular_file(path, description).map(|bytes| {
                digest(&SHA256, &bytes)
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
        })
        .transpose()
}

fn select_proxy_bind() -> Result<SocketAddr, String> {
    #[cfg(unix)]
    let user_key = {
        // SAFETY: `getuid` has no preconditions and does not mutate process state.
        u64::from(unsafe { libc::getuid() })
    };
    #[cfg(not(unix))]
    let user_key = {
        let identity = platform::current_service_identity(platform::Platform::Windows)?
            .ok_or_else(|| "Windows current-user SID is unavailable".to_string())?;
        let digest = digest(&SHA256, identity.as_bytes());
        u64::from_be_bytes(
            digest.as_ref()[..8]
                .try_into()
                .expect("SHA-256 contains at least eight bytes"),
        )
    };

    select_proxy_bind_for_user(user_key)
}

fn select_proxy_bind_for_user(user_key: u64) -> Result<SocketAddr, String> {
    for port in proxy_port_candidates(user_key) {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        match std::net::TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                return Ok(address);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => {
                return Err(format!(
                    "failed to probe per-user coding-agent proxy address {address}: {error}"
                ));
            }
        }
    }
    select_ephemeral_proxy_bind()
}

fn proxy_port_candidates(user_key: u64) -> impl Iterator<Item = u16> {
    let offset = ((user_key.wrapping_mul(2_654_435_761)) % u64::from(USER_PORT_SPAN)) as u16;
    (0..=USER_PORT_PROBE_COUNT)
        .map(move |attempt| {
            let relative = (u32::from(offset) + u32::from(attempt)) % USER_PORT_SPAN;
            USER_PORT_BASE + relative as u16
        })
        .filter(|port| *port != LEGACY_PROXY_BIND.port())
        .take(usize::from(USER_PORT_PROBE_COUNT))
}

fn select_ephemeral_proxy_bind() -> Result<SocketAddr, String> {
    let mut legacy_reservations = Vec::new();
    for _ in 0..USER_PORT_PROBE_COUNT {
        let listener =
            std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .map_err(|error| {
                    format!("failed to allocate a per-user coding-agent proxy port: {error}")
                })?;
        let address = listener.local_addr().map_err(|error| {
            format!("failed to inspect the selected coding-agent proxy port: {error}")
        })?;
        if address != LEGACY_PROXY_BIND {
            return Ok(address);
        }
        // Keep the rejected legacy endpoint reserved so the next ephemeral allocation cannot
        // immediately return the same port.
        legacy_reservations.push(listener);
    }
    Err("failed to allocate a non-legacy per-user coding-agent proxy port".into())
}

fn wait_for_health(installed: &state::DesktopState) -> Result<(), String> {
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match proxy::health(installed, HEALTH_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "coding-agent proxy did not become healthy: {}",
        last.unwrap_or_else(|| "timed out".into())
    ))
}

fn wait_for_listener_stop(installed: &state::DesktopState) -> Result<(), String> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        match std::net::TcpStream::connect_timeout(&installed.bind, HEALTH_TIMEOUT) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::AddrNotAvailable
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(());
            }
            Err(_) | Ok(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    Err(format!(
        "coding-agent proxy listener at {} remained reachable after the user service stop",
        installed.bind
    ))
}

fn private_state_files(installed: &state::DesktopState) -> Result<(), String> {
    let generations = installed.install_root.join("generations");
    let generation = generations.join(&installed.generation);
    for directory in [&installed.install_root, &generations, &generation] {
        state::validate_private_directory(directory)?;
    }
    let leaf_cache = generation.join("leaf-cache");
    match std::fs::symlink_metadata(&leaf_cache) {
        Ok(_) => state::validate_private_directory(&leaf_cache)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect optional leaf cache {}: {error}",
                leaf_cache.display()
            ));
        }
    }
    if installed.certificate.ca_signer_kind == "file-pkcs8" {
        certificate::leaf_key_is_private(&installed.certificate.ca_key_der)?;
    }
    certificate::cached_leaf_keys_are_private(&installed.certificate)?;
    certificate::leaf_key_is_private(&installed.state_path())
}

fn linux_ca_bundle(installed: &state::DesktopState) -> Option<&Path> {
    installed
        .settings
        .fields
        .get("NODE_EXTRA_CA_CERTS")?
        .installed
        .as_ref()?
        .as_str()
        .map(Path::new)
}

fn remove_generation(root: &Path, generation: &str) -> Result<(), String> {
    let path = root.join("generations").join(generation);
    if path.parent().and_then(Path::parent) != Some(root) {
        return Err(format!(
            "refusing to remove unexpected generation path {}",
            path.display()
        ));
    }
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

fn remove_fresh_install_root(root: &Path) -> Result<(), String> {
    for name in [
        "proxy.stdout.log",
        "proxy.stderr.log",
        CODEX_CA_BUNDLE_FILE_NAME,
    ] {
        state::remove_file_if_present(&root.join(name))?;
    }
    remove_empty_directory(&root.join("generations"))?;
    remove_empty_directory(root)
}

fn remove_empty_directory(path: &Path) -> Result<(), String> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

fn deep_link(folder: &Path) -> Result<String, CliError> {
    let folder = folder.to_str().ok_or_else(|| {
        CliError::Launch(format!(
            "Claude Desktop folder is not valid Unicode: {}",
            folder.display()
        ))
    })?;
    Ok(format!(
        "claude://code/new?folder={}",
        utf8_percent_encode(folder, NON_ALPHANUMERIC)
    ))
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/mod_tests.rs"]
mod tests;
