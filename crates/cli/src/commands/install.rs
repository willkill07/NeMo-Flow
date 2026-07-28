// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};

use crate::agents::CodingAgent;
use crate::error::CliError;

const BATCH_TRANSACTION_FILE_NAME: &str = "agent-proxy-batch-transaction.json";

#[derive(Debug, Clone, Args)]
pub(crate) struct InstallCommand {
    /// Agent whose user-owned configuration, hooks, and provider routing Relay will enroll.
    #[arg(value_enum)]
    pub(crate) host: InstallTarget,
    /// Override the root for proxy state and marketplace artifacts (testing/isolation only).
    #[arg(long)]
    pub(crate) install_dir: Option<PathBuf>,
    /// Transactionally refresh an existing enrollment, including policy and CA identity.
    #[arg(long)]
    pub(crate) force: bool,
    /// Preview owned host changes and platform-specific trust behavior without mutating state.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Skip post-install health verification; the proxy must still prove its service identity.
    #[arg(long)]
    pub(crate) skip_doctor: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct UninstallCommand {
    /// Agent enrollment to remove, or all Relay-owned enrollment remnants.
    #[arg(value_enum)]
    pub(crate) host: InstallTarget,
    /// Use the proxy-state and marketplace root selected by the matching installation.
    #[arg(long)]
    pub(crate) install_dir: Option<PathBuf>,
    /// Preview restoration and removal without mutating state.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum InstallTarget {
    Codex,
    #[value(name = "claude-code", alias = "claude")]
    ClaudeCode,
    ClaudeDesktop,
    Hermes,
    All,
}

impl InstallTarget {
    pub(crate) fn agents(self) -> Vec<CodingAgent> {
        match self {
            Self::Codex => vec![CodingAgent::Codex],
            Self::ClaudeCode => vec![CodingAgent::ClaudeCode],
            Self::ClaudeDesktop => Vec::new(),
            Self::Hermes => vec![CodingAgent::Hermes],
            Self::All => vec![
                CodingAgent::Codex,
                CodingAgent::ClaudeCode,
                CodingAgent::Hermes,
            ],
        }
    }

    pub(crate) const fn is_all(self) -> bool {
        matches!(self, Self::All)
    }
}

impl InstallCommand {
    pub(crate) fn into_runtime(self) -> crate::installation::InstallRequest {
        crate::installation::InstallRequest {
            install_dir: self.install_dir,
            force: self.force,
            dry_run: self.dry_run,
            skip_doctor: self.skip_doctor,
        }
    }
}

impl UninstallCommand {
    pub(crate) fn into_runtime(self) -> crate::installation::UninstallRequest {
        crate::installation::UninstallRequest {
            install_dir: self.install_dir,
            dry_run: self.dry_run,
        }
    }
}

pub(super) fn install(command: InstallCommand) -> Result<ExitCode, CliError> {
    let target = command.host;
    let mut request = command.into_runtime();
    let _batch_lock = (!request.dry_run)
        .then(crate::claude_desktop::batch_operation_lock)
        .transpose()
        .map_err(CliError::Install)?;
    if !request.dry_run {
        recover_batch_transaction()?;
    }
    if target == InstallTarget::ClaudeDesktop {
        return crate::claude_desktop::install(request);
    }
    request.install_dir = Some(selected_marketplace_install_dir(
        request.install_dir.as_deref(),
    )?);
    let candidates = target.agents();
    let agents = if target.is_all() {
        crate::agents::detected_install_integrations(&candidates)
    } else {
        candidates
    };
    if agents.is_empty() {
        return Err(CliError::Install(
            "no supported Claude Code, Codex, or Hermes CLI was detected on PATH; install a CLI or explicitly select `claude-desktop` for the preview Desktop integration"
                .into(),
        ));
    }
    if target.is_all() {
        let transaction = (!request.dry_run)
            .then(|| snapshot_batch(&agents, false, request.install_dir.as_deref()))
            .transpose()?;
        if let Some(transaction) = transaction.as_ref() {
            write_batch_transaction("install", "prepared", transaction)?;
        }
        let _retirement_guard = transaction.as_ref().map(|_| {
            crate::claude_desktop::defer_batch_resource_retirement(|retirement| {
                record_batch_deferred_retirement(retirement).map_err(|error| error.to_string())
            })
        });
        let operations = agents
            .iter()
            .copied()
            .map(|agent| {
                let result = crate::agents::install_integration(agent, request.clone());
                (
                    agent.as_arg().to_string(),
                    record_batch_host_result(agent, result),
                )
            })
            .collect::<Vec<_>>();
        let result = finish_operations(operations, "install");
        return finish_batch(result, transaction.as_ref(), "install");
    }
    run_agent_operations(agents, "install", |agent| {
        crate::agents::install_integration(agent, request.clone())
    })
}

pub(super) fn uninstall(command: UninstallCommand) -> Result<ExitCode, CliError> {
    let target = command.host;
    let mut request = command.into_runtime();
    let _batch_lock = (!request.dry_run)
        .then(crate::claude_desktop::batch_operation_lock)
        .transpose()
        .map_err(CliError::Install)?;
    if !request.dry_run {
        recover_batch_transaction()?;
    }
    if target == InstallTarget::ClaudeDesktop {
        return crate::claude_desktop::uninstall(request);
    }
    request.install_dir = Some(selected_marketplace_install_dir(
        request.install_dir.as_deref(),
    )?);
    let candidates = target.agents();
    let agents = if target.is_all() {
        crate::agents::installed_integrations(&candidates, request.install_dir.as_deref())
    } else {
        candidates
    };
    let desktop_enrolled = target.is_all()
        && crate::claude_desktop::is_enrolled(request.install_dir.as_deref())
            .map_err(CliError::Install)?;
    if agents.is_empty() && !desktop_enrolled {
        return Err(CliError::Install(
            "no installed Claude Code, Claude Desktop, Codex, or Hermes integration state was found"
                .into(),
        ));
    }
    if target.is_all() {
        let transaction = (!request.dry_run)
            .then(|| snapshot_batch(&agents, desktop_enrolled, request.install_dir.as_deref()))
            .transpose()?;
        if let Some(transaction) = transaction.as_ref() {
            write_batch_transaction("uninstall", "prepared", transaction)?;
        }
        let _retirement_guard = transaction.as_ref().map(|_| {
            crate::claude_desktop::defer_batch_resource_retirement(|retirement| {
                record_batch_deferred_retirement(retirement).map_err(|error| error.to_string())
            })
        });
        let mut operations = agents
            .iter()
            .copied()
            .map(|agent| {
                let result = crate::agents::uninstall_integration(agent, request.clone());
                (
                    agent.as_arg().to_string(),
                    record_batch_host_result(agent, result),
                )
            })
            .collect::<Vec<_>>();
        if desktop_enrolled {
            let result = crate::claude_desktop::uninstall(request.clone());
            operations.push((
                "claude-desktop".into(),
                record_batch_host_result(CodingAgent::ClaudeCode, result),
            ));
        }
        let result = finish_operations(operations, "uninstall");
        return finish_batch(result, transaction.as_ref(), "uninstall");
    }
    run_agent_operations(agents, "uninstall", |agent| {
        crate::agents::uninstall_integration(agent, request.clone())
    })
}

fn record_batch_host_result(
    agent: CodingAgent,
    result: Result<ExitCode, CliError>,
) -> Result<ExitCode, CliError> {
    let recorded = update_batch_host_result(agent);
    match (result, recorded) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(snapshot)) => Err(CliError::Install(format!(
            "{operation}; additionally failed to persist the host result snapshot: {snapshot}"
        ))),
    }
}

fn update_batch_host_result(agent: CodingAgent) -> Result<(), CliError> {
    if !batch_transaction_path()?.exists() {
        return Ok(());
    }
    let mut transaction = read_batch_transaction()?;
    if let Some(snapshot) = transaction
        .snapshot
        .agents
        .iter_mut()
        .find(|snapshot| snapshot.agent == agent)
    {
        snapshot.expected_current = Some(
            crate::agents::capture_current_setup_snapshot(&snapshot.previous)
                .map_err(CliError::Install)?,
        );
    }
    if agent == CodingAgent::ClaudeCode
        && let Some(snapshot) = transaction.snapshot.claude_desktop_host.as_mut()
    {
        snapshot.capture_result().map_err(CliError::Install)?;
    }
    if let Some(marketplace) = transaction
        .snapshot
        .marketplaces
        .iter_mut()
        .find(|snapshot| snapshot.previous.agent() == agent)
    {
        marketplace.expected_current = Some(
            marketplace
                .previous
                .capture_current()
                .map_err(CliError::Install)?,
        );
    }
    persist_batch_transaction(&transaction)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BatchSnapshot {
    proxy: crate::claude_desktop::ProxyStateSnapshot,
    agents: Vec<BatchAgentSnapshot>,
    claude_desktop_host: Option<crate::claude_desktop::ClaudeDesktopHostSnapshot>,
    marketplaces: Vec<BatchMarketplaceSnapshot>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct BatchAgentSnapshot {
    agent: CodingAgent,
    previous: crate::agents::SetupSnapshot,
    #[serde(default)]
    expected_current: Option<crate::agents::SetupSnapshot>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct BatchMarketplaceSnapshot {
    previous: crate::installation::marketplace::DurableMarketplaceSnapshot,
    #[serde(default)]
    expected_current: Option<crate::installation::marketplace::DurableMarketplaceSnapshot>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BatchTransaction {
    schema_version: u32,
    operation: String,
    stage: String,
    snapshot: BatchSnapshot,
    #[serde(default)]
    deferred_proxy_retirements: Vec<crate::claude_desktop::DeferredProxyRetirement>,
}

fn snapshot_batch(
    agents: &[CodingAgent],
    include_claude_desktop: bool,
    install_dir: Option<&std::path::Path>,
) -> Result<BatchSnapshot, CliError> {
    let proxy =
        crate::claude_desktop::snapshot_proxy_state(install_dir).map_err(CliError::Install)?;
    let agents = agents
        .iter()
        .copied()
        .map(|agent| {
            crate::agents::snapshot_setup(agent)
                .map(|previous| BatchAgentSnapshot {
                    agent,
                    previous,
                    expected_current: None,
                })
                .map_err(CliError::Install)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let claude_desktop_host = include_claude_desktop
        .then(|| crate::claude_desktop::snapshot_claude_desktop_host(install_dir))
        .transpose()
        .map_err(CliError::Install)?;
    let marketplaces =
        snapshot_marketplaces(agents.as_slice(), include_claude_desktop, install_dir)?;
    Ok(BatchSnapshot {
        proxy,
        agents,
        claude_desktop_host,
        marketplaces,
    })
}

fn snapshot_marketplaces(
    agents: &[BatchAgentSnapshot],
    include_claude_desktop: bool,
    install_dir: Option<&std::path::Path>,
) -> Result<Vec<BatchMarketplaceSnapshot>, CliError> {
    let install_dir = selected_marketplace_install_dir(install_dir)?;
    let mut hosts = agents
        .iter()
        .map(|snapshot| snapshot.agent)
        .filter(|agent| matches!(agent, CodingAgent::Codex | CodingAgent::ClaudeCode))
        .collect::<Vec<_>>();
    if include_claude_desktop && !hosts.contains(&CodingAgent::ClaudeCode) {
        hosts.push(CodingAgent::ClaudeCode);
    }
    hosts
        .into_iter()
        .map(|agent| {
            crate::installation::marketplace::capture_marketplace_snapshot(agent, &install_dir)
                .map(|previous| BatchMarketplaceSnapshot {
                    previous,
                    expected_current: None,
                })
                .map_err(CliError::Install)
        })
        .collect()
}

pub(super) fn selected_marketplace_install_dir(
    install_dir: Option<&std::path::Path>,
) -> Result<PathBuf, CliError> {
    crate::claude_desktop::resolved_marketplace_install_dir(install_dir).map_err(CliError::Install)
}

fn finish_batch(
    result: Result<ExitCode, CliError>,
    snapshot: Option<&BatchSnapshot>,
    operation: &str,
) -> Result<ExitCode, CliError> {
    let failed = match result.as_ref() {
        Ok(status) => *status != ExitCode::SUCCESS,
        Err(_) => true,
    };
    if !failed {
        if snapshot.is_some() {
            let transaction = match mark_batch_transaction_committed(operation) {
                Ok(transaction) => transaction,
                Err(commit) => {
                    return match rollback_current_batch(operation) {
                        Ok(()) => {
                            remove_batch_transaction().map_err(CliError::Install)?;
                            Err(CliError::Install(format!(
                                "failed to commit atomic `{operation} all` transaction: {commit}; restored every target from its snapshot"
                            )))
                        }
                        Err(rollback) => Err(CliError::Install(format!(
                            "failed to commit atomic `{operation} all` transaction: {commit}; rollback also failed: {rollback}"
                        ))),
                    };
                }
            };
            if let Err(error) = crate::claude_desktop::finalize_batch_resource_retirements(
                &transaction.deferred_proxy_retirements,
            ) {
                return Err(CliError::Install(format!(
                    "atomic `{operation} all` committed, but deferred certificate cleanup failed and will be retried: {error}"
                )));
            }
            remove_batch_transaction().map_err(CliError::Install)?;
        }
        return result;
    }
    if snapshot.is_none() {
        return result;
    }
    match rollback_current_batch(operation) {
        Ok(()) => {
            remove_batch_transaction().map_err(CliError::Install)?;
            result.map_err(|error| {
                CliError::Install(format!(
                    "{error}; restored every target from the atomic `{operation} all` snapshot"
                ))
            })
        }
        Err(rollback) => Err(CliError::Install(format!(
            "{}; atomic `{operation} all` rollback also failed: {rollback}",
            result.err().map_or_else(
                || "an integration returned failure".into(),
                |error| error.to_string()
            )
        ))),
    }
}

fn rollback_current_batch(operation: &str) -> Result<(), String> {
    let transaction = read_batch_transaction().map_err(|error| error.to_string())?;
    if transaction.operation != operation || transaction.stage != "prepared" {
        return Err(format!(
            "atomic `{operation} all` rollback found an unexpected {} {} journal",
            transaction.operation, transaction.stage
        ));
    }
    rollback_batch(&transaction.snapshot)?;
    crate::claude_desktop::finalize_batch_resource_retirements(
        &transaction.deferred_proxy_retirements,
    )
    .map_err(|error| format!("deferred proxy resources: {error}"))
}

fn mark_batch_transaction_committed(operation: &str) -> Result<BatchTransaction, CliError> {
    let mut transaction = read_batch_transaction()?;
    if transaction.operation != operation || transaction.stage != "prepared" {
        return Err(CliError::Install(format!(
            "cannot commit atomic `{operation} all`: journal identifies {} {}",
            transaction.operation, transaction.stage
        )));
    }
    transaction.stage = "committed".into();
    persist_batch_transaction(&transaction)?;
    Ok(transaction)
}

fn record_batch_deferred_retirement(
    retirement: crate::claude_desktop::DeferredProxyRetirement,
) -> Result<(), CliError> {
    let mut transaction = read_batch_transaction()?;
    if transaction.stage != "prepared" {
        return Err(CliError::Install(format!(
            "cannot defer proxy certificate retirement after batch stage {}",
            transaction.stage
        )));
    }
    if !transaction
        .deferred_proxy_retirements
        .iter()
        .any(|existing| existing.same_resource(&retirement))
    {
        transaction.deferred_proxy_retirements.push(retirement);
        persist_batch_transaction(&transaction)?;
    }
    Ok(())
}

fn read_batch_transaction() -> Result<BatchTransaction, CliError> {
    let path = batch_transaction_path()?;
    let bytes = crate::filesystem::bounded::read_bounded_regular_file(
        &path,
        "coding-agent proxy batch transaction",
    )
    .map_err(CliError::Install)?;
    let transaction = serde_json::from_slice::<BatchTransaction>(&bytes).map_err(|error| {
        CliError::Install(format!(
            "invalid batch transaction {}: {error}",
            path.display()
        ))
    })?;
    validate_batch_transaction(&transaction, &path)?;
    Ok(transaction)
}

fn validate_batch_transaction(
    transaction: &BatchTransaction,
    path: &std::path::Path,
) -> Result<(), CliError> {
    if transaction.schema_version != 6
        || !matches!(transaction.operation.as_str(), "install" | "uninstall")
        || !matches!(transaction.stage.as_str(), "prepared" | "committed")
    {
        return Err(CliError::Install(format!(
            "invalid batch transaction identity in {}",
            path.display()
        )));
    }
    Ok(())
}

fn persist_batch_transaction(transaction: &BatchTransaction) -> Result<(), CliError> {
    let path = batch_transaction_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CliError::Install(format!("failed to create {}: {error}", parent.display()))
        })?;
    }
    let mut bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| CliError::Install(format!("failed to encode batch journal: {error}")))?;
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(&path, &bytes).map_err(CliError::Install)
}

/*
 * A prepared journal owns rollback. A committed journal owns deferred resource retirement.
 * Keeping these transitions explicit makes crash recovery idempotent on either side of commit.
 */

pub(super) fn batch_transaction_path() -> Result<PathBuf, CliError> {
    crate::claude_desktop::active_user_config_dir()
        .map(|directory| directory.join(BATCH_TRANSACTION_FILE_NAME))
        .map_err(CliError::Install)
}

fn write_batch_transaction(
    operation: &str,
    stage: &str,
    snapshot: &BatchSnapshot,
) -> Result<(), CliError> {
    let transaction = BatchTransaction {
        schema_version: 6,
        operation: operation.into(),
        stage: stage.into(),
        snapshot: BatchSnapshot {
            proxy: snapshot.proxy.clone(),
            agents: snapshot.agents.clone(),
            claude_desktop_host: snapshot.claude_desktop_host.clone(),
            marketplaces: snapshot.marketplaces.clone(),
        },
        deferred_proxy_retirements: Vec::new(),
    };
    validate_batch_transaction(&transaction, &batch_transaction_path()?)?;
    persist_batch_transaction(&transaction)
}

pub(super) fn recover_batch_transaction() -> Result<(), CliError> {
    let path = batch_transaction_path()?;
    if !path.exists() {
        return Ok(());
    }
    let transaction = read_batch_transaction()?;
    if transaction.stage == "prepared" {
        let _retirement_guard =
            crate::claude_desktop::defer_batch_resource_retirement(|retirement| {
                record_batch_deferred_retirement(retirement).map_err(|error| error.to_string())
            });
        rollback_current_batch(&transaction.operation).map_err(CliError::Install)?;
    } else {
        crate::claude_desktop::finalize_batch_resource_retirements(
            &transaction.deferred_proxy_retirements,
        )
        .map_err(CliError::Install)?;
    }
    remove_batch_transaction().map_err(CliError::Install)?;
    if transaction.stage == "prepared" {
        println!(
            "recovered interrupted atomic `{} all` transaction",
            transaction.operation
        );
    } else {
        println!(
            "finished committed atomic `{} all` transaction",
            transaction.operation
        );
    }
    Ok(())
}

fn remove_batch_transaction() -> Result<(), String> {
    let path = batch_transaction_path().map_err(|error| error.to_string())?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
    }
}

fn rollback_batch(snapshot: &BatchSnapshot) -> Result<(), String> {
    let mut errors = snapshot
        .agents
        .iter()
        .rev()
        .filter_map(|snapshot| {
            crate::agents::restore_setup_snapshot_cas(
                &snapshot.previous,
                snapshot.expected_current.as_ref(),
            )
            .err()
            .map(|error| format!("{}: {error}", snapshot.agent.label()))
        })
        .collect::<Vec<_>>();
    if let Some(desktop) = snapshot.claude_desktop_host.as_ref()
        && let Err(error) = crate::claude_desktop::restore_claude_desktop_host(desktop)
    {
        errors.push(format!("Claude Desktop host: {error}"));
    }
    errors.extend(
        snapshot
            .marketplaces
            .iter()
            .rev()
            .filter_map(|marketplace| {
                crate::installation::marketplace::restore_marketplace_snapshot_cas(
                    &marketplace.previous,
                    marketplace.expected_current.as_ref(),
                )
                .err()
                .map(|error| format!("marketplace: {error}"))
            }),
    );
    if errors.is_empty() {
        if let Err(error) = crate::claude_desktop::restore_proxy_state_snapshot(&snapshot.proxy) {
            errors.push(format!("agent proxy: {error}"));
        }
    } else {
        errors.push(
            "agent proxy rollback was skipped because host ownership changed; retained the current proxy to avoid restoring stale credentials"
                .into(),
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(super) fn run_agent_operations(
    agents: Vec<CodingAgent>,
    operation: &str,
    mut run: impl FnMut(CodingAgent) -> Result<ExitCode, CliError>,
) -> Result<ExitCode, CliError> {
    finish_operations(
        agents
            .into_iter()
            .map(|agent| (agent.as_arg().to_string(), run(agent))),
        operation,
    )
}

pub(super) fn finish_operations(
    operations: impl IntoIterator<Item = (String, Result<ExitCode, CliError>)>,
    operation: &str,
) -> Result<ExitCode, CliError> {
    let mut result = ExitCode::SUCCESS;
    let mut errors = Vec::new();
    for (target, outcome) in operations {
        match outcome {
            Ok(status) if status != ExitCode::SUCCESS => result = status,
            Ok(_) => {}
            Err(error) => errors.push(format!("{target}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(result)
    } else {
        Err(CliError::Install(format!(
            "failed to {operation} one or more integrations after attempting every target: {}",
            errors.join("; ")
        )))
    }
}
