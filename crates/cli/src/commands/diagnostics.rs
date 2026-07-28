// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::cognitive_complexity)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use serde_json::{Value, json};

use super::install::{InstallTarget, finish_operations};
use crate::error::CliError;

#[derive(Debug, Clone, Args)]
pub(crate) struct DoctorCommand {
    /// Installed coding-agent enrollment to diagnose.
    #[arg(value_enum)]
    pub(crate) agent: Option<InstallTarget>,
    /// Use the proxy-state and marketplace root selected by the matching installation.
    #[arg(long, requires = "agent")]
    pub(crate) install_dir: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentsCommand {
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn execute(command: DoctorCommand) -> Result<ExitCode, CliError> {
    if let Some(agent) = command.agent {
        return execute_agent_doctor(agent, command.install_dir, command.json);
    }
    crate::diagnostics::run_doctor(None, command.json).await
}

fn execute_agent_doctor(
    agent: InstallTarget,
    install_dir: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode, CliError> {
    let requested_enrollments = doctor_enrollment_names(agent);
    crate::claude_desktop::ensure_selected_enrollment_root(
        install_dir.as_deref(),
        &requested_enrollments,
        "doctor",
    )
    .map_err(CliError::Install)?;
    if agent == InstallTarget::ClaudeDesktop {
        return crate::claude_desktop::doctor(install_dir, json);
    }
    let selected_install_dir =
        crate::claude_desktop::resolved_marketplace_install_dir(install_dir.as_deref())
            .map_err(CliError::Install)?;
    let selected_install_dir_ref = Some(selected_install_dir.as_path());
    let candidates = agent.agents();
    let agents = if agent.is_all() {
        crate::agents::installed_integrations(&candidates, selected_install_dir_ref)
    } else {
        candidates
    };
    let desktop_enrolled = agent.is_all()
        && crate::claude_desktop::is_enrolled(selected_install_dir_ref)
            .map_err(CliError::Install)?;
    if agents.is_empty() && !desktop_enrolled {
        return Err(CliError::Install(
            "no installed Claude Code, Claude Desktop, Codex, or Hermes integration state was found"
                .into(),
        ));
    }
    let options =
        crate::installation::marketplace::plugin_doctor_options(Some(selected_install_dir));
    if !json {
        let mut operations = agents
            .into_iter()
            .map(|agent| {
                (
                    agent.as_arg().to_string(),
                    crate::agents::doctor_integration(agent, &options).map(|()| ExitCode::SUCCESS),
                )
            })
            .collect::<Vec<_>>();
        if desktop_enrolled {
            operations.push((
                "claude-desktop".into(),
                crate::claude_desktop::doctor(Some(options.install_dir.clone()), false),
            ));
        }
        return finish_operations(operations, "diagnose");
    }
    print_agent_doctor_json(&agents, desktop_enrolled, &options)
}

fn doctor_enrollment_names(agent: InstallTarget) -> Vec<&'static str> {
    let mut names = agent
        .agents()
        .into_iter()
        .map(crate::agents::CodingAgent::install_arg)
        .collect::<Vec<_>>();
    if matches!(agent, InstallTarget::ClaudeDesktop | InstallTarget::All) {
        names.push("claude-desktop");
    }
    names
}

fn print_agent_doctor_json(
    agents: &[crate::agents::CodingAgent],
    include_desktop: bool,
    options: &crate::installation::marketplace::state::PluginInstallOptions,
) -> Result<ExitCode, CliError> {
    let mut reports = agents
        .iter()
        .copied()
        .map(|agent| crate::agents::doctor_integration_report(agent, options))
        .collect::<Result<Vec<_>, _>>()?;
    if include_desktop {
        reports.push(crate::claude_desktop::doctor_report_json(Some(
            options.install_dir.as_path(),
        ))?);
    }
    let ready = reports
        .iter()
        .all(|report| report.get("ok").and_then(Value::as_bool) == Some(true));
    let output = if reports.len() > 1 {
        json!({ "schema_version": 1, "ok": ready, "integrations": reports })
    } else {
        with_schema(reports.into_iter().next().expect("reports is not empty"))
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .map_err(|error| CliError::Install(error.to_string()))?
    );
    Ok(if ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn with_schema(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("schema_version".into(), json!(1));
    }
    value
}
