// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Command parsing, dispatch, rendering, and exit-code ownership.

mod completions;
mod configure;
mod diagnostics;
mod hook_forward;
mod install;
#[cfg(feature = "internal-test-server")]
mod internal_test_server;
mod logging;
mod model_pricing;
mod plugins;
pub(crate) mod root;
mod serve;

use std::process::ExitCode;

use clap::Parser;

#[cfg(test)]
use self::completions::CompletionsCommand;
#[cfg(test)]
use self::model_pricing::PricingCommand;
#[cfg(test)]
use self::plugins::PluginsCommand;
use self::root::{Cli, Command};
use self::serve::ServerArgs;
use crate::{configuration as runtime_configuration, diagnostics as runtime_diagnostics, error};

#[cfg(feature = "internal-test-server")]
pub(crate) use internal_test_server::run as run_internal_test_server_cli;

// Runs the async CLI entrypoint and converts any surfaced command error into a non-zero process
// exit. Errors are printed once here so subcommands can return structured errors without also
// owning process-level reporting.
pub(crate) async fn run(bootstrap_shutdown_token: Option<String>) -> ExitCode {
    match dispatch(bootstrap_shutdown_token).await {
        Ok(code) => code,
        Err(error) => {
            let exit_code = if error.requires_blocking_hook_exit() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            };
            eprintln!("{error}");
            exit_code
        }
    }
}

// Dispatches CLI subcommands. The no-subcommand path retains interactive setup/doctor behavior,
// while retired standalone-server flags are rejected by `run_default`.
async fn dispatch(bootstrap_shutdown_token: Option<String>) -> Result<ExitCode, error::CliError> {
    let cli = Cli::parse();
    let command_name = cli
        .command
        .as_ref()
        .map(Command::log_name)
        .unwrap_or("default");

    let initialize_logging = match cli.command.as_ref() {
        Some(command) => !command.skips_logging(),
        None => runtime_configuration::any_config_file_exists(),
    };
    let _logging = if initialize_logging {
        let user_only = false;
        let explicit_config = cli.server.config.as_deref();
        let config = cli.logging.resolve(explicit_config, user_only)?;
        let runtime = nemo_relay::logging::LoggingRuntime::configure(config)?;
        Some(runtime)
    } else {
        None
    };

    log::info!(
        target: "nemo_relay.cli",
        event = "command_started",
        command = command_name;
        "CLI command started"
    );

    let result = match cli.command {
        Some(command) => run_command(command, &cli.server).await,
        None => run_default(&cli.server, bootstrap_shutdown_token).await,
    };
    match &result {
        Ok(code) if *code == ExitCode::SUCCESS => log::info!(
            target: "nemo_relay.cli",
            event = "command_completed",
            command = command_name,
            outcome = "success";
            "CLI command completed"
        ),
        Ok(_) => log::warn!(
            target: "nemo_relay.cli",
            event = "command_completed",
            command = command_name,
            outcome = "nonzero_exit";
            "CLI command completed with a non-zero exit status"
        ),
        Err(error) if error.guardrail_rejection_reason().is_some() => log::warn!(
            target: "nemo_relay.cli",
            event = "command_rejected",
            command = command_name,
            error_kind = error.log_kind();
            "CLI command was rejected by policy"
        ),
        Err(error) => log::error!(
            target: "nemo_relay.cli",
            event = "command_failed",
            command = command_name,
            error_kind = error.log_kind();
            "CLI command failed"
        ),
    }
    result
}

async fn run_command(command: Command, server: &ServerArgs) -> Result<ExitCode, error::CliError> {
    validate_server_override_policy(&command, server)?;
    match command {
        Command::HookForward(command) => {
            hook_forward::execute(command).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ClaudeDesktop(command) => {
            crate::claude_desktop::launch(command.into_runtime()).await
        }
        Command::AgentProxyService(command) => {
            crate::claude_desktop::run_proxy_service(command.into_runtime()).await
        }
        Command::Install(command) => install::install(command),
        Command::Uninstall(command) => install::uninstall(command),
        Command::Config(command) => configure::execute(command).await,
        Command::Plugins(command) => plugins::execute(command, server),
        Command::ModelPricing(command) => model_pricing::execute(command),
        Command::Doctor(command) => diagnostics::execute(command).await,
        Command::Agents(command) => runtime_diagnostics::run_agents(command.json).await,
        Command::Completions(command) => completions::execute(command),
    }
}

fn validate_server_override_policy(
    command: &Command,
    server: &ServerArgs,
) -> Result<(), error::CliError> {
    let internal_transport = matches!(
        command,
        Command::HookForward(_) | Command::AgentProxyService(_)
    );
    if !internal_transport && !matches!(command, Command::Plugins(_)) && server.has_overrides() {
        return Err(error::CliError::Config(
            "root gateway/config overrides are not supported by this command; persistent coding-agent services load system and user configuration, while explicit plugin configuration paths are supported only by `nemo-relay plugins`"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn generate_completions_to(
    shell: Option<clap_complete::Shell>,
    writer: &mut dyn std::io::Write,
) -> Result<(), error::CliError> {
    completions::generate_to(shell, writer)
}

async fn run_default(
    server_args: &ServerArgs,
    _bootstrap_shutdown_token: Option<String>,
) -> Result<ExitCode, error::CliError> {
    let runtime_args = server_args.to_runtime();
    if runtime_args.requested_daemon_mode() {
        Err(error::CliError::Config(
            "standalone gateway launch was removed; enroll a local client with `nemo-relay install <claude-code|claude-desktop|codex|hermes>`"
                .into(),
        ))
    } else if runtime_configuration::any_config_file_exists() {
        runtime_diagnostics::run_doctor(None, false).await
    } else {
        Err(error::CliError::Config(
            "no persistent Relay configuration exists; run `nemo-relay config` to edit user policy or `nemo-relay install <agent>` to enroll a coding agent"
                .into(),
        ))
    }
}

#[cfg(test)]
fn run_completions(command: CompletionsCommand) -> Result<ExitCode, error::CliError> {
    completions::execute(command)
}

#[cfg(test)]
fn run_plugins(command: PluginsCommand, server: &ServerArgs) -> Result<ExitCode, error::CliError> {
    plugins::execute(command, server)
}

#[cfg(test)]
fn run_pricing(command: PricingCommand) -> Result<ExitCode, error::CliError> {
    model_pricing::execute(command)
}

#[cfg(test)]
#[path = "../../tests/coverage/commands/main_tests.rs"]
mod tests;
