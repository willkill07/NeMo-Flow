// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use super::completions::CompletionsCommand;
use super::configure::ConfigCommand;
use super::diagnostics::{AgentsCommand, DoctorCommand};
use super::hook_forward::HookForwardCommand;
use super::install::{InstallCommand, UninstallCommand};
use super::logging::LoggingArgs;
use super::model_pricing::PricingCommand;
use super::plugins::PluginsCommand;
use super::serve::ServerArgs;
use crate::agents::CodingAgent;

#[derive(Debug, Clone, Args)]
pub(crate) struct ClaudeDesktopCommand {
    /// Folder to open in a new Claude Desktop Code session (defaults to the current directory).
    #[arg(long)]
    pub(crate) folder: Option<PathBuf>,
}

impl ClaudeDesktopCommand {
    pub(crate) fn into_runtime(self) -> crate::claude_desktop::LaunchRequest {
        crate::claude_desktop::LaunchRequest {
            folder: self.folder,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentProxyServiceCommand {
    /// Installer-owned state file for this service generation.
    #[arg(long)]
    pub(crate) state: PathBuf,
}

impl AgentProxyServiceCommand {
    pub(crate) fn into_runtime(self) -> crate::claude_desktop::ProxyServiceRequest {
        crate::claude_desktop::ProxyServiceRequest { state: self.state }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum AgentArg {
    #[value(name = "claude", alias = "claude-code")]
    Claude,
    Codex,
    Hermes,
}

impl From<AgentArg> for CodingAgent {
    fn from(value: AgentArg) -> Self {
        match value {
            AgentArg::Claude => Self::ClaudeCode,
            AgentArg::Codex => Self::Codex,
            AgentArg::Hermes => Self::Hermes,
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(name = "nemo-relay")]
#[command(about = "Unified local coding-agent proxy for NeMo Relay")]
#[command(version)]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) server: ServerArgs,
    #[command(flatten)]
    pub(super) logging: LoggingArgs,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum Command {
    /// Open a protected Claude Desktop Code session.
    #[command(
        long_about = "Open the Claude Desktop Code tab through the explicitly installed, fail-closed NeMo Relay proxy. The command verifies TLS trust, authenticated proxy settings, plugin hooks, service identity, and persistent proxy configuration before opening Claude. Run `nemo-relay install claude-desktop` first.",
        after_help = "Examples:\n  nemo-relay claude-desktop\n  nemo-relay claude-desktop --folder ./my-project"
    )]
    ClaudeDesktop(ClaudeDesktopCommand),
    /// Edit persistent Relay policy at user scope (or system scope with `--system`).
    Config(ConfigCommand),
    /// Create or edit plugin configuration (writes `plugins.toml`)
    Plugins(PluginsCommand),
    /// Enroll local coding agents in the persistent per-user Relay proxy.
    Install(InstallCommand),
    /// Remove coding-agent enrollments created by `nemo-relay install`.
    Uninstall(UninstallCommand),
    /// Validate and configure model pricing catalogs.
    ModelPricing(PricingCommand),
    /// Diagnose env, agents, config, observability (optionally scoped to one agent)
    Doctor(DoctorCommand),
    /// List supported and locally-detected agents (use `--json` for machine output)
    Agents(AgentsCommand),
    /// Print shell completion script (e.g. `nemo-relay completions zsh > ~/.zfunc/_nemo-relay`)
    Completions(CompletionsCommand),
    /// Internal: subprocess used by installed hooks to forward events. Not typed by humans.
    #[command(hide = true)]
    HookForward(HookForwardCommand),
    /// Internal: persistent authenticated per-user coding-agent proxy.
    #[command(hide = true)]
    AgentProxyService(AgentProxyServiceCommand),
}

impl Command {
    pub(crate) fn log_name(&self) -> &'static str {
        match self {
            Self::ClaudeDesktop(_) => "claude_desktop",
            Self::Config(_) => "config",
            Self::Plugins(_) => "plugins",
            Self::Install(_) => "install",
            Self::Uninstall(_) => "uninstall",
            Self::ModelPricing(_) => "model_pricing",
            Self::Doctor(_) => "doctor",
            Self::Agents(_) => "agents",
            Self::Completions(_) => "completions",
            Self::HookForward(_) => "hook_forward",
            Self::AgentProxyService(_) => "agent_proxy_service",
        }
    }

    /// Configuration-editing commands remain available even when operational logging settings are
    /// invalid, so users can repair their configuration.
    pub(crate) fn skips_logging(&self) -> bool {
        matches!(self, Self::Config(_))
            || matches!(self, Self::Plugins(command) if command.is_edit())
    }
}
