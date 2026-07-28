// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use clap::Args;

use crate::error::CliError;
use crate::plugins::{ConfigurationScope, PluginsEditRequest};

#[derive(Debug, Clone, Default, Args)]
pub(crate) struct ConfigCommand {
    /// Edit system-wide plugin policy instead of the default per-user policy.
    #[arg(long)]
    pub(crate) system: bool,
}

pub(super) async fn execute(command: ConfigCommand) -> Result<ExitCode, CliError> {
    let scope = if command.system {
        ConfigurationScope::Global
    } else {
        ConfigurationScope::User
    };
    crate::plugins::edit(PluginsEditRequest { scope })?;
    Ok(ExitCode::SUCCESS)
}
