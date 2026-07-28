// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Feature-gated command syntax for the repository integration-test server binary.

use std::process::ExitCode;

use clap::Parser;

use crate::error::CliError;

#[derive(Parser)]
#[command(name = "nemo-relay-internal-managed-server")]
struct Args {
    #[arg(long)]
    config: std::path::PathBuf,
    #[arg(long)]
    bind: std::net::SocketAddr,
}

pub(crate) fn run() -> Result<ExitCode, CliError> {
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::Config(format!(
                "failed to initialize internal test runtime: {error}"
            ))
        })?;
    runtime.block_on(async move {
        let overrides = crate::server::GatewayOverrides {
            config: Some(args.config),
            bind: Some(args.bind),
            ..Default::default()
        };
        let resolved = crate::configuration::resolve_server_config(&overrides)?;
        let dynamic_plugins = crate::plugins::lifecycle::active_dynamic_plugin_components(
            overrides.config.as_ref(),
            &resolved,
        )?;
        crate::server::serve_internal_test_harness(resolved.gateway, dynamic_plugins).await
    })?;
    Ok(ExitCode::SUCCESS)
}
