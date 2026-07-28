// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Clone, Default, Args)]
pub(crate) struct ServerArgs {
    /// Explicit config path for `plugins` only.
    #[arg(long)]
    pub(super) config: Option<PathBuf>,
    /// Address for the gateway to listen on in daemon mode (default 127.0.0.1:4040)
    #[arg(long, hide = true)]
    pub(super) bind: Option<SocketAddr>,
    /// Upstream OpenAI-compatible base URL (e.g. https://api.openai.com/v1, NVIDIA inference)
    #[arg(long, hide = true)]
    pub(super) openai_base_url: Option<String>,
    /// Upstream Anthropic base URL (e.g. https://api.anthropic.com)
    #[arg(long, hide = true)]
    pub(super) anthropic_base_url: Option<String>,
    /// Internal override for the plugin configuration file.
    #[arg(long, hide = true)]
    pub(super) plugin_config_path: Option<PathBuf>,
    /// Retired gateway-child readiness file, accepted only to emit a migration error.
    #[arg(long, hide = true)]
    pub(super) ready_file: Option<PathBuf>,
    /// Maximum accepted coding-agent hook payload size, in bytes.
    #[arg(long, hide = true)]
    pub(super) max_hook_payload_bytes: Option<usize>,
    /// Maximum accepted provider passthrough request body size, in bytes.
    #[arg(long, hide = true)]
    pub(super) max_passthrough_body_bytes: Option<usize>,
}

impl ServerArgs {
    pub(super) fn has_overrides(&self) -> bool {
        self.config.is_some()
            || self.bind.is_some()
            || self.openai_base_url.is_some()
            || self.anthropic_base_url.is_some()
            || self.plugin_config_path.is_some()
            || self.ready_file.is_some()
            || self.max_hook_payload_bytes.is_some()
            || self.max_passthrough_body_bytes.is_some()
    }

    pub(super) fn to_runtime(&self) -> crate::server::GatewayOverrides {
        crate::server::GatewayOverrides {
            config: self.config.clone(),
            bind: self.bind,
            openai_base_url: self.openai_base_url.clone(),
            anthropic_base_url: self.anthropic_base_url.clone(),
            plugin_config_path: self.plugin_config_path.clone(),
            ready_file: self.ready_file.clone(),
            max_hook_payload_bytes: self.max_hook_payload_bytes,
            max_passthrough_body_bytes: self.max_passthrough_body_bytes,
        }
    }
}
