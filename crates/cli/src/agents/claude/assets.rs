// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

pub(crate) fn marketplace_manifest(marketplace: &str, plugin: &str) -> Value {
    json!({
        "name": marketplace,
        "metadata": { "description": "Local NeMo Relay plugins for Claude Code." },
        "owner": { "name": "NVIDIA Corporation and Affiliates", "email": "noreply@nvidia.com" },
        "plugins": [{
            "name": plugin,
            "description": "Use the unified Relay proxy and capture Claude Code lifecycle events.",
            "source": "./plugins/nemo-relay-plugin",
            "category": "development"
        }]
    })
}

pub(crate) fn plugin_manifest(plugin: &str) -> Value {
    json!({
        "name": plugin,
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Preview integration for Relay proxy enrollment and Claude Code lifecycle hooks.",
        "author": { "name": "NVIDIA Corporation and Affiliates", "url": "https://github.com/NVIDIA/NeMo-Relay" },
        "homepage": "https://github.com/NVIDIA/NeMo-Relay",
        "repository": "https://github.com/NVIDIA/NeMo-Relay",
        "license": "Apache-2.0",
        "keywords": ["nemo-relay", "claude-code", "hooks", "observability"]
    })
}
