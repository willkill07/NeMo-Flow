// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

pub(crate) fn marketplace_manifest(marketplace: &str, plugin: &str) -> Value {
    json!({
        "name": marketplace,
        "interface": { "displayName": "NeMo Relay Local" },
        "plugins": [{
            "name": plugin,
            "source": { "source": "local", "path": "./plugins/nemo-relay-plugin" },
            "policy": { "installation": "AVAILABLE", "authentication": "ON_INSTALL" },
            "category": "Coding"
        }]
    })
}

pub(crate) fn plugin_manifest(plugin: &str) -> Value {
    json!({
        "name": plugin,
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Preview integration for Relay proxy enrollment, Codex hooks, and managed Responses traffic.",
        "author": { "name": "NVIDIA Corporation and Affiliates", "url": "https://github.com/NVIDIA/NeMo-Relay" },
        "homepage": "https://github.com/NVIDIA/NeMo-Relay",
        "repository": "https://github.com/NVIDIA/NeMo-Relay",
        "license": "Apache-2.0",
        "keywords": ["nemo-relay", "codex", "hooks", "observability"],
        "interface": {
            "displayName": "NeMo Relay Plugin",
            "shortDescription": "Use the Relay agent proxy and capture Codex lifecycle events.",
            "longDescription": "Routes Codex model traffic through the enrolled per-user Relay proxy and installs command hooks that preserve canonical Codex lifecycle payloads.",
            "developerName": "NVIDIA",
            "category": "Coding",
            "capabilities": ["Read"],
            "defaultPrompt": ["Capture this Codex session with NeMo Relay observability."],
            "websiteURL": "https://github.com/NVIDIA/NeMo-Relay",
            "brandColor": "#76B900"
        }
    })
}
