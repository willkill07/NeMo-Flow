// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Release-gate middleware used only by the opt-in Claude Desktop live POC.

use nemo_relay_plugin::{Json, LlmRequestInterceptOutcome, NativePlugin, PluginContext};
use serde_json::Map;

const ORIGINAL_MARKER: &str = "NEMO_RELAY_POC_ORIGINAL_7F3A";
const REWRITTEN_MARKER: &str = "NEMO_RELAY_POC_REWRITTEN_91C4";
const TOOL_SENTINEL: &str = "NEMO_RELAY_CLAUDE_DESKTOP_POC_SENTINEL";

struct ClaudeDesktopPocPlugin;

impl NativePlugin for ClaudeDesktopPocPlugin {
    fn plugin_kind(&self) -> &str {
        "tests.claude_desktop_live_poc"
    }

    fn allows_multiple_components(&self) -> bool {
        false
    }

    fn register(
        &mut self,
        _plugin_config: &Map<String, Json>,
        context: &mut PluginContext<'_>,
    ) -> nemo_relay_plugin::Result<()> {
        context.register_llm_request_intercept(
            "rewrite_live_poc_marker",
            1,
            false,
            |_name, mut request, annotated| {
                rewrite_markers(&mut request.content);
                Ok(LlmRequestInterceptOutcome::new(request, annotated))
            },
        )?;
        context.register_tool_conditional_execution_guardrail(
            "block_live_poc_sentinel",
            1,
            |_name, arguments| {
                Ok(contains_sentinel(&arguments)
                    .then(|| "blocked the Claude Desktop live-POC sentinel tool call".to_string()))
            },
        )?;
        Ok(())
    }
}

fn rewrite_markers(value: &mut Json) {
    match value {
        Json::String(text) => {
            *text = text.replace(ORIGINAL_MARKER, REWRITTEN_MARKER);
        }
        Json::Array(items) => {
            for item in items {
                rewrite_markers(item);
            }
        }
        Json::Object(object) => {
            for item in object.values_mut() {
                rewrite_markers(item);
            }
        }
        Json::Null | Json::Bool(_) | Json::Number(_) => {}
    }
}

fn contains_sentinel(value: &Json) -> bool {
    match value {
        Json::String(text) => text.contains(TOOL_SENTINEL),
        Json::Array(items) => items.iter().any(contains_sentinel),
        Json::Object(object) => object.values().any(contains_sentinel),
        Json::Null | Json::Bool(_) | Json::Number(_) => false,
    }
}

nemo_relay_plugin::nemo_relay_plugin!(nemo_relay_register_plugin, || ClaudeDesktopPocPlugin);
