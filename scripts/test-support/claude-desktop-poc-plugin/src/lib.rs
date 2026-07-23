// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Release-gate middleware used only by the opt-in Claude Desktop live POC.

use nemo_relay_plugin::{
    AnnotatedLlmRequest, Json, LlmRequestInterceptOutcome, NativePlugin, PluginContext,
};
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
                let annotated = if let Some(annotated) = annotated {
                    Some(rewrite_annotated_marker(annotated)?)
                } else {
                    rewrite_latest_user_marker(&mut request.content);
                    None
                };
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

fn rewrite_annotated_marker(
    annotated: AnnotatedLlmRequest,
) -> nemo_relay_plugin::Result<AnnotatedLlmRequest> {
    let mut value = serde_json::to_value(annotated)
        .map_err(|error| format!("failed to serialize the annotated live-POC request: {error}"))?;
    rewrite_latest_user_marker(&mut value);
    serde_json::from_value(value)
        .map_err(|error| format!("failed to deserialize the annotated live-POC request: {error}"))
}

fn rewrite_latest_user_marker(value: &mut Json) -> bool {
    if let Some(messages) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("messages"))
        .and_then(Json::as_array_mut)
    {
        for message in messages.iter_mut().rev() {
            let is_user = message
                .as_object()
                .and_then(|object| object.get("role"))
                .and_then(Json::as_str)
                == Some("user");
            if !is_user {
                continue;
            }
            if let Some(content) = message
                .as_object_mut()
                .and_then(|object| object.get_mut("content"))
                && rewrite_first_marker(content)
            {
                return true;
            }
        }
        return false;
    }
    rewrite_first_marker(value)
}

fn rewrite_first_marker(value: &mut Json) -> bool {
    match value {
        Json::String(text) => {
            if !text.contains(ORIGINAL_MARKER) {
                return false;
            }
            *text = text.replace(ORIGINAL_MARKER, REWRITTEN_MARKER);
            true
        }
        Json::Array(items) => items.iter_mut().rev().any(rewrite_first_marker),
        Json::Object(object) => object.values_mut().any(rewrite_first_marker),
        Json::Null | Json::Bool(_) | Json::Number(_) => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rewrite_latest_user_marker_preserves_matching_history() {
        let mut request = json!({
            "system": format!("leave {ORIGINAL_MARKER} unchanged"),
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": format!("old {ORIGINAL_MARKER}"),
                            "cache_control": {"type": "ephemeral"}
                        }
                    ]
                },
                {
                    "role": "assistant",
                    "content": "old response"
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "injected context"},
                        {
                            "type": "text",
                            "text": format!("new {ORIGINAL_MARKER}"),
                            "cache_control": {"type": "ephemeral"}
                        }
                    ]
                }
            ]
        });

        assert!(rewrite_latest_user_marker(&mut request));
        assert_eq!(
            request["system"],
            format!("leave {ORIGINAL_MARKER} unchanged")
        );
        assert_eq!(
            request["messages"][0]["content"][0]["text"],
            format!("old {ORIGINAL_MARKER}")
        );
        assert_eq!(
            request["messages"][2]["content"][1]["text"],
            format!("new {REWRITTEN_MARKER}")
        );
    }

    #[test]
    fn rewrite_latest_user_marker_is_noop_without_marker() {
        let mut request = json!({
            "messages": [{"role": "user", "content": "plain prompt"}]
        });
        let baseline = request.clone();

        assert!(!rewrite_latest_user_marker(&mut request));
        assert_eq!(request, baseline);
    }
}
