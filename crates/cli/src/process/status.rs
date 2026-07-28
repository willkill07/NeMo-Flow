// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    dead_code,
    reason = "startup rendering is retained for legacy gateway regression tests"
)]

//! Human-readable proxy startup status.

use std::path::PathBuf;

use nemo_relay::observability::plugin_component::{
    AtifStorageConfig, AtofSinkSectionConfig, OBSERVABILITY_PLUGIN_KIND, ObservabilityConfig,
};
use nemo_relay::plugin::PluginConfig;
use serde_json::Value;

use crate::configuration::GatewayConfig;

pub(crate) fn render_status_frame(lines: &[String], color: bool) -> String {
    let max_width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let inner = max_width + 2;
    let mut output = String::new();
    output.push('\n');
    push_border(&mut output, '╭', '╮', inner, color);
    for line in lines {
        let padding = max_width - line.chars().count();
        let body = format!(" {line}{} ", " ".repeat(padding));
        if color {
            output.push_str(&format!(
                "\x1b[38;5;112m│\x1b[0m{body}\x1b[38;5;112m│\x1b[0m\n"
            ));
        } else {
            output.push_str(&format!("│{body}│\n"));
        }
    }
    push_border(&mut output, '╰', '╯', inner, color);
    output.push('\n');
    output
}

pub(crate) fn exporter_destinations(config: &GatewayConfig) -> Vec<String> {
    let Some(plugin_config) = config.plugin_config.as_ref() else {
        return Vec::new();
    };
    let Ok(plugin_config) = serde_json::from_value::<PluginConfig>(plugin_config.clone()) else {
        return vec!["configured (invalid plugin config)".into()];
    };
    let Some(component) = plugin_config
        .components
        .iter()
        .find(|component| component.kind == OBSERVABILITY_PLUGIN_KIND)
    else {
        return Vec::new();
    };
    if !component.enabled {
        return Vec::new();
    }
    let Ok(observability) =
        serde_json::from_value::<ObservabilityConfig>(Value::Object(component.config.clone()))
    else {
        return vec!["Observability configured (invalid config)".into()];
    };
    observability_destinations(&observability)
}

fn observability_destinations(config: &ObservabilityConfig) -> Vec<String> {
    let mut destinations = Vec::new();
    if let Some(section) = config.atof.as_ref().filter(|section| section.enabled) {
        for sink in &section.sinks {
            match sink {
                AtofSinkSectionConfig::File(file) => {
                    let directory = file
                        .output_directory
                        .clone()
                        .unwrap_or_else(current_output_directory);
                    let path = directory.join(
                        file.filename
                            .clone()
                            .unwrap_or_else(|| "nemo-relay-events-<timestamp>.jsonl".into()),
                    );
                    destinations.push(format!("ATOF {}", path.display()));
                }
                AtofSinkSectionConfig::Stream(stream) => {
                    destinations.push(format!("ATOF {}", sanitized_url(&stream.url)));
                }
            }
        }
    }
    if let Some(section) = config.atif.as_ref().filter(|section| section.enabled) {
        if section.storage.is_empty() {
            let directory = section
                .output_directory
                .clone()
                .unwrap_or_else(current_output_directory);
            destinations.push(format!(
                "ATIF {}",
                directory.join(&section.filename_template).display()
            ));
        } else {
            for backend in &section.storage {
                destinations.push(format!("ATIF {}", atif_storage_destination(backend)));
            }
        }
    }
    if let Some(section) = config
        .opentelemetry
        .as_ref()
        .filter(|section| section.enabled)
    {
        destinations.push(format!(
            "OpenTelemetry {}",
            section
                .endpoint
                .as_deref()
                .map(sanitized_url)
                .as_deref()
                .unwrap_or("OTLP endpoint from environment/default")
        ));
    }
    if let Some(section) = config
        .openinference
        .as_ref()
        .filter(|section| section.enabled)
    {
        destinations.push(format!(
            "OpenInference {}",
            section
                .endpoint
                .as_deref()
                .map(sanitized_url)
                .as_deref()
                .unwrap_or("OTLP endpoint from environment/default")
        ));
    }
    destinations
}

fn atif_storage_destination(storage: &AtifStorageConfig) -> String {
    match storage {
        AtifStorageConfig::Http(http) => sanitized_url(&http.endpoint),
        AtifStorageConfig::S3(s3) => {
            let prefix = s3.key_prefix.as_deref().unwrap_or("").trim_matches('/');
            if prefix.is_empty() {
                format!("s3://{}", s3.bucket)
            } else {
                format!("s3://{}/{prefix}", s3.bucket)
            }
        }
    }
}

fn sanitized_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return "configured endpoint".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    if url.query().is_some() {
        let keys = url
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .collect::<Vec<_>>();
        url.set_query(None);
        if !keys.is_empty() {
            let mut query = url.query_pairs_mut();
            for key in keys {
                query.append_pair(&key, "[REDACTED]");
            }
        }
    }
    url.to_string()
}

fn current_output_directory() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn push_border(output: &mut String, left: char, right: char, inner: usize, color: bool) {
    if color {
        output.push_str(&format!(
            "\x1b[38;5;112m{left}{}{right}\x1b[0m\n",
            "─".repeat(inner)
        ));
    } else {
        output.push(left);
        output.push_str(&"─".repeat(inner));
        output.push(right);
        output.push('\n');
    }
}
