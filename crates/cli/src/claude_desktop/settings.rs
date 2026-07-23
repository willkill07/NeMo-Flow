// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Field-level Claude settings migration and corporate-proxy preservation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const RELAY_BASE_URLS: [&str; 2] = [crate::bootstrap::DEFAULT_URL, "http://localhost:47632"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct UpstreamProxy {
    /// The URL is secret-bearing when Basic authentication is configured. The containing state
    /// file is always owner-only and diagnostics use [`Self::redacted_url`].
    pub(super) url: String,
    pub(super) no_proxy: Option<String>,
    /// Linux carries an existing Claude-scoped CA bundle into the sidecar so an HTTPS
    /// corporate proxy signed by that CA remains reachable. macOS and Windows use their
    /// current-user trust stores instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ca_bundle: Option<PathBuf>,
}

impl UpstreamProxy {
    pub(super) fn redacted_url(&self) -> String {
        let Ok(mut url) = reqwest::Url::parse(&self.url) else {
            return "<invalid>".into();
        };
        if !url.username().is_empty() {
            let _ = url.set_username("***");
        }
        if url.password().is_some() {
            let _ = url.set_password(Some("***"));
        }
        url.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct FieldPatch {
    pub(super) previous: Option<Value>,
    pub(super) installed: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct SettingsPatch {
    pub(super) settings_path: PathBuf,
    pub(super) original_settings_absent: bool,
    pub(super) fields: BTreeMap<String, FieldPatch>,
    #[serde(default)]
    pub(super) previous_permissions: Option<SettingsPermissions>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct SettingsPermissions {
    pub(super) unix_mode: Option<u32>,
    pub(super) windows_dacl: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct PreparedSettings {
    pub(super) value: Value,
    pub(super) patch: SettingsPatch,
    pub(super) upstream_proxy: Option<UpstreamProxy>,
}

pub(super) fn prepare(
    path: &Path,
    proxy_url: &str,
    state_path: &Path,
    root_pem: &Path,
    platform: &str,
    prior_upstream: Option<&UpstreamProxy>,
) -> Result<PreparedSettings, String> {
    let process_env = process_proxy_environment()?;
    prepare_with_process_env(
        path,
        proxy_url,
        state_path,
        root_pem,
        platform,
        prior_upstream,
        &process_env,
    )
}

fn prepare_with_process_env(
    path: &Path,
    proxy_url: &str,
    state_path: &Path,
    root_pem: &Path,
    platform: &str,
    prior_upstream: Option<&UpstreamProxy>,
    process_env: &Map<String, Value>,
) -> Result<PreparedSettings, String> {
    let original_settings_absent = !path.exists();
    let previous_permissions = capture_permissions(path)?;
    let mut value = crate::agents::shared::host::read_json_object(path)?;
    let original_env = env_object(&value)?.cloned().unwrap_or_default();
    let mut upstream_proxy =
        resolve_upstream_proxy(&original_env, process_env, proxy_url, prior_upstream)?;
    if let Some(base_url) = unique_case_insensitive_string(process_env, "ANTHROPIC_BASE_URL")? {
        return Err(format!(
            "the installer inherited ANTHROPIC_BASE_URL={base_url:?}; unset it before installing Claude Desktop protection so terminal Claude Code cannot bypass TLS interception"
        ));
    }
    let mut desired = original_env.clone();
    let mut touched = BTreeSet::new();

    remove_case_insensitive(&mut desired, "HTTPS_PROXY", &mut touched);
    for key in case_insensitive_keys(process_env, "HTTPS_PROXY") {
        desired.insert(key.clone(), Value::String(proxy_url.into()));
        touched.insert(key);
    }
    desired.insert("HTTPS_PROXY".into(), Value::String(proxy_url.into()));
    touched.insert("HTTPS_PROXY".into());

    remove_case_insensitive(&mut desired, "NEMO_RELAY_FAIL_CLOSED", &mut touched);
    desired.insert("NEMO_RELAY_FAIL_CLOSED".into(), Value::String("1".into()));
    touched.insert("NEMO_RELAY_FAIL_CLOSED".into());

    remove_case_insensitive(
        &mut desired,
        "NEMO_RELAY_CLAUDE_DESKTOP_STATE",
        &mut touched,
    );
    desired.insert(
        "NEMO_RELAY_CLAUDE_DESKTOP_STATE".into(),
        Value::String(state_path.display().to_string()),
    );
    touched.insert("NEMO_RELAY_CLAUDE_DESKTOP_STATE".into());

    let base_url_keys = case_insensitive_keys(&desired, "ANTHROPIC_BASE_URL");
    for key in base_url_keys {
        let current = desired.get(&key).and_then(Value::as_str).ok_or_else(|| {
            format!("Claude setting env.{key} must be a string before Relay can manage it")
        })?;
        if !RELAY_BASE_URLS
            .iter()
            .any(|managed| current.trim_end_matches('/') == managed.trim_end_matches('/'))
        {
            return Err(format!(
                "Claude setting env.{key} points at custom Anthropic gateway {current:?}; remove it or use the direct gateway integration instead"
            ));
        }
        desired.remove(&key);
        touched.insert(key);
    }
    touched.insert("ANTHROPIC_BASE_URL".into());

    let no_proxy = layered_environment_string(&original_env, process_env, "NO_PROXY")?;
    let existing_custom_ca =
        layered_environment_string(&original_env, process_env, "NODE_EXTRA_CA_CERTS")?;
    remove_case_insensitive(&mut desired, "NO_PROXY", &mut touched);
    let sanitized_no_proxy = no_proxy
        .as_deref()
        .map(sanitize_no_proxy)
        .unwrap_or_default();
    for key in case_insensitive_keys(process_env, "NO_PROXY") {
        desired.insert(key.clone(), Value::String(sanitized_no_proxy.clone()));
        touched.insert(key);
    }
    desired.insert("NO_PROXY".into(), Value::String(sanitized_no_proxy));
    touched.insert("NO_PROXY".into());

    match platform {
        "linux" => {
            remove_case_insensitive(&mut desired, "NODE_EXTRA_CA_CERTS", &mut touched);
            desired.insert(
                "NODE_EXTRA_CA_CERTS".into(),
                Value::String(root_pem.display().to_string()),
            );
            touched.insert("NODE_EXTRA_CA_CERTS".into());
            if let Some(proxy) = upstream_proxy.as_mut() {
                proxy.ca_bundle = Some(root_pem.to_path_buf());
            }
        }
        "macos" | "windows" => {
            remove_case_insensitive(&mut desired, "CLAUDE_CODE_CERT_STORE", &mut touched);
            desired.insert(
                "CLAUDE_CODE_CERT_STORE".into(),
                Value::String("bundled,system".into()),
            );
            touched.insert("CLAUDE_CODE_CERT_STORE".into());
            if let (Some(proxy), Some(custom_ca)) =
                (upstream_proxy.as_mut(), existing_custom_ca.as_deref())
            {
                proxy.ca_bundle = Some(resolve_ca_bundle(custom_ca)?);
            }
        }
        other => return Err(format!("unsupported Claude Desktop platform {other}")),
    }

    set_env_object(&mut value, desired.clone())?;
    let fields = touched
        .into_iter()
        .map(|key| {
            let previous = original_env.get(&key).cloned();
            let installed = desired.get(&key).cloned();
            (
                key,
                FieldPatch {
                    previous,
                    installed,
                },
            )
        })
        .collect();
    Ok(PreparedSettings {
        value,
        patch: SettingsPatch {
            settings_path: path.to_path_buf(),
            original_settings_absent,
            fields,
            previous_permissions,
        },
        upstream_proxy,
    })
}

pub(super) fn apply(prepared: &PreparedSettings) -> Result<(), String> {
    write_private_json(&prepared.patch.settings_path, &prepared.value)
}

/// Restore only fields that still equal the value installed by Relay. Unrelated keys and
/// concurrent edits are retained.
pub(super) fn restore(patch: &SettingsPatch) -> Result<Vec<String>, String> {
    let mut value = crate::agents::shared::host::read_json_object(&patch.settings_path)?;
    let mut env = env_object(&value)?.cloned().unwrap_or_default();
    let mut retained_edits = Vec::new();
    for (key, field) in &patch.fields {
        let current = env.get(key).cloned();
        if current != field.installed {
            retained_edits.push(key.clone());
            continue;
        }
        match &field.previous {
            Some(previous) => {
                env.insert(key.clone(), previous.clone());
            }
            None => {
                env.remove(key);
            }
        }
    }
    set_env_object(&mut value, env)?;
    if patch.original_settings_absent && value.as_object().is_some_and(serde_json::Map::is_empty) {
        match std::fs::remove_file(&patch.settings_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to remove {}: {error}",
                    patch.settings_path.display()
                ));
            }
        }
    } else {
        write_with_previous_permissions(
            &patch.settings_path,
            &value,
            patch.previous_permissions.as_ref(),
        )?;
    }
    Ok(retained_edits)
}

pub(super) fn matches(patch: &SettingsPatch) -> Result<(), String> {
    let value = crate::agents::shared::host::read_json_object(&patch.settings_path)?;
    let env = env_object(&value)?.cloned().unwrap_or_default();
    let mismatches = patch
        .fields
        .iter()
        .filter(|(key, field)| env.get(*key).cloned() != field.installed)
        .map(|(key, _)| format!("env.{key}"))
        .collect::<Vec<_>>();
    if !mismatches.is_empty() {
        return Err(format!(
            "Claude settings differ from the installed protection at {}; mismatched {}",
            patch.settings_path.display(),
            mismatches.join(", ")
        ));
    }
    validate_environment_policy(&env, patch)?;
    settings_file_is_private(&patch.settings_path)
}

pub(super) fn effective_state_path() -> Result<Option<PathBuf>, String> {
    Ok(unique_case_insensitive_string(
        &process_environment(&["NEMO_RELAY_CLAUDE_DESKTOP_STATE"])?,
        "NEMO_RELAY_CLAUDE_DESKTOP_STATE",
    )?
    .map(PathBuf::from))
}

pub(super) fn effective_environment_matches(patch: &SettingsPatch) -> Result<(), String> {
    let env = process_environment(&[
        "HTTPS_PROXY",
        "NO_PROXY",
        "ANTHROPIC_BASE_URL",
        "NEMO_RELAY_FAIL_CLOSED",
        "NEMO_RELAY_CLAUDE_DESKTOP_STATE",
        "NODE_EXTRA_CA_CERTS",
        "CLAUDE_CODE_CERT_STORE",
    ])?;
    validate_environment_policy(&env, patch)
}

pub(super) fn apply_installed(patch: &SettingsPatch) -> Result<(), String> {
    let mut value = crate::agents::shared::host::read_json_object(&patch.settings_path)?;
    let mut env = env_object(&value)?.cloned().unwrap_or_default();
    for (key, field) in &patch.fields {
        match &field.installed {
            Some(installed) => {
                env.insert(key.clone(), installed.clone());
            }
            None => {
                env.remove(key);
            }
        }
    }
    set_env_object(&mut value, env)?;
    write_private_json(&patch.settings_path, &value)
}

pub(super) fn compose_linux_ca_bundle(
    destination: &Path,
    root_pem: &str,
    existing: Option<&str>,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    if let Some(existing) = existing.filter(|value| !value.trim().is_empty()) {
        let existing_path = resolve_ca_bundle(existing)?;
        bytes.extend(crate::filesystem::bounded::read_bounded_regular_file(
            &existing_path,
            "existing NODE_EXTRA_CA_CERTS bundle",
        )?);
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
    }
    bytes.extend_from_slice(root_pem.as_bytes());
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    crate::filesystem::atomic_write(destination, &bytes)
}

pub(super) fn existing_env_string(path: &Path, name: &str) -> Result<Option<String>, String> {
    let value = crate::agents::shared::host::read_json_object(path)?;
    let env = env_object(&value)?.cloned().unwrap_or_default();
    layered_environment_string(&env, &process_environment(&[name])?, name)
}

fn resolve_upstream_proxy(
    env: &Map<String, Value>,
    process_env: &Map<String, Value>,
    relay_proxy_url: &str,
    prior_upstream: Option<&UpstreamProxy>,
) -> Result<Option<UpstreamProxy>, String> {
    for deferred in ["PROXY_PAC_URL", "AUTO_PROXY_URL"] {
        if unique_case_insensitive_string(env, deferred)?.is_some()
            || unique_case_insensitive_string(process_env, deferred)?.is_some()
        {
            return Err(format!(
                "{deferred} is configured, but PAC/automatic proxy discovery is not supported by Claude Desktop wrapping"
            ));
        }
    }
    let settings_https = unique_case_insensitive_string(env, "HTTPS_PROXY")?;
    if settings_https.as_deref() == Some(relay_proxy_url) {
        return Ok(prior_upstream.cloned());
    }
    let https = merge_environment_values(
        settings_https,
        unique_case_insensitive_string(process_env, "HTTPS_PROXY")?,
        "HTTPS_PROXY",
    )?;
    if https.as_deref() == Some(relay_proxy_url) {
        return Ok(prior_upstream.cloned());
    }
    let all = layered_environment_string(env, process_env, "ALL_PROXY")?;
    let http = layered_environment_string(env, process_env, "HTTP_PROXY")?;
    let selected = select_proxy_value(https, all, http)?;
    let no_proxy = layered_environment_string(env, process_env, "NO_PROXY")?;
    selected
        .map(|url| validate_upstream_proxy(&url, no_proxy))
        .transpose()
}

fn layered_environment_string(
    settings: &Map<String, Value>,
    process: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    merge_environment_values(
        unique_case_insensitive_string(settings, name)?,
        unique_case_insensitive_string(process, name)?,
        name,
    )
}

fn merge_environment_values(
    settings: Option<String>,
    process: Option<String>,
    name: &str,
) -> Result<Option<String>, String> {
    match (settings, process) {
        (Some(settings), Some(process)) if settings != process => Err(format!(
            "Claude settings and the installer process contain conflicting {name} definitions; make them identical or keep only one before installing Desktop protection"
        )),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn select_proxy_value(
    https: Option<String>,
    all: Option<String>,
    http: Option<String>,
) -> Result<Option<String>, String> {
    if https.is_some() {
        return Ok(https);
    }
    match (&all, &http) {
        (Some(all), Some(http)) if all != http => Err(
            "ALL_PROXY and HTTP_PROXY conflict without an explicit HTTPS_PROXY; keep one route or set HTTPS_PROXY before installing Desktop protection"
                .into(),
        ),
        _ => Ok(all.or(http)),
    }
}

fn process_proxy_environment() -> Result<Map<String, Value>, String> {
    const RELEVANT: [&str; 8] = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PROXY_PAC_URL",
        "AUTO_PROXY_URL",
        "ANTHROPIC_BASE_URL",
        "NODE_EXTRA_CA_CERTS",
    ];
    process_environment(&RELEVANT)
}

fn resolve_ca_bundle(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!(
            "NODE_EXTRA_CA_CERTS must be an absolute path for the persistent Claude Desktop service, got {raw:?}"
        ));
    }
    let resolved = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve NODE_EXTRA_CA_CERTS {raw:?}: {error}"))?;
    if !resolved.is_file() {
        return Err(format!(
            "NODE_EXTRA_CA_CERTS {} must resolve to a regular file",
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn process_environment(names: &[&str]) -> Result<Map<String, Value>, String> {
    std::env::vars_os()
        .filter(|(key, _)| {
            names
                .iter()
                .any(|name| key.to_string_lossy().eq_ignore_ascii_case(name))
        })
        .map(|(key, value)| {
            let key = key
                .into_string()
                .map_err(|_| "process proxy environment name is not valid Unicode".to_string())?;
            let value = value
                .into_string()
                .map_err(|_| format!("process environment {key} is not valid Unicode"))?;
            Ok((key, Value::String(value)))
        })
        .collect()
}

fn validate_environment_policy(
    env: &Map<String, Value>,
    patch: &SettingsPatch,
) -> Result<(), String> {
    for name in [
        "HTTPS_PROXY",
        "NO_PROXY",
        "NEMO_RELAY_FAIL_CLOSED",
        "NEMO_RELAY_CLAUDE_DESKTOP_STATE",
        "NODE_EXTRA_CA_CERTS",
        "CLAUDE_CODE_CERT_STORE",
    ] {
        let Some(expected) = patch
            .fields
            .get(name)
            .and_then(|field| field.installed.as_ref())
            .and_then(Value::as_str)
        else {
            continue;
        };
        let actual = unique_case_insensitive_string(env, name)?;
        if actual.as_deref() != Some(expected) {
            return Err(format!(
                "effective Claude environment {name} differs from the installed protection"
            ));
        }
    }
    if unique_case_insensitive_string(env, "ANTHROPIC_BASE_URL")?.is_some() {
        return Err("effective Claude ANTHROPIC_BASE_URL bypasses Desktop TLS interception".into());
    }
    if let Some(no_proxy) = unique_case_insensitive_string(env, "NO_PROXY")?
        && sanitize_no_proxy(&no_proxy) != no_proxy
    {
        return Err("effective Claude NO_PROXY bypasses api.anthropic.com".into());
    }
    Ok(())
}

pub(super) fn validate_upstream_proxy(
    raw: &str,
    no_proxy: Option<String>,
) -> Result<UpstreamProxy, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|error| format!("invalid corporate proxy URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "unsupported corporate proxy scheme {:?}; Claude Desktop wrapping currently supports explicit HTTP(S) proxies with optional Basic authentication, not SOCKS, PAC, NTLM, or Kerberos",
            url.scheme()
        ));
    }
    if url.host_str().is_none()
        || url.port_or_known_default().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "corporate proxy URL {} must contain only an HTTP(S) authority and optional Basic credentials",
            redacted_proxy_url(&url)
        ));
    }
    Ok(UpstreamProxy {
        url: url.to_string(),
        no_proxy: no_proxy.filter(|value| !value.trim().is_empty()),
        ca_bundle: None,
    })
}

pub(super) fn sanitize_no_proxy(raw: &str) -> String {
    no_proxy_entries(raw)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter(|entry| !bypasses_anthropic(entry))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn normalize_no_proxy(raw: &str) -> String {
    no_proxy_entries(raw)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn no_proxy_entries(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(|character: char| character == ',' || character.is_ascii_whitespace())
}

fn bypasses_anthropic(entry: &str) -> bool {
    let (entry, port) = entry
        .rsplit_once(':')
        .map_or((entry, None), |(host, port)| {
            if port.chars().all(|character| character.is_ascii_digit()) {
                (host, port.parse::<u16>().ok())
            } else {
                (entry, None)
            }
        });
    if port.is_some_and(|port| port != 443) {
        return false;
    }
    let host = entry
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == "*"
        || super::certificate::INTERCEPTED_HOST.eq_ignore_ascii_case(&host)
        || super::certificate::INTERCEPTED_HOST.ends_with(&format!(".{host}"))
}

fn redacted_proxy_url(url: &reqwest::Url) -> String {
    let mut redacted = url.clone();
    if !redacted.username().is_empty() {
        let _ = redacted.set_username("***");
    }
    if redacted.password().is_some() {
        let _ = redacted.set_password(Some("***"));
    }
    redacted.to_string()
}

fn env_object(value: &Value) -> Result<Option<&Map<String, Value>>, String> {
    match value.get("env") {
        Some(Value::Object(env)) => Ok(Some(env)),
        Some(_) => Err("Claude settings env field must be a JSON object".into()),
        None => Ok(None),
    }
}

fn set_env_object(value: &mut Value, env: Map<String, Value>) -> Result<(), String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Claude settings must be a JSON object".to_string())?;
    if env.is_empty() {
        object.remove("env");
    } else {
        object.insert("env".into(), Value::Object(env));
    }
    Ok(())
}

fn capture_permissions(path: &Path) -> Result<Option<SettingsPermissions>, String> {
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
            .permissions()
            .mode()
            & 0o7777;
        return Ok(Some(SettingsPermissions {
            unix_mode: Some(mode),
            windows_dacl: None,
        }));
    }
    #[cfg(windows)]
    {
        let dacl = crate::filesystem::read_windows_dacl(path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        return Ok(Some(SettingsPermissions {
            unix_mode: None,
            windows_dacl: Some(dacl),
        }));
    }
    #[allow(unreachable_code)]
    Ok(Some(SettingsPermissions::default()))
}

fn settings_file_is_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "Claude settings {} expose the Relay proxy credential outside the owner (mode {:o})",
                path.display(),
                mode & 0o777
            ));
        }
    }
    #[cfg(windows)]
    if !crate::filesystem::windows_path_is_private(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
    {
        return Err(format!(
            "Claude settings {} do not have an owner-only ACL",
            path.display()
        ));
    }
    Ok(())
}

fn write_private_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    crate::filesystem::atomic_write_private(path, &bytes)
}

fn write_with_previous_permissions(
    path: &Path,
    value: &Value,
    permissions: Option<&SettingsPermissions>,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    #[cfg(unix)]
    if let Some(mode) = permissions.and_then(|permissions| permissions.unix_mode) {
        use std::os::unix::fs::PermissionsExt;

        return crate::filesystem::atomic_write_with_permissions(
            path,
            &bytes,
            Some(&std::fs::Permissions::from_mode(mode)),
        );
    }
    #[cfg(windows)]
    if let Some(dacl) = permissions.and_then(|permissions| permissions.windows_dacl.as_deref()) {
        return crate::filesystem::atomic_write_with_windows_dacl(path, &bytes, dacl);
    }
    crate::filesystem::atomic_write(path, &bytes)
}

fn case_insensitive_keys(env: &Map<String, Value>, name: &str) -> Vec<String> {
    env.keys()
        .filter(|key| key.eq_ignore_ascii_case(name))
        .cloned()
        .collect()
}

fn remove_case_insensitive(
    env: &mut Map<String, Value>,
    name: &str,
    touched: &mut BTreeSet<String>,
) {
    for key in case_insensitive_keys(env, name) {
        env.remove(&key);
        touched.insert(key);
    }
}

fn unique_case_insensitive_string(
    env: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    let values = case_insensitive_keys(env, name)
        .into_iter()
        .map(|key| {
            env.get(&key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("Claude setting env.{key} must be a string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if values.len() > 1 {
        return Err(format!(
            "conflicting case variants of {name} are ambiguous; keep one explicit value before installing Claude Desktop protection"
        ));
    }
    Ok(values.into_iter().next())
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/settings_tests.rs"]
mod tests;
