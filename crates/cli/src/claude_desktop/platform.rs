// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform adapters for Claude application identity, login services, trust, and deep links.

use std::path::{Path, PathBuf};

use crate::installation::marketplace::host::{CommandRunner, RealCommandRunner};

use super::state::{CertificateState, DesktopState};

pub(super) const MACOS_SERVICE_LABEL: &str = "com.nvidia.nemo-relay.claude-desktop";
pub(super) const WINDOWS_TASK_NAME: &str = "NeMo Relay Claude Desktop";
pub(super) const LINUX_SERVICE_NAME: &str = "nemo-relay-claude-desktop.service";
const WINDOWS_PROCESS_QUERY: &str = "$names = @('Claude.exe','claude-code.exe','ClaudeCode.exe'); Get-CimInstance Win32_Process | Where-Object { $_.Name -in $names -or ($_.Name -eq 'node.exe' -and $_.CommandLine -match '(@anthropic-ai[\\\\/]claude-code[\\\\/]|claude-code[\\\\/]cli\\.js)') } | ForEach-Object { if ($_.Name -eq 'node.exe') { 'Claude Code (Node.js)' } else { $_.Name } }";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Platform {
    MacOs,
    Windows,
    Linux,
}

impl Platform {
    pub(super) fn current() -> Result<Self, String> {
        match std::env::consts::OS {
            "macos" => Ok(Self::MacOs),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            other => Err(format!(
                "Claude Desktop wrapping is supported only on macOS, Windows, Ubuntu, and Debian; current platform is {other}"
            )),
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "macos" => Ok(Self::MacOs),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            other => Err(format!("invalid Claude Desktop platform in state: {other}")),
        }
    }
}

pub(super) fn validate_supported_platform(platform: Platform) -> Result<String, String> {
    validate_supported_platform_with(platform, &RealCommandRunner)
}

fn validate_supported_platform_with(
    platform: Platform,
    runner: &dyn CommandRunner,
) -> Result<String, String> {
    match platform {
        Platform::MacOs => validate_macos_version(runner),
        Platform::Windows => validate_windows_version(runner),
        Platform::Linux => validate_linux_platform(runner),
    }
}

pub(super) fn application_identity(platform: Platform) -> Result<String, String> {
    application_identity_with(platform, &RealCommandRunner)
}

fn application_identity_with(
    platform: Platform,
    runner: &dyn CommandRunner,
) -> Result<String, String> {
    match platform {
        Platform::MacOs => macos_application_identity(runner),
        Platform::Windows => windows_application_identity(runner),
        Platform::Linux => linux_application_identity(runner),
    }
}

pub(super) fn active_claude_processes(platform: Platform) -> Result<Vec<String>, String> {
    active_claude_processes_with(platform, &RealCommandRunner)
}

fn active_claude_processes_with(
    platform: Platform,
    runner: &dyn CommandRunner,
) -> Result<Vec<String>, String> {
    match platform {
        Platform::Windows => active_windows_processes(runner),
        Platform::MacOs | Platform::Linux => active_unix_processes(runner),
    }
}

pub(super) fn service_definition_path(
    platform: Platform,
    install_root: &Path,
) -> Result<PathBuf, String> {
    let home = crate::agents::shared::host::home_dir()?;
    Ok(match platform {
        Platform::MacOs => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{MACOS_SERVICE_LABEL}.plist")),
        Platform::Windows => install_root.join("claude-desktop-task.xml"),
        Platform::Linux => std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("systemd")
            .join("user")
            .join(LINUX_SERVICE_NAME),
    })
}

pub(super) fn ensure_no_foreign_service(
    platform: Platform,
    install_root: &Path,
) -> Result<(), String> {
    ensure_no_foreign_service_with(platform, install_root, &RealCommandRunner)
}

fn ensure_no_foreign_service_with(
    platform: Platform,
    install_root: &Path,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    let definition = service_definition_path(platform, install_root)?;
    if definition.exists() {
        return Err(format!(
            "refusing to overwrite unowned Claude Desktop service definition {}; remove it explicitly before installing",
            definition.display()
        ));
    }
    if service_registration_status(platform, None, runner).is_ok() {
        return Err(format!(
            "refusing to replace an unowned {} login service; remove it explicitly before installing",
            platform.as_str()
        ));
    }
    Ok(())
}

pub(super) fn render_service_definition(
    platform: Platform,
    relay: &Path,
    state_path: &Path,
    install_root: &Path,
    windows_principal: Option<&str>,
) -> Result<String, String> {
    match platform {
        Platform::MacOs => Ok(render_launch_agent(relay, state_path, install_root)),
        Platform::Windows => Ok(render_scheduled_task(
            relay,
            state_path,
            windows_principal.unwrap_or("CURRENT_USER"),
        )),
        Platform::Linux => render_systemd_unit(relay, state_path),
    }
}

pub(super) fn register_service(state: &DesktopState, dry_run: bool) -> Result<(), String> {
    register_service_with(state, dry_run, &RealCommandRunner)
}

fn register_service_with(
    state: &DesktopState,
    dry_run: bool,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    let platform = Platform::parse(&state.platform)?;
    let definition_path = service_definition_path(platform, &state.install_root)?;
    let principal = windows_principal();
    let definition = render_service_definition(
        platform,
        &state.relay_binary,
        &state.state_path(),
        &state.install_root,
        principal.as_deref(),
    )?;
    if dry_run {
        println!("write {}", definition_path.display());
        println!("register {} login service", state.platform);
        return Ok(());
    }
    crate::filesystem::atomic_write(&definition_path, definition.as_bytes())?;
    match platform {
        Platform::MacOs => {
            let domain = launchctl_domain();
            let _ = run_status(
                runner,
                "launchctl",
                &["bootout", &domain, path_text(&definition_path)?],
            );
            run_checked(
                runner,
                "launchctl",
                &["bootstrap", &domain, path_text(&definition_path)?],
                "register Claude Desktop LaunchAgent",
            )?;
        }
        Platform::Windows => run_checked(
            runner,
            "schtasks.exe",
            &[
                "/Create",
                "/TN",
                WINDOWS_TASK_NAME,
                "/XML",
                path_text(&definition_path)?,
                "/F",
            ],
            "register Claude Desktop logon task",
        )?,
        Platform::Linux => {
            run_checked(
                runner,
                "systemctl",
                &["--user", "daemon-reload"],
                "reload the systemd user manager",
            )?;
            run_checked(
                runner,
                "systemctl",
                &["--user", "enable", LINUX_SERVICE_NAME],
                "enable Claude Desktop systemd user service",
            )?;
        }
    }
    Ok(())
}

pub(super) fn start_service(state: &DesktopState) -> Result<(), String> {
    start_service_with(state, &RealCommandRunner)
}

fn start_service_with(state: &DesktopState, runner: &dyn CommandRunner) -> Result<(), String> {
    match Platform::parse(&state.platform)? {
        Platform::MacOs => run_checked(
            runner,
            "launchctl",
            &[
                "kickstart",
                "-k",
                &format!("{}/{}", launchctl_domain(), MACOS_SERVICE_LABEL),
            ],
            "start Claude Desktop LaunchAgent",
        ),
        Platform::Windows => run_checked(
            runner,
            "schtasks.exe",
            &["/Run", "/TN", WINDOWS_TASK_NAME],
            "start Claude Desktop logon task",
        ),
        Platform::Linux => run_checked(
            runner,
            "systemctl",
            &["--user", "start", LINUX_SERVICE_NAME],
            "start Claude Desktop systemd user service",
        ),
    }
}

pub(super) fn stop_service(state: &DesktopState) -> Result<(), String> {
    stop_service_with(state, &RealCommandRunner)
}

fn stop_service_with(state: &DesktopState, runner: &dyn CommandRunner) -> Result<(), String> {
    match Platform::parse(&state.platform)? {
        Platform::MacOs => {
            let definition = service_definition_path(Platform::MacOs, &state.install_root)?;
            let status = run_status(
                runner,
                "launchctl",
                &["bootout", &launchctl_domain(), path_text(&definition)?],
            )?;
            if status != 0 && definition.exists() {
                return Err("failed to stop Claude Desktop LaunchAgent".into());
            }
            Ok(())
        }
        Platform::Windows => {
            let _ = run_status(runner, "schtasks.exe", &["/End", "/TN", WINDOWS_TASK_NAME])?;
            Ok(())
        }
        Platform::Linux => {
            let _ = run_status(runner, "systemctl", &["--user", "stop", LINUX_SERVICE_NAME])?;
            Ok(())
        }
    }
}

pub(super) fn unregister_service(state: &DesktopState, dry_run: bool) -> Result<(), String> {
    unregister_service_with(state, dry_run, &RealCommandRunner)
}

fn unregister_service_with(
    state: &DesktopState,
    dry_run: bool,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    let platform = Platform::parse(&state.platform)?;
    let definition = service_definition_path(platform, &state.install_root)?;
    if dry_run {
        println!("unregister {} login service", state.platform);
        println!("remove {}", definition.display());
        return Ok(());
    }
    let registered = service_registration_status(platform, None, runner).is_ok();
    if registered {
        stop_service_with(state, runner)?;
    }
    match platform {
        Platform::MacOs => {}
        Platform::Windows => {
            if service_registration_status(Platform::Windows, None, runner).is_ok() {
                let status = run_status(
                    runner,
                    "schtasks.exe",
                    &["/Delete", "/TN", WINDOWS_TASK_NAME, "/F"],
                )?;
                if status != 0 {
                    return Err("failed to delete Claude Desktop logon task".into());
                }
            }
        }
        Platform::Linux => {
            if registered {
                run_checked(
                    runner,
                    "systemctl",
                    &["--user", "disable", LINUX_SERVICE_NAME],
                    "disable Claude Desktop systemd user service",
                )?;
            }
        }
    }
    super::state::remove_file_if_present(&definition)?;
    if platform == Platform::Linux {
        run_checked(
            runner,
            "systemctl",
            &["--user", "daemon-reload"],
            "reload the systemd user manager",
        )?;
    }
    Ok(())
}

pub(super) fn service_definition_matches(state: &DesktopState) -> Result<String, String> {
    service_definition_matches_with(state, &RealCommandRunner)
}

fn service_definition_matches_with(
    state: &DesktopState,
    runner: &dyn CommandRunner,
) -> Result<String, String> {
    let platform = Platform::parse(&state.platform)?;
    let path = service_definition_path(platform, &state.install_root)?;
    let actual = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read service definition {}: {error}",
            path.display()
        )
    })?;
    let expected = render_service_definition(
        platform,
        &state.relay_binary,
        &state.state_path(),
        &state.install_root,
        windows_principal().as_deref(),
    )?;
    if actual != expected {
        return Err(format!(
            "service definition {} differs from the installed generation",
            path.display()
        ));
    }
    service_registration_status(platform, Some(state), runner)?;
    Ok(format!("{} is registered", path.display()))
}

fn service_registration_status(
    platform: Platform,
    expected: Option<&DesktopState>,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    let (program, args, label) = match platform {
        Platform::MacOs => (
            "launchctl",
            vec![
                "print".to_string(),
                format!("{}/{}", launchctl_domain(), MACOS_SERVICE_LABEL),
            ],
            "Claude Desktop LaunchAgent",
        ),
        Platform::Windows => (
            "schtasks.exe",
            vec![
                "/Query".to_string(),
                "/TN".to_string(),
                WINDOWS_TASK_NAME.to_string(),
                "/XML".to_string(),
            ],
            "Claude Desktop logon task",
        ),
        Platform::Linux => (
            "systemctl",
            vec![
                "--user".to_string(),
                "is-enabled".to_string(),
                LINUX_SERVICE_NAME.to_string(),
            ],
            "Claude Desktop systemd user service",
        ),
    };
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_output(runner, program, &args)?;
    if output.status != 0 {
        return Err(format!("{label} is not registered"));
    }
    match (platform, expected) {
        (Platform::MacOs, Some(state)) => {
            let relay = state.relay_binary.display().to_string();
            let state_path = state.state_path().display().to_string();
            if output.stdout.contains(&relay)
                && output.stdout.contains(&state_path)
                && output.stdout.contains("claude-desktop-sidecar")
            {
                Ok(())
            } else {
                Err("registered Claude Desktop LaunchAgent has unexpected arguments".into())
            }
        }
        (Platform::Windows, Some(state)) => {
            let command = format!(
                "<Command>{}</Command>",
                xml_escape(&state.relay_binary.display().to_string())
            );
            let state_argument = format!(
                "--state &quot;{}&quot;",
                xml_escape(&state.state_path().display().to_string())
            );
            if output.stdout.contains("<Enabled>true</Enabled>")
                && output.stdout.contains(&command)
                && output.stdout.contains(&state_argument)
            {
                Ok(())
            } else {
                Err(
                    "registered Claude Desktop logon task is disabled or has unexpected arguments"
                        .into(),
                )
            }
        }
        (Platform::Linux, _) if output.stdout.trim() != "enabled" => {
            Err("Claude Desktop systemd user service is not enabled".into())
        }
        _ => Ok(()),
    }
}

pub(super) fn install_trust(
    platform: Platform,
    certificate: &CertificateState,
    dry_run: bool,
) -> Result<(), String> {
    install_trust_with(platform, certificate, dry_run, &RealCommandRunner)
}

fn install_trust_with(
    platform: Platform,
    certificate: &CertificateState,
    dry_run: bool,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    if dry_run {
        println!(
            "trust Claude Desktop root certificate {} for the current user",
            certificate.root_sha256
        );
        return Ok(());
    }
    if trust_entry_present(platform, certificate, runner)? {
        return Ok(());
    }
    match platform {
        Platform::MacOs => run_checked(
            runner,
            "/usr/bin/security",
            &[
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                path_text(&macos_login_keychain()?)?,
                path_text(&certificate.root_pem)?,
            ],
            "trust Claude Desktop root in the login Keychain",
        ),
        Platform::Windows => run_checked(
            runner,
            "certutil.exe",
            &[
                "-user",
                "-addstore",
                "-f",
                "Root",
                path_text(&certificate.root_der)?,
            ],
            "trust Claude Desktop root in CurrentUser Root",
        ),
        Platform::Linux => Ok(()),
    }
}

pub(super) fn remove_trust(
    platform: Platform,
    certificate: &CertificateState,
    dry_run: bool,
) -> Result<(), String> {
    remove_trust_with(platform, certificate, dry_run, &RealCommandRunner)
}

fn remove_trust_with(
    platform: Platform,
    certificate: &CertificateState,
    dry_run: bool,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    if dry_run {
        println!(
            "remove Claude Desktop root certificate {} from current-user trust",
            certificate.root_sha256
        );
        return Ok(());
    }
    if !trust_entry_present(platform, certificate, runner)? {
        return Ok(());
    }
    let root_sha1 = validated_root_sha1(certificate)?;
    match platform {
        Platform::MacOs => {
            let status = run_status(
                runner,
                "/usr/bin/security",
                &[
                    "delete-certificate",
                    "-Z",
                    root_sha1,
                    path_text(&macos_login_keychain()?)?,
                ],
            )?;
            if status == 0 {
                Ok(())
            } else {
                Err(format!(
                    "failed to remove trusted certificate {} from the login Keychain",
                    certificate.root_sha256
                ))
            }
        }
        Platform::Windows => {
            let status = run_status(
                runner,
                "certutil.exe",
                &["-user", "-delstore", "Root", root_sha1],
            )?;
            if status == 0 {
                Ok(())
            } else {
                Err(format!(
                    "failed to remove {} from CurrentUser Root",
                    certificate.root_common_name
                ))
            }
        }
        Platform::Linux => Ok(()),
    }
}

pub(super) fn trust_status(
    platform: Platform,
    certificate: &CertificateState,
    linux_bundle: Option<&Path>,
) -> Result<String, String> {
    trust_status_with(platform, certificate, linux_bundle, &RealCommandRunner)
}

fn trust_status_with(
    platform: Platform,
    certificate: &CertificateState,
    linux_bundle: Option<&Path>,
    runner: &dyn CommandRunner,
) -> Result<String, String> {
    match platform {
        Platform::MacOs => {
            if trust_entry_present(platform, certificate, runner)? {
                Ok("login Keychain trust matches the installed root".into())
            } else {
                Err("installed Claude Desktop root is not trusted in the login Keychain".into())
            }
        }
        Platform::Windows => {
            if trust_entry_present(platform, certificate, runner)? {
                Ok("CurrentUser Root contains the installed root".into())
            } else {
                Err("installed Claude Desktop root is not in CurrentUser Root".into())
            }
        }
        Platform::Linux => {
            let bundle = linux_bundle.ok_or_else(|| {
                "Claude-scoped NODE_EXTRA_CA_CERTS bundle is missing from state".to_string()
            })?;
            let bundle_bytes = std::fs::read(bundle)
                .map_err(|error| format!("failed to read {}: {error}", bundle.display()))?;
            let root = std::fs::read(&certificate.root_pem).map_err(|error| {
                format!("failed to read {}: {error}", certificate.root_pem.display())
            })?;
            if bundle_bytes
                .windows(root.len())
                .any(|candidate| candidate == root)
            {
                Ok(format!(
                    "Claude-scoped CA bundle {} is composed",
                    bundle.display()
                ))
            } else {
                Err(format!(
                    "Claude-scoped CA bundle {} does not contain the installed root",
                    bundle.display()
                ))
            }
        }
    }
}

fn trust_entry_present(
    platform: Platform,
    certificate: &CertificateState,
    runner: &dyn CommandRunner,
) -> Result<bool, String> {
    let root_sha1 = validated_root_sha1(certificate)?;
    match platform {
        Platform::MacOs => {
            let output = run_output(
                runner,
                "/usr/bin/security",
                &[
                    "find-certificate",
                    "-Z",
                    "-c",
                    &certificate.root_common_name,
                    path_text(&macos_login_keychain()?)?,
                ],
            )?;
            Ok(output.status == 0 && output_contains_thumbprint(&output.stdout, root_sha1))
        }
        Platform::Windows => {
            let output = run_output(
                runner,
                "certutil.exe",
                &["-user", "-store", "Root", &certificate.root_common_name],
            )?;
            Ok(output.status == 0 && output_contains_thumbprint(&output.stdout, root_sha1))
        }
        Platform::Linux => Ok(false),
    }
}

fn output_contains_thumbprint(output: &str, thumbprint: &str) -> bool {
    let normalized = output
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .collect::<String>()
        .to_ascii_uppercase();
    normalized.contains(&thumbprint.to_ascii_uppercase())
}

fn validated_root_sha1(certificate: &CertificateState) -> Result<&str, String> {
    let thumbprint = certificate.root_sha1.as_str();
    if thumbprint.len() == 40
        && thumbprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        Ok(thumbprint)
    } else {
        Err("Claude Desktop state contains an invalid root certificate thumbprint".into())
    }
}

pub(super) fn open_deep_link(platform: Platform, url: &str) -> Result<(), String> {
    open_deep_link_with(platform, url, &RealCommandRunner)
}

fn open_deep_link_with(
    platform: Platform,
    url: &str,
    runner: &dyn CommandRunner,
) -> Result<(), String> {
    match platform {
        Platform::MacOs => run_checked(runner, "open", &[url], "open Claude Desktop deep link"),
        Platform::Windows => run_checked(
            runner,
            "rundll32.exe",
            &["url.dll,FileProtocolHandler", url],
            "open Claude Desktop deep link",
        ),
        Platform::Linux => run_checked(runner, "xdg-open", &[url], "open Claude Desktop deep link"),
    }
}

fn render_launch_agent(relay: &Path, state: &Path, root: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>claude-desktop-sidecar</string>\n    <string>--state</string>\n    <string>{}</string>\n  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ProcessType</key><string>Background</string>\n  <key>ThrottleInterval</key><integer>5</integer>\n  <key>Umask</key><integer>63</integer>\n  <key>StandardOutPath</key><string>{}</string>\n  <key>StandardErrorPath</key><string>{}</string>\n</dict>\n</plist>\n",
        MACOS_SERVICE_LABEL,
        xml_escape(&relay.display().to_string()),
        xml_escape(&state.display().to_string()),
        xml_escape(&root.join("sidecar.stdout.log").display().to_string()),
        xml_escape(&root.join("sidecar.stderr.log").display().to_string()),
    )
}

fn render_scheduled_task(relay: &Path, state: &Path, principal: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger></Triggers>\n  <Principals><Principal id=\"Author\"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT5S</Interval><Count>999</Count></RestartOnFailure></Settings>\n  <Actions Context=\"Author\"><Exec><Command>{}</Command><Arguments>claude-desktop-sidecar --state &quot;{}&quot;</Arguments></Exec></Actions>\n</Task>\n",
        xml_escape(principal),
        xml_escape(principal),
        xml_escape(&relay.display().to_string()),
        xml_escape(&state.display().to_string()),
    )
}

fn render_systemd_unit(relay: &Path, state: &Path) -> Result<String, String> {
    Ok(format!(
        "[Unit]\nDescription=NeMo Relay protection for Claude Desktop Code\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} claude-desktop-sidecar --state {}\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&relay.display().to_string())?,
        systemd_quote(&state.display().to_string())?,
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_control) {
        return Err("systemd service paths must not contain control characters".into());
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('%', "%%")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    ))
}

fn validate_macos_version(runner: &dyn CommandRunner) -> Result<String, String> {
    let output = run_output(runner, "sw_vers", &["-productVersion"])?;
    let major = output
        .stdout
        .trim()
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "could not determine the macOS version".to_string())?;
    if major < 11 {
        return Err(format!(
            "Claude Desktop protection requires macOS 11 or newer; found {}",
            output.stdout.trim()
        ));
    }
    Ok(format!("macOS {}", output.stdout.trim()))
}

fn validate_windows_version(runner: &dyn CommandRunner) -> Result<String, String> {
    let output = run_output(runner, "cmd.exe", &["/C", "ver"])?;
    if output.status != 0 {
        return Err("could not determine the Windows version".into());
    }
    let version = output
        .stdout
        .split("Version ")
        .nth(1)
        .and_then(|value| value.split('.').next())
        .and_then(|value| value.trim_matches(['[', ']']).parse::<u64>().ok())
        .ok_or_else(|| {
            format!(
                "could not parse Windows version from {:?}",
                output.stdout.trim()
            )
        })?;
    if version < 10 {
        return Err(format!(
            "Claude Desktop protection requires Windows 10 or newer; found {}",
            output.stdout.trim()
        ));
    }
    Ok(output.stdout.trim().to_string())
}

fn validate_linux_platform(runner: &dyn CommandRunner) -> Result<String, String> {
    let raw = std::fs::read_to_string("/etc/os-release")
        .map_err(|error| format!("failed to read /etc/os-release: {error}"))?;
    let systemd_status = run_status(runner, "systemctl", &["--user", "show-environment"])?;
    validate_linux_release(&raw, systemd_status)
}

fn validate_linux_release(raw: &str, systemd_status: i32) -> Result<String, String> {
    let id = os_release_value(raw, "ID").unwrap_or_default();
    let version = os_release_value(raw, "VERSION_ID").unwrap_or_default();
    let supported = match id.as_str() {
        "ubuntu" => version_major(&version).is_some_and(|major| major >= 22),
        "debian" => version_major(&version).is_some_and(|major| major >= 12),
        _ => false,
    };
    if !supported {
        return Err(format!(
            "Claude Desktop Linux support currently requires Ubuntu 22.04+ or Debian 12+ with a systemd user session; found {id} {version}"
        ));
    }
    if systemd_status != 0 {
        return Err(
            "a running systemd user session is required for Claude Desktop protection".into(),
        );
    }
    Ok(format!("{id} {version} with systemd user session"))
}

fn macos_application_identity(runner: &dyn CommandRunner) -> Result<String, String> {
    let home = crate::agents::shared::host::home_dir()?;
    let candidates = [
        PathBuf::from("/Applications/Claude.app"),
        home.join("Applications").join("Claude.app"),
    ];
    macos_application_identity_from(runner, &candidates)
}

fn macos_application_identity_from(
    runner: &dyn CommandRunner,
    candidates: &[PathBuf],
) -> Result<String, String> {
    let app = candidates
        .iter()
        .find(|path| path.is_dir())
        .ok_or_else(|| "Claude.app was not found in /Applications or ~/Applications".to_string())?;
    let plist = app.join("Contents").join("Info.plist");
    let output = run_output(
        runner,
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleIdentifier",
            "raw",
            "-o",
            "-",
            path_text(&plist)?,
        ],
    )?;
    let bundle = output.stdout.trim();
    if bundle != "com.anthropic.claudefordesktop" {
        return Err(format!(
            "{} has unexpected bundle identity {bundle:?}",
            app.display()
        ));
    }
    Ok(format!("{} ({bundle})", app.display()))
}

fn windows_application_identity(runner: &dyn CommandRunner) -> Result<String, String> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
    let candidates = [
        local.join("Programs").join("Claude").join("Claude.exe"),
        local.join("AnthropicClaude").join("Claude.exe"),
    ];
    if let Some(path) = candidates.into_iter().find(|path| path.is_file()) {
        return Ok(path.display().to_string());
    }

    // Anthropic's enterprise distribution is a per-user MSIX whose payload resides below the
    // protected WindowsApps directory, so detect it through the package registry rather than by
    // guessing an executable path.
    let output = run_output(
        runner,
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-AppxPackage -Name Claude | Select-Object -First 1).PackageFullName",
        ],
    )?;
    let package = output.stdout.trim();
    if output.status == 0 && !package.is_empty() {
        Ok(format!("Windows MSIX package {package}"))
    } else {
        Err("the per-user Claude Desktop executable or Claude MSIX package was not found".into())
    }
}

fn linux_application_identity(runner: &dyn CommandRunner) -> Result<String, String> {
    linux_application_identity_at(runner, Path::new("/usr/bin/claude-desktop"))
}

fn linux_application_identity_at(
    runner: &dyn CommandRunner,
    executable: &Path,
) -> Result<String, String> {
    if !executable.is_file() {
        return Err("Anthropic's /usr/bin/claude-desktop executable was not found".into());
    }
    let output = run_output(
        runner,
        "dpkg-query",
        &["-W", "-f=${Status}\t${Version}\n", "claude-desktop"],
    )?;
    let identity = output.stdout.trim();
    if output.status != 0 || !identity.starts_with("install ok installed\t") {
        return Err("Anthropic's claude-desktop Debian package is not installed".into());
    }
    Ok(format!("{} ({identity})", executable.display()))
}

fn active_unix_processes(runner: &dyn CommandRunner) -> Result<Vec<String>, String> {
    let mut active = Vec::new();
    for name in ["Claude", "Claude Helper", "claude", "claude-desktop"] {
        let status = run_status(runner, "pgrep", &["-x", name])?;
        if status == 0 {
            active.push(name.to_string());
        }
    }
    let processes = run_output(runner, "ps", &["-axo", "comm=,args="])?;
    if processes
        .stdout
        .lines()
        .any(unix_process_line_is_node_claude)
    {
        active.push("Claude Code (Node.js)".into());
    }
    if processes
        .stdout
        .lines()
        .any(unix_process_line_is_desktop_claude)
    {
        active.push("Claude Desktop helper".into());
    }
    active.sort();
    active.dedup();
    Ok(active)
}

fn unix_process_line_is_node_claude(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("/@anthropic-ai/claude-code/")
        || lower.contains("/node_modules/@anthropic-ai/claude-code/")
        || lower.contains("/claude-code/cli.js")
}

fn unix_process_line_is_desktop_claude(line: &str) -> bool {
    let executable = line.split_ascii_whitespace().next().unwrap_or_default();
    let lower = executable.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    lower.contains("/claude.app/contents/")
        || name == "claude-desktop"
        || name.starts_with("claude helper")
}

fn active_windows_processes(runner: &dyn CommandRunner) -> Result<Vec<String>, String> {
    let output = run_output(
        runner,
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_PROCESS_QUERY,
        ],
    )?;
    if output.status != 0 {
        return Err(format!(
            "failed to enumerate Claude processes on Windows: {}",
            output.stderr.trim()
        ));
    }
    let mut active = output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|name| {
            matches!(
                *name,
                "Claude.exe" | "claude-code.exe" | "ClaudeCode.exe" | "Claude Code (Node.js)"
            )
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    active.sort();
    active.dedup();
    Ok(active)
}

fn macos_login_keychain() -> Result<PathBuf, String> {
    let root = crate::agents::shared::host::home_dir()?
        .join("Library")
        .join("Keychains");
    let modern = root.join("login.keychain-db");
    if modern.exists() {
        Ok(modern)
    } else {
        Ok(root.join("login.keychain"))
    }
}

fn launchctl_domain() -> String {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        format!("gui/{}", unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        "gui/0".into()
    }
}

fn windows_principal() -> Option<String> {
    let user = std::env::var("USERNAME").ok()?;
    Some(std::env::var("USERDOMAIN").map_or(user.clone(), |domain| format!("{domain}\\{user}")))
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid Unicode: {}", path.display()))
}

fn os_release_value(raw: &str, key: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim_matches(['"', '\'']).to_string())
    })
}

fn version_major(value: &str) -> Option<u64> {
    value.split('.').next()?.parse().ok()
}

struct ProcessOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_output(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
) -> Result<ProcessOutput, String> {
    let arguments = args
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    let output = runner.run_capture(Path::new(program), &arguments)?;
    Ok(ProcessOutput {
        status: output.status(),
        stdout: output.stdout().into(),
        stderr: output.stderr().into(),
    })
}

fn run_status(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<i32, String> {
    let arguments = args
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    runner.run_quiet(Path::new(program), &arguments)
}

fn run_checked(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
    action: &str,
) -> Result<(), String> {
    let output = run_output(runner, program, args)?;
    if output.status == 0 {
        Ok(())
    } else {
        let details = output.stderr.trim();
        Err(if details.is_empty() {
            format!("failed to {action} (exit {})", output.status)
        } else {
            format!("failed to {action}: {details}")
        })
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/platform_tests.rs"]
mod tests;
