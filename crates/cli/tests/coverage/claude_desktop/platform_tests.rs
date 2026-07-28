// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::installation::marketplace::host::CommandOutput;

use super::*;

const TEST_WINDOWS_SID: &str = "S-1-5-21-1000";

#[derive(Default)]
struct FakeRunner {
    outputs: RefCell<HashMap<String, VecDeque<CommandOutput>>>,
    calls: RefCell<Vec<String>>,
}

impl FakeRunner {
    fn key(program: &Path, args: &[String]) -> String {
        std::iter::once(program.display().to_string())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
            .join("\u{1f}")
    }

    fn enqueue(&self, program: &str, args: &[&str], status: i32, stdout: &str, stderr: &str) {
        let arguments = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        self.outputs
            .borrow_mut()
            .entry(Self::key(Path::new(program), &arguments))
            .or_default()
            .push_back(CommandOutput::from_parts(
                status,
                stdout.into(),
                stderr.into(),
            ));
    }

    fn response(&self, program: &Path, args: &[String]) -> Result<CommandOutput, String> {
        let key = Self::key(program, args);
        self.calls.borrow_mut().push(key.clone());
        Ok(self
            .outputs
            .borrow_mut()
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| CommandOutput::from_parts(0, String::new(), String::new())))
    }

    fn called(&self, program: &str, argument: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|call| call.starts_with(program) && call.contains(argument))
    }
}

impl CommandRunner for FakeRunner {
    fn current_executable(&self) -> Result<PathBuf, String> {
        Ok(PathBuf::from("/test/nemo-relay"))
    }

    fn resolve_executable(&self, command: &str) -> Result<Option<PathBuf>, String> {
        Ok(Some(PathBuf::from(command)))
    }

    fn run(&self, program: &Path, args: &[String]) -> Result<i32, String> {
        self.response(program, args).map(|output| output.status())
    }

    fn run_quiet(&self, program: &Path, args: &[String]) -> Result<i32, String> {
        self.response(program, args).map(|output| output.status())
    }

    fn run_capture(&self, program: &Path, args: &[String]) -> Result<CommandOutput, String> {
        self.response(program, args)
    }
}

struct PlatformFixture {
    _temp: tempfile::TempDir,
    _environment: crate::test_support::EnvScope,
    root: PathBuf,
    state: DesktopState,
}

impl PlatformFixture {
    fn new(platform: Platform) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let config = temp.path().join("config");
        let local = temp.path().join("local");
        std::fs::create_dir_all(home.join("Library").join("Keychains")).unwrap();
        std::fs::create_dir_all(config.join("nemo-relay")).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let environment = crate::test_support::EnvScope::set(&[
            ("HOME", Some(home.as_os_str())),
            ("USERPROFILE", Some(home.as_os_str())),
            ("XDG_CONFIG_HOME", Some(config.as_os_str())),
            ("LOCALAPPDATA", Some(local.as_os_str())),
            ("USERNAME", Some(std::ffi::OsStr::new("Test User"))),
            ("USERDOMAIN", Some(std::ffi::OsStr::new("DOMAIN"))),
        ]);
        let root = temp.path().join("marketplace").join("agent-proxy");
        std::fs::create_dir_all(&root).unwrap();
        let certificate = super::super::certificate::generate(&root, "generation").unwrap();
        let relay = temp.path().join("NeMo Relay").join("nemo-relay");
        std::fs::create_dir_all(relay.parent().unwrap()).unwrap();
        std::fs::write(&relay, b"relay").unwrap();
        let state = DesktopState {
            schema_version: super::super::state::STATE_SCHEMA_VERSION,
            generation: "generation".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            relay_version: "0.7.0".into(),
            relay_binary: relay,
            install_root: root.clone(),
            user_config_dir: config.join("nemo-relay"),
            platform: platform.as_str().into(),
            service_identity: (platform == Platform::Windows).then(|| TEST_WINDOWS_SID.into()),
            bind: super::super::LEGACY_PROXY_BIND,
            proxy_username: "relay".into(),
            proxy_token: "token".into(),
            upstream_proxy: None,
            gateway_fingerprint: "gateway".into(),
            max_hook_payload_bytes: crate::configuration::DEFAULT_MAX_HOOK_PAYLOAD_BYTES,
            configuration_fingerprint: "configuration".into(),
            certificate,
            settings: Default::default(),
            claude_code_installed: false,
            claude_desktop_installed: false,
            enrollments: Default::default(),
        };
        Self {
            _temp: temp,
            _environment: environment,
            root,
            state,
        }
    }
}

#[test]
fn service_definitions_preserve_paths_with_spaces() {
    let relay = Path::new("/opt/NeMo Relay/nemo-relay");
    let state = Path::new("/home/Test User/state.json");
    let root = Path::new("/home/Test User");
    let launchd = render_service_definition(Platform::MacOs, relay, state, root, None).unwrap();
    assert!(launchd.contains("/opt/NeMo Relay/nemo-relay"));
    let task = render_service_definition(
        Platform::Windows,
        Path::new("C:\\Program Files\\NeMo Relay\\nemo-relay.exe"),
        Path::new("C:\\Users\\Test User\\state.json"),
        root,
        Some(TEST_WINDOWS_SID),
    )
    .unwrap();
    assert!(task.contains("&quot;C:\\Users\\Test User\\state.json&quot;"));
    assert!(task.contains("<Hidden>true</Hidden>"));
    assert!(task.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    let systemd = render_service_definition(Platform::Linux, relay, state, root, None).unwrap();
    assert!(systemd.contains("ExecStart=\"/opt/NeMo Relay/nemo-relay\""));
    assert!(systemd.contains("WantedBy=default.target"));
    assert!(systemd_quote("/tmp/unsafe\npath").is_err());
    assert!(
        systemd_quote("/tmp/100% \"quoted\"")
            .unwrap()
            .contains("100%%")
    );
    assert_eq!(
        xml_escape("<&>\"'"),
        "&lt;&amp;&gt;&quot;&apos;".to_string()
    );
}

#[test]
fn node_claude_process_detection_is_path_specific() {
    assert!(unix_process_line_is_node_claude(
        "node /opt/node_modules/@anthropic-ai/claude-code/cli.js"
    ));
    assert!(!unix_process_line_is_node_claude(
        "node /workspace/claude-code-notes/server.js"
    ));
    assert!(unix_process_line_is_desktop_claude(
        "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer) --type=renderer"
    ));
    assert!(unix_process_line_is_desktop_claude(
        "/usr/bin/claude-desktop --no-sandbox"
    ));
    assert!(!unix_process_line_is_desktop_claude(
        "/opt/nemo-relay install claude-desktop"
    ));
}

#[test]
fn platform_names_round_trip_and_reject_unknown_values() {
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        assert_eq!(Platform::parse(platform.as_str()).unwrap(), platform);
    }
    assert!(Platform::parse("plan9").unwrap_err().contains("invalid"));
    assert_eq!(Platform::current().unwrap().as_str(), std::env::consts::OS);
}

#[test]
fn version_validation_covers_supported_and_rejected_platforms() {
    let runner = FakeRunner::default();
    runner.enqueue("sw_vers", &["-productVersion"], 0, "14.6.1\n", "");
    assert_eq!(
        validate_supported_platform_with(Platform::MacOs, &runner).unwrap(),
        "macOS 14.6.1"
    );
    runner.enqueue("sw_vers", &["-productVersion"], 0, "10.15.7\n", "");
    assert!(validate_supported_platform_with(Platform::MacOs, &runner).is_err());
    runner.enqueue("sw_vers", &["-productVersion"], 0, "unknown\n", "");
    assert!(validate_supported_platform_with(Platform::MacOs, &runner).is_err());

    runner.enqueue(
        "cmd.exe",
        &["/C", "ver"],
        0,
        "Microsoft Windows [Version 10.0]\n",
        "",
    );
    assert!(validate_supported_platform_with(Platform::Windows, &runner).is_ok());
    runner.enqueue(
        "cmd.exe",
        &["/C", "ver"],
        0,
        "Microsoft Windows [Version 6.3]\n",
        "",
    );
    assert!(validate_supported_platform_with(Platform::Windows, &runner).is_err());
    runner.enqueue("cmd.exe", &["/C", "ver"], 1, "", "");
    assert!(validate_supported_platform_with(Platform::Windows, &runner).is_err());

    assert!(validate_linux_release("ID=ubuntu\nVERSION_ID=\"22.04\"\n", 0).is_ok());
    assert!(validate_linux_release("ID=debian\nVERSION_ID=\"12\"\n", 0).is_ok());
    assert!(validate_linux_release("ID=ubuntu\nVERSION_ID=\"20.04\"\n", 0).is_ok());
    assert_eq!(
        validate_linux_release("ID=fedora\nVERSION_ID=\"40\"\n", 0).unwrap(),
        "fedora 40 with systemd user session"
    );
    assert_eq!(
        validate_linux_release("NAME=Custom Linux\n", 0).unwrap(),
        "Linux with systemd user session"
    );
    assert!(validate_linux_release("ID=debian\nVERSION_ID=\"12\"\n", 1).is_err());
    assert_eq!(
        os_release_value("ID='debian'\nNAME=Debian\n", "ID").as_deref(),
        Some("debian")
    );
}

#[test]
fn application_identity_checks_each_supported_distribution() {
    let fixture = PlatformFixture::new(Platform::MacOs);
    let runner = FakeRunner::default();
    let app = fixture
        ._temp
        .path()
        .join("home")
        .join("Applications")
        .join("Claude.app");
    std::fs::create_dir_all(app.join("Contents")).unwrap();
    std::fs::write(app.join("Contents").join("Info.plist"), b"plist").unwrap();
    runner.enqueue(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleIdentifier",
            "raw",
            "-o",
            "-",
            app.join("Contents").join("Info.plist").to_str().unwrap(),
        ],
        0,
        "com.anthropic.claudefordesktop\n",
        "",
    );
    assert!(
        macos_application_identity_from(&runner, std::slice::from_ref(&app))
            .unwrap()
            .contains("com.anthropic")
    );

    let windows_executable = fixture
        ._temp
        .path()
        .join("local")
        .join("Programs")
        .join("Claude")
        .join("Claude.exe");
    std::fs::create_dir_all(windows_executable.parent().unwrap()).unwrap();
    std::fs::write(&windows_executable, b"exe").unwrap();
    assert_eq!(
        application_identity_with(Platform::Windows, &runner).unwrap(),
        windows_executable.display().to_string()
    );

    let linux_executable = fixture._temp.path().join("claude-desktop");
    std::fs::write(&linux_executable, b"elf").unwrap();
    runner.enqueue(
        "dpkg-query",
        &["-W", "-f=${Status}\t${Version}\n", "claude-desktop"],
        0,
        "install ok installed\t1.2.3\n",
        "",
    );
    assert!(
        linux_application_identity_at(&runner, &linux_executable)
            .unwrap()
            .contains("1.2.3")
    );
}

#[test]
fn application_identity_reports_wrong_or_missing_installations() {
    let fixture = PlatformFixture::new(Platform::MacOs);
    let runner = FakeRunner::default();
    assert!(
        macos_application_identity_from(
            &runner,
            &[fixture._temp.path().join("missing-Claude.app")]
        )
        .is_err()
    );

    runner.enqueue(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-AppxPackage -Name Claude | Select-Object -First 1).PackageFullName",
        ],
        0,
        "Claude_1.0_x64\n",
        "",
    );
    assert!(
        application_identity_with(Platform::Windows, &runner)
            .unwrap()
            .contains("MSIX")
    );
    assert!(linux_application_identity_at(&runner, &fixture._temp.path().join("missing")).is_err());
}

#[test]
fn application_identity_rejects_wrong_bundle_package_and_empty_msix_identity() {
    let fixture = PlatformFixture::new(Platform::MacOs);
    let runner = FakeRunner::default();
    let app = fixture._temp.path().join("Claude.app");
    std::fs::create_dir_all(app.join("Contents")).unwrap();
    std::fs::write(app.join("Contents").join("Info.plist"), b"plist").unwrap();
    runner.enqueue(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleIdentifier",
            "raw",
            "-o",
            "-",
            app.join("Contents").join("Info.plist").to_str().unwrap(),
        ],
        0,
        "example.foreign\n",
        "",
    );
    assert!(macos_application_identity_from(&runner, &[app]).is_err());

    runner.enqueue(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-AppxPackage -Name Claude | Select-Object -First 1).PackageFullName",
        ],
        0,
        "\n",
        "",
    );
    assert!(windows_application_identity(&runner).is_err());

    let executable = fixture._temp.path().join("claude-desktop");
    std::fs::write(&executable, b"elf").unwrap();
    runner.enqueue(
        "dpkg-query",
        &["-W", "-f=${Status}\t${Version}\n", "claude-desktop"],
        1,
        "deinstall ok config-files\t1.0\n",
        "",
    );
    assert!(linux_application_identity_at(&runner, &executable).is_err());
}

#[test]
fn process_discovery_is_platform_specific_and_deduplicated() {
    let runner = FakeRunner::default();
    let uid = unix_effective_uid();
    for name in ["Claude", "Claude Helper", "claude", "claude-desktop"] {
        runner.enqueue(
            "pgrep",
            &["-u", &uid, "-x", name],
            i32::from(name != "Claude"),
            "",
            "",
        );
    }
    runner.enqueue(
        "ps",
        &["-U", &uid, "-o", "comm=,args="],
        0,
        "node /opt/node_modules/@anthropic-ai/claude-code/cli.js\n/usr/bin/claude-desktop --type=utility\n",
        "",
    );
    let unix = active_claude_processes_with(Platform::Linux, &runner).unwrap();
    assert_eq!(
        unix,
        vec!["Claude", "Claude Code (Node.js)", "Claude Desktop helper"]
    );

    runner.enqueue(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_PROCESS_QUERY,
        ],
        0,
        "Claude.exe\nClaude Code (Node.js)\nClaude.exe\nother.exe\n",
        "",
    );
    assert_eq!(
        active_claude_processes_with(Platform::Windows, &runner).unwrap(),
        vec!["Claude Code (Node.js)", "Claude.exe"]
    );
    assert!(WINDOWS_PROCESS_QUERY.contains("GetOwnerSid"));
    assert!(WINDOWS_PROCESS_QUERY.contains("WindowsIdentity"));

    runner.enqueue(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_PROCESS_QUERY,
        ],
        1,
        "",
        "CIM unavailable",
    );
    assert!(
        active_claude_processes_with(Platform::Windows, &runner)
            .unwrap_err()
            .contains("CIM unavailable")
    );
}

fn registration_output(platform: Platform, state: &DesktopState) -> String {
    match platform {
        Platform::MacOs => format!(
            "{} agent-proxy-service --state {}",
            state.relay_binary.display(),
            state.state_path().display()
        ),
        Platform::Windows => render_service_definition(
            platform,
            &state.relay_binary,
            &state.state_path(),
            &state.install_root,
            Some(TEST_WINDOWS_SID),
        )
        .unwrap(),
        Platform::Linux => format!(
            "FragmentPath={}\nDropInPaths=\nNeedDaemonReload=no\nExecStart={{ path={} ; argv[]={} agent-proxy-service --state {} ; }}\n",
            installed_service_definition_path(state, Platform::Linux)
                .unwrap()
                .display(),
            state.relay_binary.display(),
            state.relay_binary.display(),
            state.state_path().display()
        ),
    }
}

fn queue_registration_status(runner: &FakeRunner, platform: Platform, output: &str) {
    match platform {
        Platform::MacOs => runner.enqueue(
            "launchctl",
            &[
                "print",
                &format!("{}/{}", launchctl_domain(), MACOS_SERVICE_LABEL),
            ],
            0,
            output,
            "",
        ),
        Platform::Windows => {
            let task_name = windows_task_name(TEST_WINDOWS_SID);
            runner.enqueue(
                "schtasks.exe",
                &["/Query", "/TN", &task_name, "/XML"],
                0,
                output,
                "",
            );
        }
        Platform::Linux => {
            runner.enqueue(
                "systemctl",
                &[
                    "--user",
                    "show",
                    LINUX_SERVICE_NAME,
                    "--property=FragmentPath",
                    "--property=DropInPaths",
                    "--property=NeedDaemonReload",
                    "--property=ExecStart",
                    "--no-pager",
                ],
                0,
                output,
                "",
            );
            runner.enqueue(
                "systemctl",
                &["--user", "is-enabled", LINUX_SERVICE_NAME],
                0,
                "enabled\n",
                "",
            );
        }
    }
}

fn queue_registration_status_times(
    runner: &FakeRunner,
    platform: Platform,
    output: &str,
    count: usize,
) {
    for _ in 0..count {
        queue_registration_status(runner, platform, output);
    }
}

fn exercise_service_lifecycle(platform: Platform) {
    let fixture = PlatformFixture::new(platform);
    let runner = FakeRunner::default();
    register_service_with(&fixture.state, false, &runner).unwrap();
    let definition = service_definition_path(platform, &fixture.root).unwrap();
    assert!(definition.exists());
    start_service_with(&fixture.state, &runner).unwrap();

    let registered = registration_output(platform, &fixture.state);
    queue_registration_status(&runner, platform, &registered);
    assert!(
        service_definition_matches_with(&fixture.state, &runner)
            .unwrap()
            .contains("registered")
    );
    queue_registration_status_times(&runner, platform, &registered, 2);
    stop_service_with(&fixture.state, &runner).unwrap();

    queue_registration_status_times(
        &runner,
        platform,
        &registered,
        if platform == Platform::MacOs { 3 } else { 4 },
    );
    unregister_service_with(&fixture.state, false, &runner).unwrap();
    assert!(!definition.exists());
}

#[test]
fn service_lifecycle_uses_matching_platform_adapter() {
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        exercise_service_lifecycle(platform);
    }
}

#[test]
fn service_dry_runs_and_mismatch_checks_are_non_destructive() {
    let fixture = PlatformFixture::new(Platform::Linux);
    let runner = FakeRunner::default();
    register_service_with(&fixture.state, true, &runner).unwrap();
    unregister_service_with(&fixture.state, true, &runner).unwrap();
    assert!(runner.calls.borrow().is_empty());

    let path = service_definition_path(Platform::Linux, &fixture.root).unwrap();
    crate::filesystem::atomic_write(&path, b"foreign").unwrap();
    assert!(
        ensure_no_foreign_service_with(Platform::Linux, &fixture.root, &runner)
            .unwrap_err()
            .contains("unowned")
    );
    assert!(service_definition_matches_with(&fixture.state, &runner).is_err());
}

#[test]
fn service_commands_surface_command_and_registration_failures() {
    let fixture = PlatformFixture::new(Platform::Windows);
    let runner = FakeRunner::default();
    let task_name = windows_task_name(TEST_WINDOWS_SID);
    runner.enqueue(
        "schtasks.exe",
        &[
            "/Create",
            "/TN",
            &task_name,
            "/XML",
            service_definition_path(Platform::Windows, &fixture.root)
                .unwrap()
                .to_str()
                .unwrap(),
            "/F",
        ],
        5,
        "",
        "access denied",
    );
    assert!(
        register_service_with(&fixture.state, false, &runner)
            .unwrap_err()
            .contains("access denied")
    );

    let runner = FakeRunner::default();
    runner.enqueue(
        "schtasks.exe",
        &["/Query", "/TN", &task_name, "/XML"],
        1,
        "",
        "",
    );
    assert!(
        service_registration_status(Platform::Windows, None, &runner)
            .unwrap_err()
            .contains("not registered")
    );
}

#[test]
fn windows_service_identity_is_stable_and_distinct_per_user() {
    assert_eq!(
        windows_task_name("S-1-5-21-1000"),
        windows_task_name("s-1-5-21-1000")
    );
    assert_ne!(
        windows_task_name("S-1-5-21-1000"),
        windows_task_name("S-1-5-21-2000")
    );
    assert!(windows_task_name(TEST_WINDOWS_SID).starts_with(WINDOWS_TASK_PREFIX));
}

#[test]
fn windows_service_identity_rejects_modified_trigger_or_principal_sid() {
    let fixture = PlatformFixture::new(Platform::Windows);
    let registered = registration_output(Platform::Windows, &fixture.state);

    for modified in [
        registered.replacen(TEST_WINDOWS_SID, "S-1-5-21-2000", 1),
        registered.replacen(
            &format!("<Principal id=\"Author\"><UserId>{TEST_WINDOWS_SID}</UserId>"),
            "<Principal id=\"Author\"><UserId>S-1-5-21-2000</UserId>",
            1,
        ),
        registered.replace(
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<RunLevel>HighestAvailable</RunLevel>",
        ),
        registered.replace("<Hidden>true</Hidden>", "<Hidden>false</Hidden>"),
        registered.replace("<Count>999</Count>", "<Count>1</Count>"),
        registered.replace(
            "</LogonTrigger>",
            "</LogonTrigger><TimeTrigger><Enabled>true</Enabled></TimeTrigger>",
        ),
        registered.replace(
            "</Principals>",
            &format!(
                "<Principal id=\"Other\"><UserId>{TEST_WINDOWS_SID}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
            ),
        ),
        registered.replace(
            "</Actions>",
            "<Exec><Command>C:\\malware.exe</Command><Arguments>run</Arguments></Exec></Actions>",
        ),
        registered.replace(
            "</Arguments>",
            " --unexpected</Arguments>",
        ),
    ] {
        let runner = FakeRunner::default();
        queue_registration_status(&runner, Platform::Windows, &modified);
        assert!(
            service_registration_status(Platform::Windows, Some(&fixture.state), &runner)
                .unwrap_err()
                .contains("unexpected triggers")
        );
    }

    let reformatted = registered.replace("><", ">\n  <");
    let runner = FakeRunner::default();
    queue_registration_status(&runner, Platform::Windows, &reformatted);
    service_registration_status(Platform::Windows, Some(&fixture.state), &runner).unwrap();
}

#[test]
fn linux_service_lifecycle_uses_the_persisted_xdg_root() {
    let fixture = PlatformFixture::new(Platform::Linux);
    let runner = FakeRunner::default();
    register_service_with(&fixture.state, false, &runner).unwrap();
    let definition = installed_service_definition_path(&fixture.state, Platform::Linux).unwrap();
    assert!(definition.exists());
    let registered = registration_output(Platform::Linux, &fixture.state);

    let unrelated = fixture._temp.path().join("unrelated-xdg");
    std::fs::create_dir_all(&unrelated).unwrap();
    fixture
        ._environment
        .update(&[("XDG_CONFIG_HOME", Some(unrelated.as_os_str()))]);

    queue_registration_status(&runner, Platform::Linux, &registered);
    service_definition_matches_with(&fixture.state, &runner).unwrap();
    queue_registration_status_times(&runner, Platform::Linux, &registered, 4);
    unregister_service_with(&fixture.state, false, &runner).unwrap();
    assert!(!definition.exists());
}

#[test]
fn windows_uninstall_uses_persisted_sid_after_environment_changes() {
    let fixture = PlatformFixture::new(Platform::Windows);
    let runner = FakeRunner::default();
    register_service_with(&fixture.state, false, &runner).unwrap();
    let registered = registration_output(Platform::Windows, &fixture.state);
    queue_registration_status_times(&runner, Platform::Windows, &registered, 4);

    fixture._environment.update(&[
        ("USERNAME", Some(std::ffi::OsStr::new("Different User"))),
        ("USERDOMAIN", Some(std::ffi::OsStr::new("OTHER"))),
    ]);
    unregister_service_with(&fixture.state, false, &runner).unwrap();

    let persisted = windows_task_name(TEST_WINDOWS_SID);
    assert!(runner.called("schtasks.exe", &persisted));
    assert!(!runner.called("schtasks.exe", &windows_task_name("OTHER\\Different User")));
}

#[test]
fn service_identity_and_unregistration_fail_closed_on_foreign_state() {
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        let fixture = PlatformFixture::new(platform);
        let runner = FakeRunner::default();
        queue_registration_status(
            &runner,
            platform,
            if platform == Platform::Linux {
                "disabled\n"
            } else {
                "foreign definition"
            },
        );
        assert!(service_registration_status(platform, Some(&fixture.state), &runner).is_err());
    }

    let fixture = PlatformFixture::new(Platform::Linux);
    let definition = service_definition_path(Platform::Linux, &fixture.root).unwrap();
    let expected = render_service_definition(
        Platform::Linux,
        &fixture.state.relay_binary,
        &fixture.state.state_path(),
        &fixture.state.install_root,
        None,
    )
    .unwrap();
    crate::filesystem::atomic_write(&definition, expected.as_bytes()).unwrap();
    let runner = FakeRunner::default();
    let live = registration_output(Platform::Linux, &fixture.state)
        .replace("DropInPaths=", "DropInPaths=/tmp/foreign.conf");
    queue_registration_status(&runner, Platform::Linux, &live);
    let error = stop_service_with(&fixture.state, &runner).unwrap_err();
    assert!(error.contains("no longer owns"), "{error}");
    assert!(!runner.called("systemctl", "stop"));
    drop(fixture);

    let fixture = PlatformFixture::new(Platform::Windows);
    let runner = FakeRunner::default();
    queue_registration_status(&runner, Platform::Windows, "foreign");
    assert!(
        ensure_no_foreign_service_with(Platform::Windows, &fixture.root, &runner)
            .unwrap_err()
            .contains("unowned")
    );
    drop(fixture);

    let fixture = PlatformFixture::new(Platform::MacOs);
    let definition = service_definition_path(Platform::MacOs, &fixture.root).unwrap();
    crate::filesystem::atomic_write(&definition, b"owned").unwrap();
    let runner = FakeRunner::default();
    runner.enqueue(
        "launchctl",
        &["bootout", &launchctl_domain(), definition.to_str().unwrap()],
        1,
        "",
        "",
    );
    assert!(stop_service_with(&fixture.state, &runner).is_err());
    drop(fixture);

    for platform in [Platform::Windows, Platform::Linux] {
        let fixture = PlatformFixture::new(platform);
        let runner = FakeRunner::default();
        match platform {
            Platform::Windows => {
                let task_name = windows_task_name(TEST_WINDOWS_SID);
                runner.enqueue(
                    "schtasks.exe",
                    &["/End", "/TN", &task_name],
                    1,
                    "",
                    "access denied",
                );
            }
            Platform::Linux => runner.enqueue(
                "systemctl",
                &["--user", "stop", LINUX_SERVICE_NAME],
                1,
                "",
                "failed",
            ),
            Platform::MacOs => unreachable!(),
        }
        assert!(stop_service_with(&fixture.state, &runner).is_err());
    }

    let fixture = PlatformFixture::new(Platform::Windows);
    let definition = service_definition_path(Platform::Windows, &fixture.root).unwrap();
    let expected = render_service_definition(
        Platform::Windows,
        &fixture.state.relay_binary,
        &fixture.state.state_path(),
        &fixture.state.install_root,
        Some(TEST_WINDOWS_SID),
    )
    .unwrap();
    crate::filesystem::atomic_write(&definition, expected.as_bytes()).unwrap();
    let runner = FakeRunner::default();
    let task_name = windows_task_name(TEST_WINDOWS_SID);
    let registered = registration_output(Platform::Windows, &fixture.state);
    queue_registration_status_times(&runner, Platform::Windows, &registered, 2);
    runner.enqueue(
        "schtasks.exe",
        &["/End", "/TN", &task_name],
        1,
        "",
        "ERROR: The scheduled task is not running.",
    );
    stop_service_with(&fixture.state, &runner).unwrap();
    drop(fixture);

    let fixture = PlatformFixture::new(Platform::Windows);
    let definition = service_definition_path(Platform::Windows, &fixture.root).unwrap();
    let expected = render_service_definition(
        Platform::Windows,
        &fixture.state.relay_binary,
        &fixture.state.state_path(),
        &fixture.state.install_root,
        Some(TEST_WINDOWS_SID),
    )
    .unwrap();
    crate::filesystem::atomic_write(&definition, expected.as_bytes()).unwrap();
    let runner = FakeRunner::default();
    let registered = registration_output(Platform::Windows, &fixture.state);
    queue_registration_status_times(&runner, Platform::Windows, &registered, 4);
    let task_name = windows_task_name(TEST_WINDOWS_SID);
    runner.enqueue(
        "schtasks.exe",
        &["/Delete", "/TN", &task_name, "/F"],
        1,
        "",
        "",
    );
    assert!(unregister_service_with(&fixture.state, false, &runner).is_err());
    drop(fixture);

    let fixture = PlatformFixture::new(Platform::Linux);
    let definition = service_definition_path(Platform::Linux, &fixture.root).unwrap();
    crate::filesystem::atomic_write(&definition, b"foreign service").unwrap();
    let runner = FakeRunner::default();
    let error = unregister_service_with(&fixture.state, false, &runner).unwrap_err();
    assert!(error.contains("differs from the installed generation"));
    assert_eq!(
        std::fs::read_to_string(&definition).unwrap(),
        "foreign service"
    );
    assert!(runner.calls.borrow().is_empty());
}

fn exercise_trust_lifecycle(platform: Platform) {
    let fixture = PlatformFixture::new(platform);
    let runner = FakeRunner::default();
    let certificate = &fixture.state.certificate;
    let root_sha1 = certificate.root_sha1.clone();
    match platform {
        Platform::MacOs => {
            let keychain = macos_login_keychain().unwrap();
            let args = [
                "find-certificate",
                "-Z",
                "-c",
                certificate.root_common_name.as_str(),
                keychain.to_str().unwrap(),
            ];
            runner.enqueue("/usr/bin/security", &args, 1, "", "");
            runner.enqueue("/usr/bin/security", &args, 0, &root_sha1, "");
            runner.enqueue("/usr/bin/security", &args, 0, &root_sha1, "");
        }
        Platform::Windows => {
            let args = [
                "-user",
                "-store",
                "Root",
                certificate.root_common_name.as_str(),
            ];
            runner.enqueue("certutil.exe", &args, 1, "", "");
            runner.enqueue(
                "certutil.exe",
                &args,
                0,
                &format!("Cert Hash(sha1): {root_sha1}"),
                "",
            );
            runner.enqueue(
                "certutil.exe",
                &args,
                0,
                &format!("Cert Hash(sha1): {root_sha1}"),
                "",
            );
        }
        Platform::Linux => {}
    }
    install_trust_with(platform, certificate, false, &runner).unwrap();
    let bundle = (platform == Platform::Linux).then_some(certificate.root_pem.as_path());
    assert!(trust_status_with(platform, certificate, bundle, &runner).is_ok());
    remove_trust_with(platform, certificate, false, &runner).unwrap();
}

#[test]
fn trust_lifecycle_is_scoped_to_the_current_user_on_all_platforms() {
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        exercise_trust_lifecycle(platform);
    }
}

#[test]
fn trust_dry_run_and_linux_bundle_validation_cover_failure_paths() {
    let fixture = PlatformFixture::new(Platform::Linux);
    let runner = FakeRunner::default();
    install_trust_with(Platform::Linux, &fixture.state.certificate, true, &runner).unwrap();
    remove_trust_with(Platform::Linux, &fixture.state.certificate, true, &runner).unwrap();
    assert!(trust_status_with(Platform::Linux, &fixture.state.certificate, None, &runner).is_err());
    let unrelated = fixture.root.join("unrelated.pem");
    std::fs::write(&unrelated, b"unrelated").unwrap();
    assert!(
        trust_status_with(
            Platform::Linux,
            &fixture.state.certificate,
            Some(&unrelated),
            &runner
        )
        .is_err()
    );
    let mut invalid = fixture.state.certificate.clone();
    invalid.root_sha1.clear();
    assert!(trust_status_with(Platform::MacOs, &invalid, None, &runner).is_err());
}

#[test]
fn trust_adapters_distinguish_absent_present_and_failed_removal() {
    let fixture = PlatformFixture::new(Platform::MacOs);
    let certificate = &fixture.state.certificate;
    let root_sha1 = certificate.root_sha1.clone();
    let keychain = macos_login_keychain().unwrap();
    let find_args = [
        "find-certificate",
        "-Z",
        "-c",
        certificate.root_common_name.as_str(),
        keychain.to_str().unwrap(),
    ];

    let runner = FakeRunner::default();
    runner.enqueue("/usr/bin/security", &find_args, 1, "", "");
    assert!(
        trust_status_with(Platform::MacOs, certificate, None, &runner)
            .unwrap_err()
            .contains("not trusted")
    );

    let runner = FakeRunner::default();
    runner.enqueue("/usr/bin/security", &find_args, 0, &root_sha1, "");
    install_trust_with(Platform::MacOs, certificate, false, &runner).unwrap();
    assert!(!runner.called("/usr/bin/security", "add-trusted-cert"));

    let runner = FakeRunner::default();
    runner.enqueue("/usr/bin/security", &find_args, 0, &root_sha1, "");
    runner.enqueue(
        "/usr/bin/security",
        &[
            "delete-certificate",
            "-Z",
            root_sha1.as_str(),
            keychain.to_str().unwrap(),
        ],
        1,
        "",
        "",
    );
    assert!(remove_trust_with(Platform::MacOs, certificate, false, &runner).is_err());

    let runner = FakeRunner::default();
    runner.enqueue(
        "certutil.exe",
        &[
            "-user",
            "-store",
            "Root",
            certificate.root_common_name.as_str(),
        ],
        1,
        "",
        "",
    );
    assert!(trust_status_with(Platform::Windows, certificate, None, &runner).is_err());

    let runner = FakeRunner::default();
    runner.enqueue("tool", &["arg"], 5, "", "");
    assert!(
        run_checked(&runner, "tool", &["arg"], "perform test action")
            .unwrap_err()
            .contains("exit 5")
    );
}

#[test]
fn deep_links_use_the_native_platform_opener() {
    let runner = FakeRunner::default();
    let url = "claude://code/new?folder=%2Ftmp";
    open_deep_link_with(Platform::MacOs, url, &runner).unwrap();
    open_deep_link_with(Platform::Windows, url, &runner).unwrap();
    open_deep_link_with(Platform::Linux, url, &runner).unwrap();
    assert!(runner.called("open", url));
    assert!(runner.called("rundll32.exe", "FileProtocolHandler"));
    assert!(runner.called("xdg-open", url));
}
