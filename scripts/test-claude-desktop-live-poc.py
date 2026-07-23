#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Opt-in, destructive-to-current-session release gate for Claude Desktop protection.

The test installs user-scoped TLS trust and a login service, invokes the user's real Claude
subscription, validates isolated ATOF and ATIF file artifacts, and requires two short visual
confirmations in Claude Desktop. It always attempts to uninstall on exit. Run it only on a
disposable release-gate account with Claude closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

OPT_IN = "NEMO_RELAY_CLAUDE_DESKTOP_LIVE_POC"
PLUGIN_ID = "tests.claude_desktop_live_poc"
ORIGINAL_MARKER = "NEMO_RELAY_POC_ORIGINAL_7F3A"
REWRITTEN_MARKER = "NEMO_RELAY_POC_REWRITTEN_91C4"
TOOL_SENTINEL = "NEMO_RELAY_CLAUDE_DESKTOP_POC_SENTINEL"
SERVICE_LABEL = "com.nvidia.nemo-relay.claude-desktop"
WINDOWS_TASK = "NeMo Relay Claude Desktop"
LINUX_SERVICE = "nemo-relay-claude-desktop.service"
ATOF_FILENAME = "events.jsonl"
ATIF_FILENAME_TEMPLATE = "trajectory-{session_id}.json"
ATIF_FILENAME_GLOB = "trajectory-*.json"

PROVIDER_ENVIRONMENT = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
)


class PocFailure(RuntimeError):
    """A release-gate assertion failed."""


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes | None
    mode: int | None

    @classmethod
    def capture(cls, path: Path) -> FileSnapshot:
        if not path.exists():
            return cls(path, None, None)
        metadata = path.stat()
        if not path.is_file():
            raise PocFailure(f"expected a regular file at {path}")
        return cls(path, path.read_bytes(), stat.S_IMODE(metadata.st_mode))

    def unchanged(self) -> bool:
        if self.data is None:
            return not self.path.exists()
        if not self.path.is_file() or self.path.read_bytes() != self.data:
            return False
        return os.name == "nt" or stat.S_IMODE(self.path.stat().st_mode) == self.mode

    def restore(self) -> None:
        if self.data is None:
            self.path.unlink(missing_ok=True)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(self.data)
        if self.mode is not None and os.name != "nt":
            self.path.chmod(self.mode)


def capture_pair(paths: tuple[Path, Path]) -> tuple[FileSnapshot, FileSnapshot]:
    """Capture the two Relay plugin configuration files with a fixed tuple type."""
    return FileSnapshot.capture(paths[0]), FileSnapshot.capture(paths[1])


def command_text(command: Sequence[os.PathLike[str] | str]) -> str:
    return shlex.join(os.fspath(part) for part in command)


def run(
    command: Sequence[os.PathLike[str] | str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    input_text: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"+ {command_text(command)}", flush=True)
    result = subprocess.run(
        [os.fspath(part) for part in command],
        cwd=cwd,
        env=dict(environment) if environment is not None else None,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        details = "\n".join(value.strip() for value in (result.stdout or "", result.stderr or "") if value.strip())
        raise PocFailure(
            f"command failed with exit {result.returncode}: {command_text(command)}"
            + (f"\n{details}" if details else "")
        )
    return result


def config_home() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "nemo-relay"


def assert_no_user_observability(path: Path) -> None:
    if not path.is_file():
        return
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise PocFailure(f"invalid TOML in {path}: {error}") from error
    components = config.get("components")
    if isinstance(components, list) and any(
        isinstance(component, dict) and component.get("kind") == "observability" for component in components
    ):
        raise PocFailure(
            f"temporarily remove the user-scoped observability component from {path}; "
            "the live POC installs isolated ATOF and ATIF file exporters and restores the exact baseline afterward"
        )


def toml_string(value: os.PathLike[str] | str) -> str:
    return json.dumps(os.fspath(value))


def observability_component(output_root: Path) -> str:
    return f"""[[components]]
kind = "observability"
enabled = true

[components.config]
version = 2

[components.config.atof]
enabled = true

[[components.config.atof.sinks]]
type = "file"
output_directory = {toml_string(output_root / "atof")}
filename = "{ATOF_FILENAME}"
mode = "overwrite"

[components.config.atif]
enabled = true
agent_name = "Claude Desktop live POC"
output_directory = {toml_string(output_root / "atif")}
filename_template = "{ATIF_FILENAME_TEMPLATE}"
"""


def configure_observability(path: Path, output_root: Path) -> None:
    assert_no_user_observability(path)
    if not path.is_file():
        raise PocFailure(f"Relay did not create the expected user plugin configuration at {path}")
    (output_root / "atof").mkdir(parents=True)
    (output_root / "atif").mkdir()
    existing = path.read_text(encoding="utf-8")
    separator = "" if existing.endswith("\n\n") else "\n" if existing.endswith("\n") else "\n\n"
    rendered = f"{existing}{separator}{observability_component(output_root)}\n"
    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as error:
        raise PocFailure(f"could not compose the live POC observability configuration: {error}") from error
    path.write_text(rendered, encoding="utf-8")


def settings_snapshot() -> tuple[FileSnapshot, FileSnapshot]:
    settings = Path.home() / ".claude" / "settings.json"
    return (
        FileSnapshot.capture(settings),
        FileSnapshot.capture(settings.with_suffix(".json.nemo-relay.bak")),
    )


def semantic_settings(snapshot: FileSnapshot) -> object | None:
    if snapshot.data is None:
        return None
    try:
        return json.loads(snapshot.data)
    except json.JSONDecodeError as error:
        raise PocFailure(f"invalid JSON in baseline {snapshot.path}: {error}") from error


def assert_settings_restored(baseline: tuple[FileSnapshot, FileSnapshot]) -> None:
    current = settings_snapshot()
    if semantic_settings(current[0]) != semantic_settings(baseline[0]):
        raise PocFailure("uninstall did not restore the prior Claude settings value")
    if os.name != "nt" and current[0].mode != baseline[0].mode:
        raise PocFailure("uninstall did not restore prior Claude settings permissions")
    if not baseline[1].unchanged():
        raise PocFailure("uninstall did not restore the prior Claude provider backup")


def trust_inventory() -> str:
    system = platform.system()
    if system == "Darwin":
        keychains = Path.home() / "Library" / "Keychains"
        keychain = keychains / "login.keychain-db"
        if not keychain.exists():
            keychain = keychains / "login.keychain"
        result = run(
            [
                "/usr/bin/security",
                "find-certificate",
                "-a",
                "-c",
                "NeMo Relay Claude Desktop",
                "-Z",
                keychain,
            ],
            check=False,
            capture=True,
        )
        return result.stdout or ""
    if system == "Windows":
        result = run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-ChildItem Cert:\\CurrentUser\\Root | "
                "Where-Object {$_.Subject -like '*NeMo Relay Claude Desktop*'} | "
                "Sort-Object Thumbprint | Select-Object Thumbprint,Subject | ConvertTo-Json -Compress",
            ],
            capture=True,
        )
        return (result.stdout or "").strip()
    return "linux-scoped-ca-bundle"


def desktop_install_root() -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "nemo-relay" / "plugins" / "claude-desktop"
    if system == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise PocFailure("LOCALAPPDATA is required for the Windows live POC")
        return Path(local) / "nemo-relay" / "plugins" / "claude-desktop"
    data = os.environ.get("XDG_DATA_HOME")
    return (Path(data) if data else Path.home() / ".local" / "share") / "nemo-relay" / "plugins" / "claude-desktop"


def service_definition_path(install_root: Path) -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"
    if system == "Windows":
        return install_root / "claude-desktop-task.xml"
    config = os.environ.get("XDG_CONFIG_HOME")
    return (Path(config) if config else Path.home() / ".config") / "systemd" / "user" / LINUX_SERVICE


def service_is_registered() -> bool:
    system = platform.system()
    if system == "Darwin":
        command = ["launchctl", "print", f"gui/{os.getuid()}/{SERVICE_LABEL}"]
    elif system == "Windows":
        command = ["schtasks.exe", "/Query", "/TN", WINDOWS_TASK]
    else:
        command = ["systemctl", "--user", "is-enabled", LINUX_SERVICE]
    return run(command, check=False, capture=True).returncode == 0


def build_poc_plugin(repo: Path, work: Path) -> Path:
    source = repo / "scripts" / "test-support" / "claude-desktop-poc-plugin"
    target = work / "plugin-target"
    run(
        [
            "cargo",
            "build",
            "--manifest-path",
            source / "Cargo.toml",
            "--target-dir",
            target,
        ],
        cwd=repo,
    )
    library_name = {
        "Darwin": "libnemo_relay_claude_desktop_poc_plugin.dylib",
        "Linux": "libnemo_relay_claude_desktop_poc_plugin.so",
        "Windows": "nemo_relay_claude_desktop_poc_plugin.dll",
    }.get(platform.system())
    if library_name is None:
        raise PocFailure(f"unsupported live-POC platform {platform.system()}")
    built = target / "debug" / library_name
    if not built.is_file():
        raise PocFailure(f"POC plugin build did not produce {built}")

    materialized = work / "plugin"
    materialized.mkdir()
    library = materialized / library_name
    shutil.copy2(built, library)
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    template = (source / "relay-plugin.toml").read_text(encoding="utf-8")
    manifest = materialized / "relay-plugin.toml"
    manifest.write_text(
        template.replace("<platform-library-file>", library_name).replace("<artifact-sha256>", digest),
        encoding="utf-8",
    )
    return manifest


def installed_claude_environment() -> dict[str, str]:
    settings = Path.home() / ".claude" / "settings.json"
    value = json.loads(settings.read_text(encoding="utf-8"))
    configured = value.get("env", {})
    if not isinstance(configured, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in configured.items()
    ):
        raise PocFailure(f"{settings} does not contain a string-valued env object")
    environment = os.environ.copy()
    environment.update(configured)
    for name in PROVIDER_ENVIRONMENT:
        if name != "ANTHROPIC_BASE_URL":
            environment.pop(name, None)
    return environment


def assert_oauth_rewrite(claude: str, workspace: Path, environment: Mapping[str, str]) -> None:
    prompt = f"Reply with exactly the marker in this sentence and nothing else: {ORIGINAL_MARKER}"
    result = run(
        [
            claude,
            "-p",
            prompt,
            "--output-format",
            "text",
            "--no-session-persistence",
            "--tools",
            "",
        ],
        capture=True,
        cwd=workspace,
        environment=environment,
        timeout=180,
    )
    output = result.stdout or ""
    if REWRITTEN_MARKER not in output or ORIGINAL_MARKER in output:
        raise PocFailure(
            f"the real Claude response did not expose the Relay request rewrite; received {output.strip()!r}"
        )


def hook_payload(sentinel: Path) -> str:
    return json.dumps(
        {
            "session_id": "nemo-relay-claude-desktop-live-poc",
            "hook_event_name": "PreToolUse",
            "tool_use_id": "poc-tool-1",
            "tool_name": "Bash",
            "tool_input": {"command": f"touch {sentinel}"},
        }
    )


def assert_pre_tool_guardrail(relay: Path, sentinel: Path, environment: Mapping[str, str]) -> None:
    sentinel.unlink(missing_ok=True)
    result = run(
        [
            relay,
            "hook-forward",
            "claude",
            "--gateway-url",
            "http://127.0.0.1:47632",
            "--forward-only",
            "--fail-closed",
        ],
        check=False,
        capture=True,
        environment=environment,
        input_text=hook_payload(sentinel),
        timeout=15,
    )
    if result.returncode == 0:
        raise PocFailure("the sentinel PreToolUse hook was not rejected")
    if sentinel.exists():
        raise PocFailure("the sentinel tool unexpectedly executed")


def load_atof_events(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise PocFailure(f"ATOF did not create {path}")
    events: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise PocFailure(f"could not read ATOF file {path}: {error}") from error
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise PocFailure(f"invalid ATOF JSON at {path}:{line_number}: {error}") from error
        if not isinstance(event, dict):
            raise PocFailure(f"ATOF record {path}:{line_number} is not a JSON object")
        if event.get("atof_version") != "0.1":
            raise PocFailure(f"ATOF record {path}:{line_number} does not use ATOF 0.1")
        events.append(event)
    if not events:
        raise PocFailure(f"ATOF file {path} is empty")
    return events


def load_atif_trajectories(path: Path) -> list[dict[str, object]]:
    files = sorted(path.glob(ATIF_FILENAME_GLOB))
    if not files:
        raise PocFailure(f"ATIF did not create a {ATIF_FILENAME_GLOB} file in {path}")
    trajectories: list[dict[str, object]] = []
    for file in files:
        try:
            contents = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise PocFailure(f"could not read ATIF artifact {file}: {error}") from error
        try:
            trajectory = json.loads(contents)
        except json.JSONDecodeError as error:
            raise PocFailure(f"invalid ATIF JSON in {file}: {error}") from error
        if not isinstance(trajectory, dict):
            raise PocFailure(f"ATIF artifact {file} is not a JSON object")
        if trajectory.get("schema_version") != "ATIF-v1.7":
            raise PocFailure(f"ATIF artifact {file} does not use ATIF-v1.7")
        trajectories.append(trajectory)
    return trajectories


def contains_rewritten_marker(value: object) -> bool:
    return REWRITTEN_MARKER in json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def validate_observability_artifacts(output_root: Path) -> tuple[int, int]:
    events = load_atof_events(output_root / "atof" / ATOF_FILENAME)
    if not any(contains_rewritten_marker(event) for event in events):
        raise PocFailure("the ATOF event stream does not contain the rewritten live POC request")

    trajectories = load_atif_trajectories(output_root / "atif")
    matching = [
        trajectory
        for trajectory in trajectories
        if isinstance(trajectory.get("steps"), list)
        and bool(trajectory["steps"])
        and contains_rewritten_marker(trajectory)
    ]
    if not matching:
        raise PocFailure("no non-empty ATIF trajectory contains the rewritten live POC request")
    return len(events), len(trajectories)


def wait_for_observability_artifacts(output_root: Path, timeout: float = 15) -> tuple[int, int]:
    deadline = time.monotonic() + timeout
    last_error: PocFailure | None = None
    while time.monotonic() < deadline:
        try:
            return validate_observability_artifacts(output_root)
        except PocFailure as error:
            last_error = error
            time.sleep(0.2)
    raise PocFailure(f"observability artifacts were not complete after {timeout:g} seconds: {last_error}")


def require_manual_pass(title: str, instructions: str, sentinel: Path) -> None:
    sentinel.unlink(missing_ok=True)
    print(f"\n--- {title} ---\n{instructions}\n", flush=True)
    answer = input("Type PASS only after both checks succeed: ").strip()
    if answer != "PASS":
        raise PocFailure(f"{title} was not confirmed")
    if sentinel.exists():
        raise PocFailure(f"{title} created the blocked sentinel file")


def stop_sidecar() -> None:
    system = platform.system()
    if system == "Darwin":
        definition = Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"
        run(
            [
                "launchctl",
                "bootout",
                f"gui/{os.getuid()}",
                definition,
            ]
        )
    elif system == "Windows":
        run(["schtasks.exe", "/Change", "/TN", WINDOWS_TASK, "/DISABLE"])
        run(["schtasks.exe", "/End", "/TN", WINDOWS_TASK], check=False)
    elif system == "Linux":
        run(["systemctl", "--user", "stop", LINUX_SERVICE])
    else:
        raise PocFailure(f"unsupported live-POC platform {system}")

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with socket.socket() as connection:
            connection.settimeout(0.2)
            if connection.connect_ex(("127.0.0.1", 47633)) != 0:
                return
        time.sleep(0.1)
    raise PocFailure("the Claude Desktop proxy remained reachable after stopping the sidecar")


def assert_fail_closed_without_sidecar(
    relay: Path,
    claude: str,
    workspace: Path,
    sentinel: Path,
    environment: Mapping[str, str],
) -> None:
    hook = run(
        [
            relay,
            "hook-forward",
            "claude",
            "--gateway-url",
            "http://127.0.0.1:47632",
            "--forward-only",
            "--fail-closed",
        ],
        check=False,
        capture=True,
        environment=environment,
        input_text=hook_payload(sentinel),
        timeout=15,
    )
    if hook.returncode == 0:
        raise PocFailure("PreToolUse did not fail closed while the sidecar was stopped")

    result = run(
        [
            claude,
            "-p",
            "Reply exactly DIRECT_FALLBACK_SUCCEEDED if you receive this request.",
            "--output-format",
            "text",
            "--no-session-persistence",
            "--tools",
            "",
        ],
        check=False,
        capture=True,
        cwd=workspace,
        environment=environment,
        timeout=60,
    )
    if result.returncode == 0 or "DIRECT_FALLBACK_SUCCEEDED" in (result.stdout or ""):
        raise PocFailure("Claude completed inference after the protected sidecar was stopped")


def restore_plugin_configuration(
    baseline: tuple[FileSnapshot, FileSnapshot],
    expected: tuple[FileSnapshot, FileSnapshot] | None,
    relay: Path,
) -> None:
    if expected is not None and all(snapshot.unchanged() for snapshot in expected):
        for snapshot in baseline:
            snapshot.restore()
        return
    run([relay, "plugins", "remove", PLUGIN_ID], check=False)
    raise PocFailure(
        "Relay plugin configuration changed concurrently; removed the POC plugin through the CLI "
        "instead of overwriting those edits"
    )


@dataclass
class PocRun:
    repo: Path
    work: Path
    workspace: Path
    observability_root: Path
    sentinel: Path
    relay: Path
    claude: str
    plugin_paths: tuple[Path, Path]
    plugin_baseline: tuple[FileSnapshot, FileSnapshot]
    claude_baseline: tuple[FileSnapshot, FileSnapshot]
    trust_baseline: str
    install_root: Path
    service_definition_baseline: FileSnapshot
    service_registration_baseline: bool
    plugin_expected: tuple[FileSnapshot, FileSnapshot] | None = None
    desktop_installed: bool = False
    plugin_registered: bool = False
    succeeded: bool = False

    @classmethod
    def create(cls, claude: str) -> PocRun:
        repo = Path(__file__).resolve().parent.parent
        work = Path(tempfile.mkdtemp(prefix="nemo-relay-claude-desktop-poc-"))
        workspace = work / "workspace"
        workspace.mkdir()
        user_config = config_home()
        plugin_paths = (
            user_config / "plugins.toml",
            user_config / ".dynamic-plugins.json",
        )
        install_root = desktop_install_root()
        return cls(
            repo=repo,
            work=work,
            workspace=workspace,
            observability_root=work / "observability",
            sentinel=workspace / TOOL_SENTINEL,
            relay=repo / "target" / "debug" / ("nemo-relay.exe" if os.name == "nt" else "nemo-relay"),
            claude=claude,
            plugin_paths=plugin_paths,
            plugin_baseline=capture_pair(plugin_paths),
            claude_baseline=settings_snapshot(),
            trust_baseline=trust_inventory(),
            install_root=install_root,
            service_definition_baseline=FileSnapshot.capture(service_definition_path(install_root)),
            service_registration_baseline=service_is_registered(),
        )

    def execute(self) -> None:
        self.preflight()
        self.install_poc_plugin()
        self.install_desktop()
        self.verify_terminal_paths()
        self.verify_gui_paths()
        self.verify_observability()
        self.verify_fail_closed()
        self.succeeded = True

    def preflight(self) -> None:
        if self.install_root.exists():
            raise PocFailure(f"remove stale Claude Desktop integration files at {self.install_root} before the POC")
        if self.service_definition_baseline.data is not None or self.service_registration_baseline:
            raise PocFailure("remove the existing Claude Desktop Relay login service before the POC")
        assert_no_user_observability(self.plugin_paths[0])
        run(["cargo", "build", "-p", "nemo-relay-cli", "--bin", "nemo-relay"], cwd=self.repo)
        dry_run = run(
            [self.relay, "install", "claude-desktop", "--dry-run"],
            check=False,
            capture=True,
            cwd=self.workspace,
        )
        if dry_run.returncode != 0:
            raise PocFailure(
                "Claude Desktop protection is already present or its state is not clean:\n"
                + (dry_run.stderr or dry_run.stdout or "unknown preflight failure").strip()
            )
        existing_plugin = run(
            [self.relay, "plugins", "inspect", PLUGIN_ID, "--json"],
            check=False,
            capture=True,
            cwd=self.workspace,
        )
        if existing_plugin.returncode == 0:
            raise PocFailure(f"remove the existing {PLUGIN_ID} record before running the POC")

    def install_poc_plugin(self) -> None:
        run([self.claude, "daemon", "stop", "--any"], check=False, capture=True)
        manifest = build_poc_plugin(self.repo, self.work)
        run([self.relay, "plugins", "add", "--user", manifest], cwd=self.workspace)
        self.plugin_registered = True
        self.plugin_expected = capture_pair(self.plugin_paths)
        run([self.relay, "plugins", "enable", PLUGIN_ID], cwd=self.workspace)
        configure_observability(self.plugin_paths[0], self.observability_root)
        self.plugin_expected = capture_pair(self.plugin_paths)

    def install_desktop(self) -> None:
        run([self.relay, "install", "claude-desktop"], cwd=self.workspace)
        self.desktop_installed = True
        doctor = run(
            [self.relay, "doctor", "--plugin", "claude-desktop", "--json"],
            capture=True,
            cwd=self.workspace,
        )
        report = json.loads(doctor.stdout or "{}")
        if not report.get("effective_protection"):
            raise PocFailure(f"doctor did not report effective protection: {report}")

    def verify_terminal_paths(self) -> None:
        environment = installed_claude_environment()
        assert_oauth_rewrite(self.claude, self.workspace, environment)
        assert_pre_tool_guardrail(self.relay, self.sentinel, environment)

    def verify_gui_paths(self) -> None:
        run([self.relay, "claude-desktop", "--folder", self.workspace], cwd=self.workspace)
        gui_instructions = f"""
In the Code tab opened by `nemo-relay claude-desktop`:
  1. Ask: Reply with exactly {ORIGINAL_MARKER}
     The response must contain {REWRITTEN_MARKER}, proving Relay rewrote the model request.
  2. Ask Claude to use its shell tool to create this file: {self.sentinel}
     The tool must be rejected and the file must remain absent.
""".strip()
        require_manual_pass("wrapped deep-link launch", gui_instructions, self.sentinel)

        icon_instructions = f"""
Quit Claude Desktop completely, relaunch it from the original operating-system application icon,
open a Code session for {self.workspace}, and repeat both checks:
  - {ORIGINAL_MARKER} must become {REWRITTEN_MARKER} in the response.
  - a shell request to create {self.sentinel} must be rejected.
Afterward, quit Claude Desktop completely before typing PASS.
""".strip()
        require_manual_pass("original Claude icon", icon_instructions, self.sentinel)

    def verify_observability(self) -> None:
        event_count, trajectory_count = wait_for_observability_artifacts(self.observability_root)
        print(
            f"Validated {event_count} raw ATOF events and {trajectory_count} ATIF trajectories "
            "from the live POC request.",
            flush=True,
        )

    def verify_fail_closed(self) -> None:
        environment = installed_claude_environment()
        run([self.claude, "daemon", "stop", "--any"], check=False, capture=True)
        stop_sidecar()
        assert_fail_closed_without_sidecar(
            self.relay,
            self.claude,
            self.workspace,
            self.sentinel,
            environment,
        )

    def cleanup(self) -> list[str]:
        errors: list[str] = []
        self.uninstall_desktop(errors)
        self.restore_plugin(errors)
        self.verify_restoration(errors)
        return errors

    def uninstall_desktop(self, errors: list[str]) -> None:
        if not self.desktop_installed:
            return
        uninstall = run(
            [self.relay, "uninstall", "claude-desktop"],
            check=False,
            capture=True,
            cwd=self.workspace,
        )
        if uninstall.returncode != 0:
            errors.append(
                "Claude Desktop uninstall failed; close Claude and run "
                f"`{self.relay} uninstall claude-desktop`: "
                + (uninstall.stderr or uninstall.stdout or "unknown failure").strip()
            )
            return
        self.desktop_installed = False

    def restore_plugin(self, errors: list[str]) -> None:
        if not self.plugin_registered:
            return
        try:
            restore_plugin_configuration(self.plugin_baseline, self.plugin_expected, self.relay)
            self.plugin_registered = False
        except PocFailure as error:
            errors.append(str(error))

    def verify_restoration(self, errors: list[str]) -> None:
        if self.desktop_installed:
            return
        try:
            assert_settings_restored(self.claude_baseline)
        except PocFailure as error:
            errors.append(str(error))
        if trust_inventory() != self.trust_baseline:
            errors.append("uninstall did not restore the prior user trust inventory")
        if not self.service_definition_baseline.unchanged():
            errors.append("uninstall did not restore the prior login-service definition")
        if service_is_registered() != self.service_registration_baseline:
            errors.append("uninstall did not restore the prior login-service registration")
        if self.install_root.exists():
            errors.append(f"uninstall left the integration install root at {self.install_root}")

    def finish(self, cleanup_errors: list[str]) -> None:
        if cleanup_errors:
            print(f"POC workspace retained at {self.work}", file=sys.stderr)
            raise PocFailure("; ".join(cleanup_errors))
        if not self.succeeded:
            raise PocFailure("the live POC did not complete")
        shutil.rmtree(self.work)
        print(
            "PASS: OAuth, request rewriting, ATOF and ATIF file observability, PreToolUse rejection, "
            "sidecar fail-closed behavior, both GUI launch paths, and uninstall restoration were validated."
        )


def validate_host() -> str:
    current_platform = platform.system()
    if current_platform not in {"Darwin", "Windows", "Linux"}:
        raise PocFailure(f"unsupported platform {current_platform}")
    configured_credentials = [name for name in PROVIDER_ENVIRONMENT if os.environ.get(name)]
    if configured_credentials:
        raise PocFailure(
            "unset provider credentials and custom routing before the OAuth POC: " + ", ".join(configured_credentials)
        )
    claude = shutil.which("claude")
    if claude is None:
        raise PocFailure("the supported terminal Claude Code executable is not on PATH")
    return claude


def main() -> int:
    if os.environ.get(OPT_IN) != "1":
        print(f"SKIP: set {OPT_IN}=1 only on a release-gate account after reading this script's warning")
        return 0
    poc = PocRun.create(validate_host())
    print(
        "This test will install current-user TLS trust, a login service, Claude settings, and isolated "
        "ATOF and ATIF file exporters; it consumes real Claude subscription requests and requires GUI confirmation.",
        flush=True,
    )
    input("Confirm Claude Desktop and all terminal Claude processes are closed, then press Enter: ")

    try:
        poc.execute()
    finally:
        cleanup_errors = poc.cleanup()
    poc.finish(cleanup_errors)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PocFailure, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
