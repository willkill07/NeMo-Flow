#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared support for opt-in tests that mutate agent configuration and platform-specific trust.

relay_live_setup() {
    relay_live_agent="$1"
    relay_live_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    relay_live_work="$(mktemp -d)"
    relay_live_install="$relay_live_work/install"
    relay_live_installed=0
    (
        cd "$relay_live_repo"
        cargo build -p nemo-relay-cli --bin nemo-relay
    )
    export PATH="$relay_live_repo/target/debug:$PATH"
}

relay_live_platform() {
    if [[ "${OS:-}" == "Windows_NT" ]]; then
        echo "Windows"
    else
        uname -s
    fi
}

relay_live_cleanup() {
    local cleanup_failed=0
    if [[ "${relay_live_installed:-0}" == "1" ]]; then
        if ! relay_start_service >/dev/null 2>&1; then
            echo "WARNING: could not restart the Relay service before cleanup." >&2
            cleanup_failed=1
        fi
        if ! nemo-relay uninstall "$relay_live_agent" \
            --install-dir "$relay_live_install"; then
            echo "ERROR: live-test uninstall failed; recovery state is preserved." >&2
            echo "Retry: nemo-relay uninstall $relay_live_agent --install-dir $relay_live_install" >&2
            cleanup_failed=1
        fi
    fi
    if [[ "$cleanup_failed" == "1" ]]; then
        echo "Live proxy test workspace retained at $relay_live_work" >&2
        return 1
    elif [[ "${NEMO_RELAY_E2E_KEEP_WORK:-0}" == "1" ]]; then
        echo "Live proxy test workspace retained at $relay_live_work" >&2
    elif [[ -n "${relay_live_work:-}" && -d "$relay_live_work" ]]; then
        rm -rf "$relay_live_work"
    fi
}

relay_install_and_verify() {
    nemo-relay install "$relay_live_agent" --install-dir "$relay_live_install"
    relay_live_installed=1
    if [[ "$(relay_live_platform)" == "Linux" && "$relay_live_agent" == "codex" ]]; then
        export CODEX_CA_CERTIFICATE="$relay_live_install/agent-proxy/codex-ca-bundle.pem"
    fi
    nemo-relay doctor "$relay_live_agent" --install-dir "$relay_live_install"
    python3 - "$relay_live_install/agent-proxy/state.json" "$relay_live_agent" <<'PY'
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text())
agent = sys.argv[2]
host, port = state["bind"].rsplit(":", 1)
assert state["schema_version"] == 5, state["schema_version"]
assert host == "127.0.0.1", host
assert 0 < int(port) < 65536, port
assert agent in state["enrollments"], state["enrollments"].keys()
assert len({row["token"] for row in state["enrollments"].values()}) == len(
    state["enrollments"]
)
PY
}

relay_windows_task_name() {
    python3 - "$relay_live_install/agent-proxy/state.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text())
identity = state["service_identity"]
assert state["platform"] == "windows", state["platform"]
assert identity.startswith("S-1-"), identity
suffix = hashlib.sha256(identity.lower().encode()).hexdigest()[:16]
print(f"NeMo Relay Agent Proxy {suffix}")
PY
}

relay_stop_service() {
    case "$(relay_live_platform)" in
        Darwin)
            launchctl bootout \
                "gui/$(id -u)" \
                "$HOME/Library/LaunchAgents/com.nvidia.nemo-relay.agent-proxy.plist"
            ;;
        Linux)
            systemctl --user stop nemo-relay-agent-proxy.service
            ;;
        Windows)
            schtasks.exe /End /TN "$(relay_windows_task_name)"
            ;;
        *)
            echo "ERROR: unsupported live-test platform" >&2
            return 2
            ;;
    esac
}

relay_start_service() {
    case "$(relay_live_platform)" in
        Darwin)
            launchctl bootstrap \
                "gui/$(id -u)" \
                "$HOME/Library/LaunchAgents/com.nvidia.nemo-relay.agent-proxy.plist" \
                2>/dev/null || true
            launchctl kickstart \
                -k "gui/$(id -u)/com.nvidia.nemo-relay.agent-proxy"
            ;;
        Linux)
            systemctl --user start nemo-relay-agent-proxy.service
            ;;
        Windows)
            schtasks.exe /Run /TN "$(relay_windows_task_name)"
            ;;
        *)
            echo "ERROR: unsupported live-test platform" >&2
            return 2
            ;;
    esac
}

relay_wait_for_service() {
    for _ in $(seq 1 100); do
        if nemo-relay doctor "$relay_live_agent" \
            --install-dir "$relay_live_install" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "the per-user coding-agent proxy did not restart" >&2
    return 1
}
