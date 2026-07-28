#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "${NEMO_RELAY_CODEX_LIVE_E2E:-0}" != "1" ]]; then
    echo "SKIP: set NEMO_RELAY_CODEX_LIVE_E2E=1 to mutate agent configuration and platform-specific trust, then run a real Codex request"
    exit 0
fi
if ! command -v codex >/dev/null 2>&1; then
    echo "ERROR: the selected Codex live lane requires codex on PATH" >&2
    exit 2
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-support/agent_proxy_live.sh"
relay_live_setup codex
trap relay_live_cleanup EXIT

relay_live_atof="$relay_live_work/atof"
export XDG_CONFIG_HOME="$relay_live_work/config"
mkdir -p "$XDG_CONFIG_HOME/nemo-relay" "$relay_live_atof"
python3 - "$XDG_CONFIG_HOME/nemo-relay/plugins.toml" "$relay_live_atof" <<'PY'
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
output_directory = Path(sys.argv[2])
config_path.write_text(
    f"""version = 1

[[components]]
kind = "observability"
enabled = true

[components.config]
version = 2

[components.config.atof]
enabled = true

[[components.config.atof.sinks]]
type = "file"
output_directory = {str(output_directory)!r}
filename = "events.jsonl"
mode = "append"
"""
)
PY
relay_install_and_verify

codex_home="${CODEX_HOME:-$HOME/.codex}"
python3 - "$codex_home/config.toml" <<'PY'
import sys
import tomllib
from pathlib import Path

config = tomllib.loads(Path(sys.argv[1]).read_text())
provider = config["model_providers"]["nemo-relay-openai"]
assert config["model_provider"] == "nemo-relay-openai"
assert provider["base_url"].startswith("https://127.0.0.1:")
assert provider["supports_websockets"] is True
assert "x-nemo-relay-agent-authorization" in provider["http_headers"]
assert "x-nemo-relay-client-token" not in provider["http_headers"]
assert "mcp_servers" not in config or "nemo-relay" not in config["mcp_servers"]
PY

(
    cd "$relay_live_work"
    codex exec --ephemeral --skip-git-repo-check \
        "Reply with exactly RELAY_PROXY_WEBSOCKET_OK" >"$relay_live_work/codex-websocket.stdout"
)
grep -q "RELAY_PROXY_WEBSOCKET_OK" "$relay_live_work/codex-websocket.stdout"

(
    cd "$relay_live_work"
    codex exec --ephemeral --skip-git-repo-check \
        -c 'model_providers.nemo-relay-openai.supports_websockets=false' \
        "Reply with exactly RELAY_PROXY_HTTP_SSE_OK" >"$relay_live_work/codex-http-sse.stdout"
)
grep -q "RELAY_PROXY_HTTP_SSE_OK" "$relay_live_work/codex-http-sse.stdout"

(
    cd "$relay_live_work"
    codex exec --ephemeral --skip-git-repo-check \
        "Reply with exactly RELAY_PROXY_CONCURRENT_ONE"
) >"$relay_live_work/codex-concurrent-one.stdout" 2>"$relay_live_work/codex-concurrent-one.stderr" &
codex_first_pid=$!
(
    cd "$relay_live_work"
    codex exec --ephemeral --skip-git-repo-check \
        "Reply with exactly RELAY_PROXY_CONCURRENT_TWO"
) >"$relay_live_work/codex-concurrent-two.stdout" 2>"$relay_live_work/codex-concurrent-two.stderr" &
codex_second_pid=$!
wait "$codex_first_pid"
wait "$codex_second_pid"
grep -q "RELAY_PROXY_CONCURRENT_ONE" "$relay_live_work/codex-concurrent-one.stdout"
grep -q "RELAY_PROXY_CONCURRENT_TWO" "$relay_live_work/codex-concurrent-two.stdout"

python3 - "$relay_live_atof/events.jsonl" <<'PY'
import json
import sys
import time
from datetime import datetime
from pathlib import Path

events_path = Path(sys.argv[1])


def contains(value, marker):
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(contains(child, marker) for child in value.values())
    if isinstance(value, list):
        return any(contains(child, marker) for child in value)
    return False


def timestamp(row):
    return datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))


def root_uuid(row, by_uuid):
    seen = set()
    current = row
    while current.get("parent_uuid"):
        parent = current["parent_uuid"]
        assert parent not in seen, "ATOF parent lineage contains a cycle"
        seen.add(parent)
        current = by_uuid[parent]
    return current["uuid"]


def verify(rows):
    llm = [row for row in rows if row.get("category") == "llm"]
    starts = [row for row in llm if row.get("scope_category") == "start"]
    ends = {
        row["uuid"]: row for row in llm if row.get("scope_category") == "end"
    }
    by_uuid = {row["uuid"]: row for row in rows}

    websocket = [
        row
        for row in starts
        if contains(row, "RELAY_PROXY_WEBSOCKET_OK")
        and row.get("metadata", {}).get("transport") == "websocket"
    ]
    assert websocket, "no WebSocket-tagged managed LLM start event was observed"

    http_sse = [
        row
        for row in starts
        if contains(row, "RELAY_PROXY_HTTP_SSE_OK")
        and row.get("metadata", {}).get("transport") == "http_sse"
    ]
    assert http_sse, "no HTTP/SSE-tagged managed LLM start event was observed"

    intervals = {}
    sessions = {}
    roots = {}
    for marker in ("RELAY_PROXY_CONCURRENT_ONE", "RELAY_PROXY_CONCURRENT_TWO"):
        marked = [
            row
            for row in starts
            if contains(row, marker) and row["uuid"] in ends
        ]
        intervals[marker] = [
            (timestamp(row), timestamp(ends[row["uuid"]])) for row in marked
        ]
        assert intervals[marker], f"no complete managed interval was observed for {marker}"
        sessions[marker] = {
            row.get("metadata", {}).get("session_id") for row in marked
        } - {None, ""}
        roots[marker] = {root_uuid(row, by_uuid) for row in marked}
        assert sessions[marker], f"no canonical session ID was observed for {marker}"
        assert roots[marker], f"no canonical root lineage was observed for {marker}"

    assert any(
        first_start < second_end and second_start < first_end
        for first_start, first_end in intervals["RELAY_PROXY_CONCURRENT_ONE"]
        for second_start, second_end in intervals["RELAY_PROXY_CONCURRENT_TWO"]
    ), "the two Codex live sessions did not overlap"
    assert sessions["RELAY_PROXY_CONCURRENT_ONE"].isdisjoint(
        sessions["RELAY_PROXY_CONCURRENT_TWO"]
    ), "the concurrent Codex calls collapsed into one Relay session ID"
    assert roots["RELAY_PROXY_CONCURRENT_ONE"].isdisjoint(
        roots["RELAY_PROXY_CONCURRENT_TWO"]
    ), "the concurrent Codex calls collapsed into one Relay root lineage"


deadline = time.monotonic() + 15
last_error = "ATOF events were not available"
while time.monotonic() < deadline:
    try:
        rows = [
            json.loads(line)
            for line in events_path.read_text().splitlines()
            if line.strip()
        ]
        verify(rows)
        break
    except (AssertionError, FileNotFoundError, KeyError, ValueError) as error:
        last_error = str(error)
        time.sleep(0.1)
else:
    raise SystemExit(f"Codex transport/concurrency evidence failed: {last_error}")
PY

relay_stop_service
set +e
(
    cd "$relay_live_work"
    codex exec --ephemeral --skip-git-repo-check \
        "Reply with exactly SHOULD_NOT_SUCCEED"
) >"$relay_live_work/stopped.stdout" 2>"$relay_live_work/stopped.stderr"
stopped_status=$?
set -e
test "$stopped_status" -ne 0
relay_start_service
relay_wait_for_service

nemo-relay uninstall codex --install-dir "$relay_live_install"
relay_live_installed=0
echo "Codex unified proxy live test passed with observed WebSocket, HTTP/SSE, and overlapping managed sessions"
