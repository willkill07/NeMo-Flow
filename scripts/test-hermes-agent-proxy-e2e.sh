#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "${NEMO_RELAY_HERMES_LIVE_E2E:-0}" != "1" ]]; then
    echo "SKIP: set NEMO_RELAY_HERMES_LIVE_E2E=1 to mutate agent configuration and platform-specific trust, then run a real Hermes request"
    exit 0
fi
if ! command -v hermes >/dev/null 2>&1; then
    echo "ERROR: the selected Hermes live lane requires hermes on PATH" >&2
    exit 2
fi
if [[ -z "${NEMO_RELAY_HERMES_UNKNOWN_PROVIDER_COMMAND:-}" ]]; then
    echo "ERROR: set NEMO_RELAY_HERMES_UNKNOWN_PROVIDER_COMMAND to a successful local Hermes command that uses an unknown public HTTPS provider" >&2
    exit 2
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-support/agent_proxy_live.sh"
relay_live_setup hermes
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

hermes_home="${HERMES_HOME:-$HOME/.hermes}"
grep -q "^HTTPS_PROXY=https://nemo-relay-hermes:" "$hermes_home/.env"
grep -q "^NODE_EXTRA_CA_CERTS=" "$hermes_home/.env"
if uv run python - "$hermes_home/config.yaml" <<'PY'
import sys
from pathlib import Path

import yaml

config = yaml.safe_load(Path(sys.argv[1]).read_text()) or {}
servers = config.get("mcp_servers") or {}
raise SystemExit(0 if "nemo-relay" in servers else 1)
PY
then
    echo "Hermes still contains a Relay MCP entry" >&2
    exit 1
fi
grep -q "hook-forward hermes" "$hermes_home/config.yaml"

hermes -z "Reply with exactly RELAY_PROXY_OK" \
    --provider openai-api \
    --model "${NEMO_RELAY_HERMES_TEST_MODEL:-gpt-4o-mini}" \
    >"$relay_live_work/hermes.stdout"
grep -q "RELAY_PROXY_OK" "$relay_live_work/hermes.stdout"

relay_live_events="$relay_live_atof/events.jsonl"
unknown_event_offset=0
if [[ -f "$relay_live_events" ]]; then
    unknown_event_offset="$(wc -l <"$relay_live_events")"
fi
bash -lc "$NEMO_RELAY_HERMES_UNKNOWN_PROVIDER_COMMAND"
python3 - "$relay_live_events" "$unknown_event_offset" <<'PY'
import json
import sys
import time
from pathlib import Path

events_path = Path(sys.argv[1])
offset = int(sys.argv[2])


def metadata_values(value, key):
    if isinstance(value, dict):
        for name, child in value.items():
            if name == key:
                yield child
            yield from metadata_values(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from metadata_values(child, key)


deadline = time.monotonic() + 10
while True:
    lines = events_path.read_text().splitlines()[offset:] if events_path.exists() else []
    rows = [json.loads(line) for line in lines if line.strip()]
    managed = [item for row in rows for item in metadata_values(row, "managed_inference")]
    modes = [item for row in rows for item in metadata_values(row, "observability_mode")]
    if managed and modes:
        if all(item is False for item in managed) and all(
            item == "hook_only_degraded" for item in modes
        ):
            break
        raise SystemExit(
            "unknown-provider command produced non-degraded Hermes classification "
            f"after ATOF line {offset}: managed={managed!r}, modes={modes!r}"
        )
    if time.monotonic() >= deadline:
        raise SystemExit(
            "unknown-provider command produced no hook-only/degraded Hermes event "
            f"after ATOF line {offset}: managed={managed!r}, modes={modes!r}"
        )
    time.sleep(0.1)
PY

relay_stop_service
set +e
hermes -z "Reply with exactly SHOULD_NOT_SUCCEED" \
    --provider openai-api \
    --model "${NEMO_RELAY_HERMES_TEST_MODEL:-gpt-4o-mini}" \
    >"$relay_live_work/stopped.stdout" 2>"$relay_live_work/stopped.stderr"
stopped_status=$?
set -e
test "$stopped_status" -ne 0
relay_start_service
relay_wait_for_service

nemo-relay uninstall hermes --install-dir "$relay_live_install"
relay_live_installed=0
echo "Hermes native-provider and opaque unknown-provider checks passed; unknown-provider hooks were exclusively labeled managed_inference=false and observability_mode=hook_only_degraded"
