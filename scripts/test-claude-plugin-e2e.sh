#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "${NEMO_RELAY_CLAUDE_LIVE_E2E:-0}" != "1" ]]; then
    echo "SKIP: set NEMO_RELAY_CLAUDE_LIVE_E2E=1 to mutate agent configuration and platform-specific trust, then run a real Claude request"
    exit 0
fi
if ! command -v claude >/dev/null 2>&1; then
    echo "ERROR: the selected Claude Code live lane requires claude on PATH" >&2
    exit 2
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-support/agent_proxy_live.sh"
relay_live_setup claude-code
trap relay_live_cleanup EXIT
relay_install_and_verify

plugin_root="$relay_live_install/claude-code-marketplace/plugins/nemo-relay-plugin"
test ! -e "$plugin_root/.mcp.json"
grep -q "hook-forward claude" "$plugin_root/hooks/hooks.json"

claude -p "Reply with exactly RELAY_PROXY_OK" \
    --output-format json \
    --no-session-persistence \
    --tools "" >"$relay_live_work/claude.json"
grep -q "RELAY_PROXY_OK" "$relay_live_work/claude.json"

relay_stop_service
set +e
claude -p "Reply with exactly SHOULD_NOT_SUCCEED" \
    --output-format json \
    --no-session-persistence \
    --tools "" >"$relay_live_work/stopped.stdout" 2>"$relay_live_work/stopped.stderr"
stopped_status=$?
set -e
test "$stopped_status" -ne 0
relay_start_service
relay_wait_for_service

nemo-relay uninstall claude-code --install-dir "$relay_live_install"
relay_live_installed=0
echo "Claude Code unified proxy live test passed"
