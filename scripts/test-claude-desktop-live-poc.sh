#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "${NEMO_RELAY_CLAUDE_DESKTOP_LIVE_POC:-0}" != "1" ]]; then
    echo "SKIP: set NEMO_RELAY_CLAUDE_DESKTOP_LIVE_POC=1 to mutate agent configuration and platform-specific trust, then open Claude Desktop"
    exit 0
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-support/agent_proxy_live.sh"
relay_live_setup claude-desktop
trap relay_live_cleanup EXIT
relay_install_and_verify

mkdir -p "$relay_live_work/workspace"
nemo-relay claude-desktop --folder "$relay_live_work/workspace"
echo "In the opened Claude Desktop Code tab, complete one provider request."
echo "Close Claude Desktop completely, then press Enter to continue validation."
read -r

nemo-relay doctor claude-desktop --install-dir "$relay_live_install"
nemo-relay uninstall claude-desktop --install-dir "$relay_live_install"
relay_live_installed=0
echo "Claude Desktop unified proxy live test passed"
