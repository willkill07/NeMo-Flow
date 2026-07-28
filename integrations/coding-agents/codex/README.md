<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Codex Integration Assets

This directory contains Codex plugin metadata. It intentionally does not
publish a static `hooks/hooks.json`: a static command cannot carry the
installer-owned generation path and token required by fail-closed delivery.
Do not install this source directory directly.

Install Codex with:

```bash
nemo-relay install codex
# Linux only: export CODEX_CA_CERTIFICATE="<path printed by install>"
nemo-relay doctor codex
```

The installer creates the authenticated `nemo-relay-openai` provider alias at
the discovered per-user listener, sets `supports_websockets=true`, preserves
ChatGPT OAuth or API-key upstream routing, and generates a private marketplace
copy with fenced supported hooks. It does not install a Relay MCP server or
require a wrapper launch.

Responses HTTP, SSE, and WebSocket calls use the same managed-provider engine.
Each WebSocket `response.create` is decoded, rewritten through Relay
middleware, re-encoded, collected, and finalized as one streaming LLM call.
Only one response is active per connection.

For live validation, cover OAuth and API-key modes, HTTP/SSE and WebSockets,
request rewrite, hook correlation, concurrent sessions, service-stop
fail-closed behavior, backpressure, malformed frames, retry boundaries, and
exact uninstall restoration.
