<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Claude Code Integration Assets

This directory contains Claude plugin metadata. It intentionally does not
publish a static `hooks/hooks.json`: a static command cannot carry the
installer-owned generation path and token required by fail-closed delivery.
Do not install this source directory directly.

Install Claude Code with:

```bash
nemo-relay install claude-code
nemo-relay doctor claude-code
```

The installer patches authenticated HTTPS proxy and CA settings, preserves
native OAuth, and generates a private marketplace copy whose hook commands
carry the enrollment credential and generation fence. It does not install a
Relay MCP server or require a wrapper launch.

Claude provider traffic to `api.anthropic.com` is TLS-intercepted with an
exact-host leaf and passed to the shared managed-provider engine. The Claude
credential rejects every other destination, including otherwise public hosts.

The same service can own a separate `claude-desktop` enrollment. Uninstalling
one Claude enrollment preserves shared settings still owned by the other.

For live validation, exercise native OAuth, a request rewrite, a blocked tool,
service-stop fail-closed behavior, concurrent sessions, and exact uninstall
restoration.
