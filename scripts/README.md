<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Scripts

The canonical build and test surface now lives in the repository `justfile`.
Use `just --list` to discover supported developer workflows.

Keep `scripts/` focused on helpers that are still script-native:

## Top-Level Commands

- `build-docs.sh`: compatibility wrapper around the Fern documentation validation recipe; it regenerates ignored Fern API reference pages before checking the site
- `generate_attributions.sh`: regenerate attribution documents
- `test-install.sh`: Run live GitHub release and local interface checks for the curl-based CLI installer
- `test-install.ps1`: Run live GitHub release and local interface checks for the PowerShell CLI installer
- `test-install-mocks.sh`: Run installer scenarios that require simulated platforms or failures

## Opt-In Coding-Agent E2E Tests

These checks exercise installed coding-agent clients and are intentionally
outside the default Rust and CI test suites. Each proxy test requires its
documented `NEMO_RELAY_*_LIVE_E2E=1` gate because it temporarily changes real
agent configuration, makes a provider request, and restores the previous
configuration on exit. On macOS and Windows, enrollment also changes
current-user TLS trust. Linux instead writes agent-scoped CA bundles and leaves
the system trust store unchanged. Once a lane is selected, missing agent or
provider prerequisites fail instead of skipping. Individual scripts differ in
their assertions: Claude Desktop is a manual GUI proof and does not currently perform
the automated service-stop check. The Codex lane runs the installed provider
with WebSockets enabled, forces an HTTP/SSE fallback, runs two concurrent
sessions, verifies the two transport tags and overlapping call intervals from
an isolated ATOF sink, verifies fail-closed service loss, and then checks
uninstall. Automated CLI lanes stop and restart the per-user LaunchAgent,
systemd user unit, or SID-derived Windows scheduled task; selected Windows
lanes do not skip service-loss enforcement.

- `NEMO_RELAY_CODEX_LIVE_E2E=1 just test-codex-plugin-e2e`
- `NEMO_RELAY_CLAUDE_LIVE_E2E=1 just test-claude-plugin-e2e`
- `NEMO_RELAY_CLAUDE_DESKTOP_LIVE_POC=1 just test-claude-desktop-live-poc` (configures platform-specific agent trust and the per-user service, opens the protected Code tab, and pauses for GUI confirmation)
- `NEMO_RELAY_HERMES_LIVE_E2E=1 NEMO_RELAY_HERMES_UNKNOWN_PROVIDER_COMMAND='<successful unknown-provider Hermes command>' just test-hermes-agent-proxy-e2e` selects the provisioned Hermes release lane. Once selected, missing Hermes/provider setup or nonexclusive degraded markers fail instead of skipping.

The Hermes live gate requires `NEMO_RELAY_HERMES_UNKNOWN_PROVIDER_COMMAND` to
be an explicit Hermes command that uses an unsupported public HTTPS provider.
The script gives the proxy an isolated ATOF sink, requires the command to
succeed through the opaque tunnel, and verifies that every resulting provider
classification is
`managed_inference=false` and `observability_mode=hook_only_degraded`, with no
managed classification in that command's event window. Run these tests only
with no pre-existing Relay coding-agent enrollment; the installer refuses
legacy or incompatible state instead of migrating it.

## Internal Layout

- `docs/`: Fern reference-generation, migration cleanup, and `docs-website` branch sync helpers. Generated API reference output under `docs/reference/api/*-library-reference/` is ignored and recreated by `just docs`.
- `licensing/`: attribution generation helpers, including license inventory diff scripts
- `lint/`: pre-commit and local lint helpers
- `test-support/`: shared test utilities
