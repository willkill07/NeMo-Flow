<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Coding-Agent Integrations

NeMo Relay enrolls local Claude Code/Desktop, Codex, and Hermes clients in one
persistent authenticated proxy per OS user. Transparent wrappers, Relay MCP
lifecycle entries, gateway leases, and standalone coding-agent gateways have
been removed.

```text
agent native provider traffic ---\
agent lifecycle hooks ------------> per-user Relay proxy --> managed execution
Codex Responses WebSocket --------/
```

The listener uses a discovered and persisted loopback port, not a fixed
machine-wide port. Every enrollment has its own stored credential, route
policy, and configuration ownership. Claude Code/Desktop share one effective
provider credential and upstream route because they use one Claude settings
file.

## Install

```bash
nemo-relay install <claude-code|claude-desktop|codex|hermes|all>
nemo-relay doctor <agent>
```

The first enrollment installs a constrained CA in the macOS login Keychain or
Windows CurrentUser Root store. Linux writes agent-scoped CA bundles instead
of changing system trust. It also registers the platform user service. Close
agents before a force reinstall or certificate rotation.

Start enrolled clients normally. `hook-forward` remains an internal
fail-closed hook transport; `nemo-relay claude-desktop` remains the protected
Desktop deep-link command.

The checked-in host plugin directories contain metadata only and are not
direct-install packages; the repository no longer advertises a source
marketplace. `nemo-relay install` generates the private marketplace copy and
its generation-fenced hook commands transactionally. This avoids publishing a
static hook command that could bypass proxy identity checks.

## Configuration

Coding-agent sessions load system and user Relay configuration only. Project
`.nemo-relay` coding-agent configuration is intentionally ignored.

The initial managed native hosts are:

- `api.anthropic.com`
- `api.openai.com`
- `chatgpt.com`

Claude and Codex credentials reject hosts outside their managed host sets.
Hermes is the only exception: an unknown provider tunnels only when it is an
eligible public HTTPS destination reached with `CONNECT` on port 443.
Private/reserved destinations and other ports are rejected. Hermes hook events
are labeled managed only after authenticated enrollment delivery and canonical
HTTPS/443 native-route validation. HTTP, alternate-port, or
credential-bearing URLs, and unsupported paths on managed native hosts, fail
closed instead of tunneling. A Hermes hook that reports a URL outside the
managed criteria is labeled `managed_inference=false` and
`observability_mode=hook_only_degraded`; that label does not mean Relay
permitted the corresponding provider traffic.

## Security

- Agent credentials authorize only their own managed provider and hook routes.
- `CONNECT`, SNI, HTTP `Host`, method, and path must agree.
- Leaf certificates are short-lived and exact-host.
- macOS uses a non-exportable login Keychain CA key.
- Windows uses a non-exportable current-user CNG CA key.
- Linux uses an owner-only PKCS#8 CA key.
- Installed hooks fail closed on identity, generation, settings, payload, or
  delivery errors.

The trust model protects against accidental bypass and service failure. It is
not tamper-resistant enforcement against the local account owner.

## Corporate Proxies

Enrollment retains supported explicit HTTP(S) routes, including Basic
authentication, custom CA bundles, and sanitized `NO_PROXY` behavior. It reads
owned agent configuration and the installer environment, not OS/GUI proxy
settings. SOCKS, PAC/autodiscovery, NTLM, Kerberos, and platform-integrated
authentication are unsupported. Doctor reports conflicting
higher-precedence Hermes proxy variables. Bare IPv6 exclusions are supported;
IPv6 entries with ports require bracket syntax. Relay removes CIDR exclusions
because it cannot prove offline that a network excludes every current and
future managed-provider address.

## Smoke Tests

Build the CLI and use an isolated test account or disposable agent homes.
Opt-in live tests require real agent/provider credentials and current supported
agent versions.

### Shared checks

For every agent:

1. Preview installation and verify that the platform trust action and dynamic
   endpoint-selection policy are disclosed. Dry-run does not reserve or print
   the final endpoint.
2. Install and run `doctor`.
3. Confirm the service state, generation, settings fingerprint, trust
   fingerprint, and hooks pass.
4. Run two concurrent sessions and confirm their Relay roots are distinct.
5. Apply a request rewrite and confirm the provider receives it.
6. Apply a blocking tool guardrail and confirm the agent blocks.
7. Stop the proxy service and confirm provider traffic and installed hooks fail
   closed.
8. Restart the service and confirm recovery.
9. Uninstall and verify exact settings restoration.
10. After the final uninstall, verify the service, exact macOS/Windows
    current-user CA trust or Linux agent bundles, signer, cache, locator, and
    shared state are removed. On Linux, apply the printed Codex launch-variable
    restoration before restarting Codex.

### Claude live gate

- Exercise bare Claude Code and the Claude Desktop Code tab with native OAuth.
- Verify managed Anthropic HTTP/SSE and lifecycle correlation.
- Open Desktop through `nemo-relay claude-desktop --folder <path>`.
- Confirm Chat, Cowork, and cloud activity are not claimed.

### Codex live gate

- Exercise ChatGPT OAuth and API-key routing.
- Exercise Responses HTTP/SSE and WebSocket transport.
- For WebSockets, verify request rewrite, terminal completion, ping/pong/close,
  malformed/binary rejection, disconnect cleanup, serialized responses,
  backpressure, and no retry after the first response event.
- Exercise CLI and local app sessions plus trusted hooks.

### Hermes live gate

- Exercise at least one managed native provider in a local mode.
- Exercise an unknown public provider and verify hook-only/degraded labels.
- Exercise CLI, gateway, cron, API-server, ACP, or desktop-backed modes as
  supported by the installed Hermes release.
- Verify ambient proxy conflicts are diagnosed.

## Clean Reinstall

New enrollment refuses wrapper/MCP-gateway and old Claude Desktop state. Close
agents and legacy Relay processes, uninstall every integration with the old
binary, and explicitly verify that the old wrapper/MCP gateway and Claude
Desktop sidecar processes or user services are stopped and their state and
locator entries are gone. Do not install the new enrollment while the old
gateway health endpoint still responds. Then install the new binary and enroll
again. There is no automatic migration or dual-mode compatibility.

See the public [Coding Agent
Installation](../../docs/nemo-relay-cli/plugin-installation.mdx) guide and the
internal [architecture record](../../docs/design/unified-coding-agent-proxy.md).
