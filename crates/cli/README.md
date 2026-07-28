<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

[![License](https://img.shields.io/github/license/NVIDIA/NeMo-Relay)](https://github.com/NVIDIA/NeMo-Relay/blob/main/LICENSE)
[![GitHub](https://img.shields.io/badge/github-repo-blue?logo=github)](https://github.com/NVIDIA/NeMo-Relay/)
[![Release](https://img.shields.io/github/v/release/NVIDIA/NeMo-Relay?color=green)](https://github.com/NVIDIA/NeMo-Relay/releases)
[![Codecov](https://codecov.io/gh/NVIDIA/NeMo-Relay/branch/main/graph/badge.svg)](https://app.codecov.io/gh/NVIDIA/NeMo-Relay)
[![PyPI](https://img.shields.io/pypi/v/nemo-relay?color=4B8BBE&logo=pypi)](https://pypi.org/project/nemo-relay/)
[![npm node](https://img.shields.io/npm/v/nemo-relay-node?label=nemo-relay-node&color=CC3534&logo=npm)](https://www.npmjs.com/package/nemo-relay-node)
[![Crates.io](https://img.shields.io/crates/v/nemo-relay?label=nemo-relay&color=B7410E&logo=rust)](https://crates.io/crates/nemo-relay)
[![Crates.io](https://img.shields.io/crates/v/nemo-relay-adaptive?label=nemo-relay-adaptive&color=B7410E&logo=rust)](https://crates.io/crates/nemo-relay-adaptive)
[![Crates.io](https://img.shields.io/crates/v/nemo-relay-cli?label=nemo-relay-cli&color=B7410E&logo=rust)](https://crates.io/crates/nemo-relay-cli)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/NVIDIA/NeMo-Relay)

# NeMo Relay

`nemo-relay-cli` installs the NeMo Relay CLI, the `nemo-relay` binary for local
coding-agent observability and policy enforcement. It enrolls supported local
agents in one persistent proxy for the current OS user and diagnoses agent,
proxy, certificate, hook, and exporter readiness.

The CLI is a Rust package in this repository, but most users should interact
with the installed `nemo-relay` command rather than link against the crate.

## Why Use It?

The CLI is designed for these tasks:

- **Observe existing coding agents**: Enroll Claude Code/Desktop, Codex, or
  Hermes Agent once, then continue starting each client normally.
- **Apply managed policy**: Route supported native Anthropic and OpenAI HTTP,
  SSE, and WebSocket traffic through Relay's guardrails and interceptors.
- **Export local sessions**: Write ATIF trajectory files, ATOF event JSONL
  streams, or OpenInference spans from one system/user configuration model.
- **Diagnose setup readiness**: Check config layers, `plugins.toml` discovery,
  agent binaries, the per-user service, TLS trust, persistent coding-agent
  integrations, hook status, observability outputs, and shell completions with
  `nemo-relay doctor`.

## What You Get

The CLI provides these capabilities:

- **`nemo-relay` binary**: The executable installed by the `nemo-relay-cli`
  Cargo package.
- **Per-user proxy service**: The first enrollment discovers and persists an
  available loopback port. Multiple OS users do not share a static port,
  credentials, service state, or trust material during normal operation. The
  listener authenticates itself with TLS before receiving enrollment or
  provider credentials. A different local account can still occupy a
  candidate port and cause denial of service, so use OS isolation or separate
  machines for hostile multi-tenant workloads.
- **Agent-specific enrollment**: `nemo-relay install` patches only the selected
  agent, assigns it a distinct proxy credential and corporate-proxy route, and
  installs fail-closed lifecycle hooks.
- **Managed provider traffic**: The proxy handles supported Anthropic and
  OpenAI HTTP/SSE calls plus Codex Responses WebSockets.
- **Dynamic TLS**: A constrained current-user CA mints short-lived certificates
  only for the supported native host set.
- **Independent cleanup**: Uninstall restores only the selected agent's owned
  fields. The service, macOS/Windows current-user trust or Linux agent CA
  bundles, keys, and shared state are removed after the last enrollment. Linux
  Codex uninstall prints the launch variable to remove and any recorded prior
  CA selection to restore.

## Installation Options

Cargo:

```bash
cargo install nemo-relay-cli
```

Pinned Unix installer:

```bash
RELAY_VERSION="<release-tag>"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/${RELAY_VERSION}/install.sh" \
  --output nemo-relay-install.sh
less nemo-relay-install.sh
NEMO_RELAY_VERSION="${RELAY_VERSION}" sh nemo-relay-install.sh
```

Pinned Windows PowerShell installer:

```powershell
$RelayVersion = "<release-tag>"
$Installer = "nemo-relay-install.ps1"
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/$RelayVersion/install.ps1" `
  -OutFile $Installer
Get-Content -LiteralPath $Installer
$env:NEMO_RELAY_VERSION = $RelayVersion
& ".\$Installer"
```

Do not execute an installer directly from the moving `main` branch. For custom
installation directories, verification, troubleshooting, and CLI usage, refer
to the
[NeMo Relay installation guide](https://docs.nvidia.com/nemo/relay/getting-started/installation).

After installation, verify the binary with:

```bash
nemo-relay --version
```

## Getting Started

Open the user policy editor, or the equivalent explicit plugin editor:

```bash
nemo-relay config
nemo-relay plugins edit --user
```

Enroll one agent or all supported CLI agents. `all` includes Claude Code,
Codex, and Hermes; Claude Desktop remains an explicit opt-in:

```bash
nemo-relay install codex
nemo-relay install all
nemo-relay install claude-desktop
```

Start the enrolled CLI, GUI, cron job, or other supported local mode normally.
Then inspect installation health:

```bash
nemo-relay doctor codex
```

Remove one enrollment without disturbing the others:

```bash
nemo-relay uninstall codex
```

Claude Desktop retains one explicit protected deep-link launcher:

```bash
nemo-relay claude-desktop --folder ./my-project
```

## Configuration

The persistent coding-agent proxy deliberately loads only Relay system and
user configuration. It does not load project `.nemo-relay` configuration or
inherit provider credentials and provider base URLs from the service process
environment. Unrelated in-process/library configuration behavior is unchanged.

User config lives at `~/.config/nemo-relay/config.toml` or
`$XDG_CONFIG_HOME/nemo-relay/config.toml`.

`nemo-relay config` is the user-policy editor alias. Add `--system` for the
system policy file:

```bash
nemo-relay config
nemo-relay config --system
```

Observability exporters are configured through the plugin config. Edit the user
plugin config with:

```bash
nemo-relay plugins edit
```

The top-level editor menu contains one entry per supported built-in, followed by
the dynamic plugin references in the selected physical `plugins.toml`. Dynamic
plugins with a manifest-declared JSON Schema provide structured field controls.
Other dynamic plugins use a raw JSON object editor.

The canonical plugin file is `plugins.toml`; user config lives at
`~/.config/nemo-relay/plugins.toml` or
`$XDG_CONFIG_HOME/nemo-relay/plugins.toml`. Coding-agent proxy execution does
not load the project plugin layer.

Minimal ATIF example:

```toml
version = 1

[[components]]
kind = "observability"
enabled = true

[components.config.atif]
enabled = true
output_directory = "/absolute/path/to/relay-output/atif"
```

## Documentation

NeMo Relay Documentation: https://docs.nvidia.com/nemo/relay
