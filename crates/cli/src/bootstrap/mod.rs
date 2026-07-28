// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy fixed-endpoint identity retained only for exact uninstall and cleanup.

pub(crate) mod state;

use std::path::PathBuf;
use std::time::Duration;

/// Wrapper/MCP-gateway-era endpoint used only to identify and remove owned legacy state.
pub(crate) const LEGACY_FIXED_BIND: &str = "127.0.0.1:47632";
/// Wrapper/MCP-gateway-era URL used only to identify and remove owned legacy state.
pub(crate) const LEGACY_FIXED_URL: &str = "http://127.0.0.1:47632";
pub(crate) const HEALTHZ_TIMEOUT: Duration = Duration::from_millis(500);
pub(crate) const BOOTSTRAP_PROTOCOL_VERSION: u64 = 2;

#[cfg(test)]
pub(super) const BOOTSTRAP_LOCK_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))
}
