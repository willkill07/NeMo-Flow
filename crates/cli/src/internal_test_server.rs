// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Feature-gated repository integration-test server.

fn main() -> std::process::ExitCode {
    nemo_relay_cli::run_internal_test_server_cli()
}
