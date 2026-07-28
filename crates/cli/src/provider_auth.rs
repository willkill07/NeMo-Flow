// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider-credential provenance and proxy credential generation.

use std::sync::Arc;

use axum::http::HeaderMap;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::CliError;

const TOKEN_BYTES: usize = 32;
#[derive(Clone)]
pub(crate) struct ProxyCredential(Arc<str>);

impl ProxyCredential {
    pub(crate) fn generate() -> Result<Self, CliError> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| CliError::Launch("failed to generate proxy credential".into()))?;
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(Self(format!("nrp_{encoded}").into()))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceCredentialDisposition {
    ProviderCredential,
    Absent,
}

impl SourceCredentialDisposition {
    pub(crate) fn from_provider_headers(headers: &HeaderMap) -> Self {
        if has_provider_credential(headers) {
            Self::ProviderCredential
        } else {
            Self::Absent
        }
    }

    pub(crate) const fn provider_credential_present(self) -> bool {
        match self {
            Self::ProviderCredential => true,
            Self::Absent => false,
        }
    }

    pub(crate) fn after_source_normalization(self, headers: &HeaderMap) -> Self {
        Self::from_provider_headers(headers)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderRequestAuthorization {
    pub(crate) source_credential: SourceCredentialDisposition,
    pub(crate) allow_configured_provider_auth: bool,
    pub(crate) allow_environment_provider_auth: bool,
}

pub(crate) fn has_provider_credential(headers: &HeaderMap) -> bool {
    headers
        .keys()
        .any(|name| nemo_relay::api::llm::is_provider_credential_header_name(name.as_str()))
}

pub(crate) fn remove_provider_credentials(headers: &mut HeaderMap) {
    let names = headers
        .keys()
        .filter(|name| nemo_relay::api::llm::is_provider_credential_header_name(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        headers.remove(name);
    }
}

pub(crate) fn remove_named_provider_credentials<'a>(
    headers: &mut HeaderMap,
    names: impl IntoIterator<Item = &'a str>,
) {
    remove_provider_credentials(headers);
    for name in names {
        headers.remove(name);
    }
}
