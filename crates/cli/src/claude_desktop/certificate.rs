// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Constrained, installer-owned TLS material for `api.anthropic.com` interception.

use std::path::Path;
use std::sync::Arc;

use chrono::{Datelike, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, digest};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::state::CertificateState;

pub(super) const INTERCEPTED_HOST: &str = "api.anthropic.com";
pub(super) const EXPIRY_WARNING_DAYS: i64 = 30;
const LEAF_VALIDITY_DAYS: i64 = 730;

pub(super) fn generate(root: &Path, generation: &str) -> Result<CertificateState, String> {
    let generations = root.join("generations");
    super::state::ensure_private_directory(&generations)?;
    let directory = generations.join(generation);
    super::state::ensure_private_directory(&directory)?;

    let today = Utc::now().date_naive();
    let not_before = today - Duration::days(1);
    let not_after = today + Duration::days(LEAF_VALIDITY_DAYS);
    let root_not_after = not_after + Duration::days(1);
    let root_common_name = format!("NeMo Relay Claude Desktop {generation}");

    let ca_key = KeyPair::generate()
        .map_err(|error| format!("failed to generate Claude Desktop CA key: {error}"))?;
    let ca_params = ca_parameters(
        &root_common_name,
        rcgen_date(not_before),
        rcgen_date(root_not_after),
    )?;
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|error| format!("failed to issue Claude Desktop root certificate: {error}"))?;

    let leaf_key = KeyPair::generate()
        .map_err(|error| format!("failed to generate Claude Desktop leaf key: {error}"))?;
    let leaf_params = leaf_parameters(rcgen_date(not_before), rcgen_date(not_after))?;
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .map_err(|error| format!("failed to issue Claude Desktop leaf certificate: {error}"))?;

    let root_der = directory.join("root-ca.der");
    let root_pem = directory.join("root-ca.pem");
    let leaf_der = directory.join("api.anthropic.com.der");
    let leaf_key_der = directory.join("api.anthropic.com-key.der");
    crate::filesystem::atomic_write_private(&root_der, ca.der())?;
    crate::filesystem::atomic_write_private(&root_pem, ca.pem().as_bytes())?;
    crate::filesystem::atomic_write_private(&leaf_der, leaf.der())?;
    crate::filesystem::atomic_write_private(&leaf_key_der, &leaf_key.serialize_der())?;

    // `ca_key` is intentionally never serialized. It is dropped here after issuing the one exact
    // leaf, so a compromised sidecar cannot mint certificates for any other host.
    drop(ca_key);

    Ok(CertificateState {
        root_sha1: hex_digest(&SHA1_FOR_LEGACY_USE_ONLY, ca.der()),
        root_sha256: hex_sha256(ca.der()),
        root_der,
        root_pem,
        leaf_der,
        leaf_key_der,
        root_common_name,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
    })
}

fn ca_parameters(
    common_name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| format!("failed to create Claude Desktop CA parameters: {error}"))?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(INTERCEPTED_HOST.into())],
        excluded_subtrees: Vec::new(),
    });
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name = distinguished_name(common_name);
    Ok(params)
}

fn leaf_parameters(
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(vec![INTERCEPTED_HOST.into()])
        .map_err(|error| format!("failed to create Claude Desktop leaf parameters: {error}"))?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = distinguished_name(INTERCEPTED_HOST);
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

pub(super) fn server_config(
    install_root: &Path,
    certificate: &CertificateState,
) -> Result<Arc<rustls::ServerConfig>, String> {
    for path in [
        &certificate.root_der,
        &certificate.root_pem,
        &certificate.leaf_der,
        &certificate.leaf_key_der,
    ] {
        if !path.starts_with(install_root) {
            return Err(format!(
                "refusing Claude Desktop TLS material outside install root: {}",
                path.display()
            ));
        }
    }
    let root = read(&certificate.root_der, "Claude Desktop root certificate")?;
    let leaf = read(&certificate.leaf_der, "Claude Desktop leaf certificate")?;
    let key = read(&certificate.leaf_key_der, "Claude Desktop leaf private key")?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf), CertificateDer::from(root)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .map(Arc::new)
        .map_err(|error| format!("invalid Claude Desktop TLS identity: {error}"))
}

pub(super) fn validate_installed_identity(
    install_root: &Path,
    certificate: &CertificateState,
) -> Result<(), String> {
    if !certificate_files_exist(certificate) {
        return Err("installed Claude Desktop certificate material is incomplete".into());
    }
    let root_der = read(&certificate.root_der, "Claude Desktop root certificate")?;
    let root_pem = read(&certificate.root_pem, "Claude Desktop root certificate PEM")?;
    let pem_certificate = CertificateDer::from_pem_slice(&root_pem)
        .map_err(|error| format!("invalid Claude Desktop root certificate PEM: {error}"))?;
    if pem_certificate.as_ref() != root_der {
        return Err("Claude Desktop root DER and PEM certificates differ".into());
    }
    if hex_digest(&SHA1_FOR_LEGACY_USE_ONLY, &root_der) != certificate.root_sha1
        || hex_sha256(&root_der) != certificate.root_sha256
    {
        return Err(
            "Claude Desktop root certificate fingerprint differs from installed state".into(),
        );
    }
    server_config(install_root, certificate).map(|_| ())
}

pub(super) fn expiry_days(certificate: &CertificateState) -> Result<i64, String> {
    let not_after = chrono::NaiveDate::parse_from_str(&certificate.not_after, "%Y-%m-%d")
        .map_err(|error| format!("invalid certificate expiry in state: {error}"))?;
    let days = (not_after - Utc::now().date_naive()).num_days();
    Ok(days)
}

pub(super) fn certificate_files_exist(certificate: &CertificateState) -> bool {
    [
        &certificate.root_der,
        &certificate.root_pem,
        &certificate.leaf_der,
        &certificate.leaf_key_der,
    ]
    .into_iter()
    .all(|path| path.is_file())
}

pub(super) fn leaf_key_is_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is accessible outside its owner (mode {:o})",
                path.display(),
                mode & 0o777
            ));
        }
    }
    #[cfg(windows)]
    if !crate::filesystem::windows_path_is_private(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
    {
        return Err(format!("{} is not owner-only", path.display()));
    }
    Ok(())
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "NVIDIA Corporation");
    name.push(DnType::OrganizationalUnitName, "NeMo Relay");
    name.push(DnType::CommonName, common_name);
    name
}

fn rcgen_date(date: chrono::NaiveDate) -> time::OffsetDateTime {
    rcgen::date_time_ymd(date.year(), date.month() as u8, date.day() as u8)
}

fn read(path: &Path, description: &str) -> Result<Vec<u8>, String> {
    crate::filesystem::bounded::read_bounded_regular_file(path, description)
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_digest(&SHA256, bytes)
}

fn hex_digest(algorithm: &'static ring::digest::Algorithm, bytes: &[u8]) -> String {
    digest(algorithm, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/certificate_tests.rs"]
mod tests;
