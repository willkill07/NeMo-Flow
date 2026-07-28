// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Constrained, installer-owned TLS material for native coding-agent provider interception.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Datelike, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, digest};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};

use super::state::CertificateState;

pub(super) const INTERCEPTED_HOST: &str = "api.anthropic.com";
pub(super) const INTERCEPTED_HOSTS: &[&str] =
    &["api.anthropic.com", "api.openai.com", "chatgpt.com"];
pub(super) const LISTENER_HOST: &str = "127.0.0.1";
pub(super) const EXPIRY_WARNING_DAYS: i64 = 30;
const CA_VALIDITY_DAYS: i64 = 365;
const LEAF_VALIDITY_DAYS: i64 = 7;
#[cfg(test)]
static TEST_SIGNER_ROLLBACKS: AtomicUsize = AtomicUsize::new(0);

struct CertificateSigner {
    key_pair: KeyPair,
    kind: String,
    handle: Option<String>,
    serialized: Option<Vec<u8>>,
}

struct PendingGeneration {
    directory: PathBuf,
    generation: String,
    signer_created: bool,
    armed: bool,
}

impl PendingGeneration {
    fn new(directory: PathBuf, generation: &str) -> Self {
        Self {
            directory,
            generation: generation.into(),
            signer_created: false,
            armed: true,
        }
    }

    fn signer_created(&mut self) {
        self.signer_created = true;
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGeneration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.signer_created
            && let Err(error) = remove_signer_for_generation(&self.generation)
        {
            log::error!(
                target: "nemo_relay.gateway",
                event = "certificate_generation_rollback_failed",
                component = "signer";
                "Failed to remove an incomplete coding-agent proxy signer: {error}"
            );
        }
        if self
            .directory
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("generations")
        {
            match std::fs::remove_dir_all(&self.directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => log::error!(
                    target: "nemo_relay.gateway",
                    event = "certificate_generation_rollback_failed",
                    component = "generation_directory";
                    "Failed to remove incomplete certificate generation {}: {error}",
                    self.directory.display()
                ),
            }
        }
    }
}

#[cfg(test)]
pub(super) fn generate(root: &Path, generation: &str) -> Result<CertificateState, String> {
    generate_for_hosts(root, generation, INTERCEPTED_HOSTS)
}

pub(super) fn generate_for_hosts(
    root: &Path,
    generation: &str,
    hosts: &[&str],
) -> Result<CertificateState, String> {
    let hosts = validated_host_set(hosts)?;
    let generations = root.join("generations");
    super::state::ensure_private_directory(&generations)?;
    let directory = generations.join(generation);
    super::state::ensure_private_directory(&directory)?;
    let mut pending = PendingGeneration::new(directory.clone(), generation);

    let today = Utc::now().date_naive();
    let not_before = today - Duration::days(1);
    let root_not_after = today + Duration::days(CA_VALIDITY_DAYS);
    let root_common_name = format!("NeMo Relay Agent Proxy {generation}");

    let ca_signer = create_certificate_signer(generation)?;
    pending.signer_created();
    let ca_key = &ca_signer.key_pair;
    let ca_params = ca_parameters(
        &root_common_name,
        rcgen_date(not_before),
        rcgen_date(root_not_after),
        &hosts,
    )?;
    let ca = ca_params
        .self_signed(ca_key)
        .map_err(|error| format!("failed to issue coding-agent proxy root certificate: {error}"))?;

    let root_der = directory.join("root-ca.der");
    let root_pem = directory.join("root-ca.pem");
    let ca_key_der = directory.join("root-ca-key.der");
    crate::filesystem::atomic_write_private(&root_der, ca.der())?;
    crate::filesystem::atomic_write_private(&root_pem, ca.pem().as_bytes())?;
    if let Some(serialized) = ca_signer.serialized.as_deref() {
        crate::filesystem::atomic_write_private(&ca_key_der, serialized)?;
    }

    let state = CertificateState {
        root_sha1: hex_digest(&SHA1_FOR_LEGACY_USE_ONLY, ca.der()),
        root_sha256: hex_sha256(ca.der()),
        host_set_sha256: constrained_host_set_sha256(&hosts),
        root_der,
        root_pem,
        ca_key_der: if ca_signer.serialized.is_some() {
            ca_key_der
        } else {
            Default::default()
        },
        ca_key_handle: ca_signer.handle,
        ca_signer_kind: ca_signer.kind,
        root_common_name,
        not_before: not_before.to_string(),
        not_after: root_not_after.to_string(),
    };
    pending.commit();
    Ok(state)
}

#[cfg(test)]
pub(super) fn intercepted_host_set_sha256() -> String {
    constrained_host_set_sha256(INTERCEPTED_HOSTS)
}

fn constrained_host_set_sha256(hosts: &[&str]) -> String {
    let mut constrained_names = hosts.to_vec();
    constrained_names.push(LISTENER_HOST);
    host_set_sha256(&constrained_names)
}

fn validated_host_set<'a>(hosts: &'a [&'a str]) -> Result<Vec<&'a str>, String> {
    let mut hosts = hosts.to_vec();
    hosts.sort_unstable();
    hosts.dedup();
    if hosts.is_empty() || hosts.iter().any(|host| !INTERCEPTED_HOSTS.contains(host)) {
        return Err("coding-agent proxy CA host set contains an unsupported native host".into());
    }
    Ok(hosts)
}

pub(super) fn permitted_dns_hosts(certificate: &CertificateState) -> Result<Vec<String>, String> {
    let root = read(&certificate.root_der, "coding-agent proxy root certificate")?;
    let params = CertificateParams::from_ca_cert_der(&CertificateDer::from(root))
        .map_err(|error| format!("invalid coding-agent proxy root certificate: {error}"))?;
    let constraints = params.name_constraints.ok_or_else(|| {
        "coding-agent proxy root certificate has invalid name constraints".to_string()
    })?;
    let mut hosts = constraints
        .permitted_subtrees
        .iter()
        .filter_map(|subtree| match subtree {
            GeneralSubtree::DnsName(host) => Some(host.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    let host_refs = hosts.iter().map(String::as_str).collect::<Vec<_>>();
    let valid_hosts =
        validated_host_set(&host_refs).is_ok_and(|validated| validated.len() == hosts.len());
    let exact_subdomain_exclusions = constraints.excluded_subtrees
        == hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName(format!(".{host}")))
            .collect::<Vec<_>>();
    let exact_loopback_constraint = constraints
        .permitted_subtrees
        .iter()
        .filter(|subtree| matches!(subtree, GeneralSubtree::IpAddress(_)))
        .eq(std::iter::once(&GeneralSubtree::IpAddress(
            loopback_constraint(),
        )));
    if !valid_hosts
        || !exact_subdomain_exclusions
        || !exact_loopback_constraint
        || constrained_host_set_sha256(&host_refs) != certificate.host_set_sha256
    {
        return Err(
            "coding-agent proxy root certificate constraints differ from installed state".into(),
        );
    }
    Ok(hosts)
}

fn host_set_sha256(hosts: &[&str]) -> String {
    let mut hosts = hosts.to_vec();
    hosts.sort_unstable();
    hex_sha256(hosts.join("\n").as_bytes())
}

#[cfg(test)]
pub(super) fn rewrite_host_constraints_for_test(
    certificate: &mut CertificateState,
    hosts: &[&str],
) -> Result<(), String> {
    let original_der = read(&certificate.root_der, "test root certificate")?;
    let mut params = CertificateParams::from_ca_cert_der(&CertificateDer::from(original_der))
        .map_err(|error| format!("failed to parse test root certificate: {error}"))?;
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName((*host).into()))
            .chain(std::iter::once(GeneralSubtree::IpAddress(
                loopback_constraint(),
            )))
            .collect(),
        excluded_subtrees: hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName(format!(".{host}")))
            .collect(),
    });
    let signer = load_certificate_signer(
        &certificate.ca_signer_kind,
        certificate.ca_key_handle.as_deref(),
        &certificate.ca_key_der,
    )?;
    let replacement = params
        .self_signed(&signer)
        .map_err(|error| format!("failed to issue test root certificate: {error}"))?;
    crate::filesystem::atomic_write_private(&certificate.root_der, replacement.der())?;
    crate::filesystem::atomic_write_private(&certificate.root_pem, replacement.pem().as_bytes())?;
    certificate.root_sha1 = hex_digest(&SHA1_FOR_LEGACY_USE_ONLY, replacement.der());
    certificate.root_sha256 = hex_sha256(replacement.der());
    let mut constrained_names = hosts.to_vec();
    constrained_names.push(LISTENER_HOST);
    certificate.host_set_sha256 = host_set_sha256(&constrained_names);
    Ok(())
}

#[cfg(test)]
pub(super) fn requires_rotation(install_root: &Path, certificate: &CertificateState) -> bool {
    requires_rotation_for_hosts(install_root, certificate, INTERCEPTED_HOSTS)
}

pub(super) fn requires_rotation_for_hosts(
    install_root: &Path,
    certificate: &CertificateState,
    required_hosts: &[&str],
) -> bool {
    if !matches!(expiry_days(certificate), Ok(days) if days > 0)
        || validate_installed_identity(install_root, certificate).is_err()
    {
        return true;
    }
    let Ok(required_hosts) = validated_host_set(required_hosts) else {
        return true;
    };
    permitted_dns_hosts(certificate)
        .map(|permitted| {
            !required_hosts
                .iter()
                .all(|required| permitted.iter().any(|host| host == required))
        })
        .unwrap_or(true)
}

fn create_certificate_signer(generation: &str) -> Result<CertificateSigner, String> {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        macos_signer::create(generation)
    }
    #[cfg(all(windows, not(test)))]
    {
        windows_signer::create(generation)
    }
    #[cfg(any(all(not(target_os = "macos"), not(windows)), test))]
    {
        let _ = generation;
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|error| format!("failed to generate coding-agent proxy CA key: {error}"))?;
        let serialized = key_pair.serialize_der();
        Ok(CertificateSigner {
            key_pair,
            kind: "file-pkcs8".into(),
            handle: None,
            serialized: Some(serialized),
        })
    }
}

fn load_certificate_signer(
    kind: &str,
    _handle: Option<&str>,
    key_path: &Path,
) -> Result<KeyPair, String> {
    match kind {
        "file-pkcs8" => {
            let bytes = read(key_path, "coding-agent proxy CA private key")?;
            KeyPair::try_from(bytes.as_slice())
                .map_err(|error| format!("failed to load coding-agent proxy CA key: {error}"))
        }
        #[cfg(all(target_os = "macos", not(test)))]
        "macos-keychain" => macos_signer::load(
            _handle.ok_or_else(|| "coding-agent proxy Keychain handle is missing".to_string())?,
        ),
        #[cfg(all(windows, not(test)))]
        "windows-cng" => windows_signer::load(
            _handle.ok_or_else(|| "coding-agent proxy CNG handle is missing".to_string())?,
        ),
        other => Err(format!(
            "unsupported coding-agent proxy certificate signer {other:?}"
        )),
    }
}

fn ca_parameters(
    common_name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    hosts: &[&str],
) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| format!("failed to create coding-agent proxy CA parameters: {error}"))?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName((*host).into()))
            .chain(std::iter::once(GeneralSubtree::IpAddress(
                loopback_constraint(),
            )))
            .collect(),
        excluded_subtrees: hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName(format!(".{host}")))
            .collect(),
    });
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name = distinguished_name(common_name);
    Ok(params)
}

fn loopback_constraint() -> CidrSubnet {
    CidrSubnet::from_addr_prefix(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
}

#[cfg(test)]
fn leaf_parameters(
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(vec![INTERCEPTED_HOST.into()])
        .map_err(|error| format!("failed to create coding-agent proxy leaf parameters: {error}"))?;
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
    for path in [&certificate.root_der, &certificate.root_pem] {
        if !path.starts_with(install_root) {
            return Err(format!(
                "refusing coding-agent proxy TLS material outside install root: {}",
                path.display()
            ));
        }
    }
    if !certificate.ca_key_der.as_os_str().is_empty()
        && !certificate.ca_key_der.starts_with(install_root)
    {
        return Err(format!(
            "refusing coding-agent proxy CA key outside install root: {}",
            certificate.ca_key_der.display()
        ));
    }
    let root = read(&certificate.root_der, "coding-agent proxy root certificate")?;
    let permitted_hosts = permitted_dns_hosts(certificate)?;
    let cache_dir = certificate
        .root_der
        .parent()
        .expect("certificate path has a generation directory")
        .join("leaf-cache");
    let mut cached = BTreeMap::new();
    for host in permitted_hosts
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(LISTENER_HOST))
    {
        if let Ok(Some(identity)) = load_cached_leaf(&cache_dir, host, &root) {
            cached.insert(host.to_string(), identity);
        }
    }
    let resolver = ExactHostResolver {
        cache_dir,
        root,
        signer_kind: certificate.ca_signer_kind.clone(),
        signer_handle: certificate.ca_key_handle.clone(),
        ca_key_path: certificate.ca_key_der.clone(),
        root_common_name: certificate.root_common_name.clone(),
        root_not_before: certificate.not_before.clone(),
        root_not_after: certificate.not_after.clone(),
        permitted_hosts,
        cached: Mutex::new(cached),
    };
    Ok(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver)),
    ))
}

#[derive(Debug)]
struct ExactHostResolver {
    cache_dir: std::path::PathBuf,
    root: Vec<u8>,
    signer_kind: String,
    signer_handle: Option<String>,
    ca_key_path: std::path::PathBuf,
    root_common_name: String,
    root_not_before: String,
    root_not_after: String,
    permitted_hosts: Vec<String>,
    cached: Mutex<BTreeMap<String, CachedLeafIdentity>>,
}

#[derive(Debug)]
struct CachedLeafIdentity {
    key: Arc<CertifiedKey>,
    not_after: chrono::NaiveDate,
}

impl ResolvesServerCert for ExactHostResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello
            .server_name()
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| LISTENER_HOST.into());
        if host != LISTENER_HOST && !self.permitted_hosts.contains(&host) {
            return None;
        }
        let mut cached = self.cached.lock().ok()?;
        let today = Utc::now().date_naive();
        if let Some(identity) = cached.get(&host)
            && identity.not_after > today
        {
            return Some(identity.key.clone());
        }
        cached.remove(&host);
        match self.generate_leaf(&host) {
            Ok(identity) => {
                let key = identity.key.clone();
                cached.insert(host, identity);
                Some(key)
            }
            Err(error) => {
                log::error!(
                    target: "nemo_relay.gateway",
                    event = "leaf_certificate_generation_failed",
                    error_kind = "tls";
                    "Coding-agent proxy could not generate a leaf certificate: {error}"
                );
                None
            }
        }
    }
}

pub(super) fn client_config(
    certificate: &CertificateState,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(read(
            &certificate.root_der,
            "coding-agent proxy root certificate",
        )?))
        .map_err(|error| format!("invalid coding-agent proxy listener trust anchor: {error}"))?;
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

impl ExactHostResolver {
    fn generate_leaf(&self, host: &str) -> Result<CachedLeafIdentity, String> {
        super::state::ensure_private_directory(&self.cache_dir)?;
        let today = Utc::now().date_naive();
        let ca_key = load_certificate_signer(
            &self.signer_kind,
            self.signer_handle.as_deref(),
            &self.ca_key_path,
        )?;
        let root_not_before = chrono::NaiveDate::parse_from_str(&self.root_not_before, "%Y-%m-%d")
            .map_err(|error| format!("invalid proxy CA not-before date: {error}"))?;
        let root_not_after = chrono::NaiveDate::parse_from_str(&self.root_not_after, "%Y-%m-%d")
            .map_err(|error| format!("invalid proxy CA not-after date: {error}"))?
            + Duration::days(1);
        let ca_params = ca_parameters(
            &self.root_common_name,
            rcgen_date(root_not_before),
            rcgen_date(root_not_after),
            &self
                .permitted_hosts
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        let ca = ca_params
            .self_signed(&ca_key)
            .map_err(|error| format!("failed to load coding-agent proxy CA identity: {error}"))?;
        let leaf_key = KeyPair::generate()
            .map_err(|error| format!("failed to generate {host} leaf key: {error}"))?;
        let mut params = leaf_parameters_for_host(
            host,
            rcgen_date(today - Duration::days(1)),
            rcgen_date(today + Duration::days(7)),
        )?;
        params.serial_number = Some(rand_serial());
        let leaf = params
            .signed_by(&leaf_key, &ca, &ca_key)
            .map_err(|error| format!("failed to issue {host} leaf certificate: {error}"))?;
        let leaf_path = self.cache_dir.join(format!("{host}.der"));
        let key_path = self.cache_dir.join(format!("{host}-key.der"));
        let metadata_path = self.cache_dir.join(format!("{host}.json"));
        crate::filesystem::atomic_write_private(&leaf_path, leaf.der())?;
        crate::filesystem::atomic_write_private(&key_path, &leaf_key.serialize_der())?;
        let not_after = today + Duration::days(LEAF_VALIDITY_DAYS);
        let metadata = serde_json::to_vec(&CachedLeafMetadata {
            host: host.to_string(),
            not_after: not_after.to_string(),
        })
        .map_err(|error| format!("failed to encode {host} leaf metadata: {error}"))?;
        crate::filesystem::atomic_write_private(&metadata_path, &metadata)?;
        certified_key(&self.root, leaf.der(), &leaf_key.serialize_der()).map(|key| {
            CachedLeafIdentity {
                key: Arc::new(key),
                not_after,
            }
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CachedLeafMetadata {
    host: String,
    not_after: String,
}

fn load_cached_leaf(
    cache_dir: &Path,
    host: &str,
    root: &[u8],
) -> Result<Option<CachedLeafIdentity>, String> {
    let metadata_path = cache_dir.join(format!("{host}.json"));
    if !metadata_path.is_file() {
        return Ok(None);
    }
    let metadata = read(&metadata_path, "coding-agent proxy leaf-cache metadata")?;
    let metadata = serde_json::from_slice::<CachedLeafMetadata>(&metadata).map_err(|error| {
        format!(
            "invalid leaf-cache metadata {}: {error}",
            metadata_path.display()
        )
    })?;
    let not_after = chrono::NaiveDate::parse_from_str(&metadata.not_after, "%Y-%m-%d")
        .map_err(|error| format!("invalid cached leaf expiry for {host}: {error}"))?;
    if metadata.host != host || not_after <= Utc::now().date_naive() {
        return Ok(None);
    }
    let leaf = read(
        &cache_dir.join(format!("{host}.der")),
        "coding-agent proxy cached leaf certificate",
    )?;
    let key = read(
        &cache_dir.join(format!("{host}-key.der")),
        "coding-agent proxy cached leaf private key",
    )?;
    certified_key(root, &leaf, &key).map(|key| {
        Some(CachedLeafIdentity {
            key: Arc::new(key),
            not_after,
        })
    })
}

fn rand_serial() -> rcgen::SerialNumber {
    let uuid = uuid::Uuid::now_v7();
    rcgen::SerialNumber::from_slice(uuid.as_bytes())
}

fn certified_key(root: &[u8], leaf: &[u8], key: &[u8]) -> Result<CertifiedKey, String> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|error| format!("unsupported coding-agent proxy leaf key: {error}"))?;
    let certified = CertifiedKey::new(
        vec![
            CertificateDer::from(leaf.to_vec()),
            CertificateDer::from(root.to_vec()),
        ],
        signing_key,
    );
    certified
        .keys_match()
        .map_err(|error| format!("coding-agent proxy leaf certificate/key mismatch: {error}"))?;
    Ok(certified)
}

fn leaf_parameters_for_host(
    host: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(vec![host.into()])
        .map_err(|error| format!("failed to create {host} leaf parameters: {error}"))?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = distinguished_name(host);
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

pub(super) fn validate_installed_identity(
    install_root: &Path,
    certificate: &CertificateState,
) -> Result<(), String> {
    if !certificate_files_exist(certificate) {
        return Err("installed coding-agent proxy certificate material is incomplete".into());
    }
    let root_der = read(&certificate.root_der, "coding-agent proxy root certificate")?;
    let root_pem = read(
        &certificate.root_pem,
        "coding-agent proxy root certificate PEM",
    )?;
    let pem_certificate = CertificateDer::from_pem_slice(&root_pem)
        .map_err(|error| format!("invalid coding-agent proxy root certificate PEM: {error}"))?;
    if pem_certificate.as_ref() != root_der {
        return Err("coding-agent proxy root DER and PEM certificates differ".into());
    }
    if hex_digest(&SHA1_FOR_LEGACY_USE_ONLY, &root_der) != certificate.root_sha1
        || hex_sha256(&root_der) != certificate.root_sha256
    {
        return Err(
            "coding-agent proxy root certificate fingerprint differs from installed state".into(),
        );
    }
    validate_root_certificate_semantics(&root_der, certificate)?;
    server_config(install_root, certificate).map(|_| ())
}

fn validate_root_certificate_semantics(
    root_der: &[u8],
    certificate: &CertificateState,
) -> Result<(), String> {
    let der = CertificateDer::from(root_der.to_vec());
    let params = CertificateParams::from_ca_cert_der(&der)
        .map_err(|error| format!("invalid coding-agent proxy root certificate: {error}"))?;
    let common_name = match params.distinguished_name.get(&DnType::CommonName) {
        Some(DnValue::Utf8String(common_name)) => common_name.as_str(),
        _ => {
            return Err("coding-agent proxy root certificate has an invalid common name".into());
        }
    };
    let constraints = params.name_constraints.as_ref().ok_or_else(|| {
        "coding-agent proxy root certificate has invalid name constraints".to_string()
    })?;
    let mut actual_hosts = constraints
        .permitted_subtrees
        .iter()
        .filter_map(|subtree| match subtree {
            GeneralSubtree::DnsName(host) => Some(host.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    actual_hosts.sort_unstable();
    let mut constrained_names = actual_hosts.clone();
    constrained_names.push(LISTENER_HOST);
    let exact_subdomain_exclusions = constraints.excluded_subtrees
        == actual_hosts
            .iter()
            .map(|host| GeneralSubtree::DnsName(format!(".{host}")))
            .collect::<Vec<_>>();
    let exact_loopback_constraint = constraints
        .permitted_subtrees
        .iter()
        .filter(|subtree| matches!(subtree, GeneralSubtree::IpAddress(_)))
        .eq(std::iter::once(&GeneralSubtree::IpAddress(
            loopback_constraint(),
        )));
    let host_set_is_valid = !actual_hosts.is_empty()
        && actual_hosts.windows(2).all(|pair| pair[0] != pair[1])
        && actual_hosts
            .iter()
            .all(|host| INTERCEPTED_HOSTS.contains(host))
        && host_set_sha256(&constrained_names) == certificate.host_set_sha256
        && exact_subdomain_exclusions
        && exact_loopback_constraint;
    if common_name != certificate.root_common_name
        || params.is_ca != IsCa::Ca(BasicConstraints::Constrained(0))
        || params.key_usages != vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        || !params.extended_key_usages.is_empty()
        || !params.subject_alt_names.is_empty()
        || !host_set_is_valid
        || certificate.not_before
            != format!(
                "{:04}-{:02}-{:02}",
                params.not_before.year(),
                params.not_before.month() as u8,
                params.not_before.day()
            )
        || certificate.not_after
            != format!(
                "{:04}-{:02}-{:02}",
                params.not_after.year(),
                params.not_after.month() as u8,
                params.not_after.day()
            )
    {
        return Err(
            "coding-agent proxy root certificate constraints differ from installed state".into(),
        );
    }
    let (remaining, parsed) = x509_parser::parse_x509_certificate(root_der)
        .map_err(|error| format!("failed to parse coding-agent proxy root: {error}"))?;
    if !remaining.is_empty() {
        return Err("coding-agent proxy root certificate contains trailing data".into());
    }
    parsed
        .verify_signature(None)
        .map_err(|error| format!("coding-agent proxy root is not self-signed: {error}"))?;
    let signer = load_certificate_signer(
        &certificate.ca_signer_kind,
        certificate.ca_key_handle.as_deref(),
        &certificate.ca_key_der,
    )?;
    if parsed.public_key().raw != signer.public_key_der() {
        return Err("coding-agent proxy root certificate and signer do not match".into());
    }
    Ok(())
}

pub(super) fn validate_for_removal(certificate: &CertificateState) -> Result<(), String> {
    let generation_directory = certificate
        .root_der
        .parent()
        .ok_or_else(|| "coding-agent proxy root certificate has no generation path".to_string())?;
    let generations = generation_directory
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("generations"))
        .ok_or_else(|| "coding-agent proxy root certificate has an unsafe path".to_string())?;
    let install_root = generations
        .parent()
        .ok_or_else(|| "coding-agent proxy root certificate has no install root".to_string())?;
    validate_installed_identity(install_root, certificate)
}

pub(super) fn expiry_days(certificate: &CertificateState) -> Result<i64, String> {
    let not_after = chrono::NaiveDate::parse_from_str(&certificate.not_after, "%Y-%m-%d")
        .map_err(|error| format!("invalid certificate expiry in state: {error}"))?;
    let days = (not_after - Utc::now().date_naive()).num_days();
    Ok(days)
}

pub(super) fn certificate_files_exist(certificate: &CertificateState) -> bool {
    let public_material = [&certificate.root_der, &certificate.root_pem]
        .into_iter()
        .all(|path| path.is_file());
    public_material
        && load_certificate_signer(
            &certificate.ca_signer_kind,
            certificate.ca_key_handle.as_deref(),
            &certificate.ca_key_der,
        )
        .is_ok()
}

pub(super) fn leaf_cache_summary(certificate: &CertificateState) -> Result<String, String> {
    let cache_dir = certificate
        .root_der
        .parent()
        .ok_or_else(|| "coding-agent proxy CA path has no generation directory".to_string())?
        .join("leaf-cache");
    let today = Utc::now().date_naive();
    let mut status = Vec::with_capacity(INTERCEPTED_HOSTS.len());
    for host in INTERCEPTED_HOSTS {
        let metadata_path = cache_dir.join(format!("{host}.json"));
        if !metadata_path.exists() {
            status.push(format!("{host}=on-first-use"));
            continue;
        }
        let metadata = read(&metadata_path, "coding-agent proxy leaf-cache metadata")?;
        let metadata = serde_json::from_slice::<CachedLeafMetadata>(&metadata)
            .map_err(|error| format!("invalid {}: {error}", metadata_path.display()))?;
        let expiry = chrono::NaiveDate::parse_from_str(&metadata.not_after, "%Y-%m-%d")
            .map_err(|error| format!("invalid cached leaf expiry for {host}: {error}"))?;
        if metadata.host != *host {
            return Err(format!(
                "cached leaf metadata {} names the wrong host",
                metadata_path.display()
            ));
        }
        let state = if expiry > today {
            "valid"
        } else {
            "refresh-needed"
        };
        status.push(format!("{host}={state}-until-{expiry}"));
    }
    Ok(status.join(", "))
}

pub(super) fn cached_leaf_keys_are_private(certificate: &CertificateState) -> Result<(), String> {
    let cache_dir = certificate
        .root_der
        .parent()
        .ok_or_else(|| "coding-agent proxy CA path has no generation directory".to_string())?
        .join("leaf-cache");
    if !cache_dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&cache_dir)
        .map_err(|error| format!("failed to inspect {}: {error}", cache_dir.display()))?
    {
        let path = entry
            .map_err(|error| format!("failed to inspect {}: {error}", cache_dir.display()))?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("-key.der"))
        {
            leaf_key_is_private(&path)?;
        }
    }
    Ok(())
}

pub(super) fn remove_signer(certificate: &CertificateState) -> Result<(), String> {
    validate_for_removal(certificate)?;
    match certificate.ca_signer_kind.as_str() {
        "file-pkcs8" => Ok(()),
        #[cfg(all(target_os = "macos", not(test)))]
        "macos-keychain" => macos_signer::remove(
            certificate
                .ca_key_handle
                .as_deref()
                .ok_or_else(|| "coding-agent proxy Keychain handle is missing".to_string())?,
        ),
        #[cfg(all(windows, not(test)))]
        "windows-cng" => windows_signer::remove(
            certificate
                .ca_key_handle
                .as_deref()
                .ok_or_else(|| "coding-agent proxy CNG handle is missing".to_string())?,
        ),
        other => Err(format!(
            "unsupported coding-agent proxy certificate signer {other:?}"
        )),
    }
}

pub(super) fn remove_signer_for_generation(generation: &str) -> Result<(), String> {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        macos_signer::remove(&macos_signer::handle(generation))
    }
    #[cfg(all(windows, not(test)))]
    {
        windows_signer::remove(&windows_signer::handle(generation))
    }
    #[cfg(any(test, all(not(target_os = "macos"), not(windows))))]
    {
        let _ = generation;
        #[cfg(test)]
        TEST_SIGNER_ROLLBACKS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
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

#[cfg(all(target_os = "macos", not(test)))]
mod macos_signer {
    use core_foundation::base::{TCFType, ToVoid};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use rcgen::{Error, KeyPair, RemoteKeyPair};
    use security_framework::item::{ItemSearchOptions, KeyClass, Reference, SearchResult};
    use security_framework::key::{Algorithm, SecKey};
    use security_framework_sys::item::{
        kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecPrivateKeyAttrs, kSecPublicKeyAttrs,
    };

    use super::CertificateSigner;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrIsExtractable: CFStringRef;
    }

    struct KeychainRemote {
        key: SecKey,
        public_key: Vec<u8>,
    }

    impl RemoteKeyPair for KeychainRemote {
        fn public_key(&self) -> &[u8] {
            &self.public_key
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            self.key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
                .map_err(|_| Error::RemoteKeyError)
        }

        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    pub(super) fn create(generation: &str) -> Result<CertificateSigner, String> {
        let handle = handle(generation);
        let key = create_non_exportable_login_key(&handle).map_err(|error| {
            format!("failed to create non-exportable login Keychain CA key: {error}")
        })?;
        if key.external_representation().is_some() {
            let _ = key.delete();
            return Err(
                "login Keychain returned an exportable coding-agent proxy CA key; refusing installation"
                    .into(),
            );
        }
        match signer(handle.clone(), key) {
            Ok(key_pair) => Ok(CertificateSigner {
                key_pair,
                kind: "macos-keychain".into(),
                handle: Some(handle),
                serialized: None,
            }),
            Err(error) => {
                let cleanup = remove(&handle);
                Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => format!("{error}; cleanup also failed: {cleanup}"),
                })
            }
        }
    }

    #[allow(
        deprecated,
        reason = "the safe builder cannot set kSecAttrIsExtractable"
    )]
    fn create_non_exportable_login_key(
        handle: &str,
    ) -> Result<SecKey, core_foundation::error::CFError> {
        let permanent = CFBoolean::true_value();
        let not_extractable = CFBoolean::false_value();
        let private_attributes = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrIsPermanent }.to_void(),
                permanent.to_void(),
            ),
            (
                unsafe { kSecAttrIsExtractable }.to_void(),
                not_extractable.to_void(),
            ),
        ]);
        let public_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            permanent.to_void(),
        )]);
        let key_type = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
        let key_size = CFNumber::from(256_i32);
        let label = CFString::new(handle);
        let attributes = CFMutableDictionary::from_CFType_pairs(&[
            (unsafe { kSecAttrKeyType }.to_void(), key_type.to_void()),
            (
                unsafe { kSecAttrKeySizeInBits }.to_void(),
                key_size.to_void(),
            ),
            (unsafe { kSecAttrLabel }.to_void(), label.to_void()),
            (
                unsafe { kSecPrivateKeyAttrs }.to_void(),
                private_attributes.to_void(),
            ),
            (
                unsafe { kSecPublicKeyAttrs }.to_void(),
                public_attributes.to_void(),
            ),
        ]);
        SecKey::generate(attributes.to_immutable())
    }

    pub(super) fn handle(generation: &str) -> String {
        format!("com.nvidia.nemo-relay.agent-proxy.ca.{generation}")
    }

    pub(super) fn load(handle: &str) -> Result<KeyPair, String> {
        let key = find(handle)?
            .ok_or_else(|| format!("coding-agent proxy Keychain key {handle:?} was not found"))?;
        signer(handle.to_string(), key)
    }

    fn find(handle: &str) -> Result<Option<SecKey>, String> {
        let mut results = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .label(handle)
            .load_refs(true)
            .search()
            .map_err(|error| {
                format!("failed to open coding-agent proxy Keychain key {handle:?}: {error}")
            })?;
        if results.is_empty() {
            return Ok(None);
        }
        if results.len() != 1 {
            return Err(format!(
                "coding-agent proxy Keychain key {handle:?} resolved to {} entries",
                results.len()
            ));
        }
        match results.pop() {
            Some(SearchResult::Ref(Reference::Key(key))) => Ok(Some(key)),
            _ => Err(format!(
                "coding-agent proxy Keychain handle {handle:?} is not a private key"
            )),
        }
    }

    pub(super) fn remove(handle: &str) -> Result<(), String> {
        if find(handle)?.is_none() {
            return Ok(());
        }
        let mut search = ItemSearchOptions::new();
        search.key_class(KeyClass::private()).label(handle);
        search.delete().map_err(|error| {
            format!("failed to remove coding-agent proxy Keychain key {handle:?}: {error}")
        })?;
        if find(handle)?.is_some() {
            Err(format!(
                "coding-agent proxy Keychain key {handle:?} still exists after deletion"
            ))
        } else {
            Ok(())
        }
    }

    fn signer(handle: String, key: SecKey) -> Result<KeyPair, String> {
        let public_key = key
            .public_key()
            .and_then(|public| public.external_representation())
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                format!("failed to read public key for coding-agent proxy Keychain key {handle:?}")
            })?;
        if public_key.len() != 65 || public_key.first() != Some(&4) {
            return Err(format!(
                "coding-agent proxy Keychain key {handle:?} is not an ECDSA P-256 key"
            ));
        }
        KeyPair::from_remote(Box::new(KeychainRemote { key, public_key }))
            .map_err(|error| format!("failed to use coding-agent proxy Keychain key: {error}"))
    }
}

#[cfg(all(windows, not(test)))]
mod windows_signer {
    use std::ptr;

    use rcgen::{Error, KeyPair, RemoteKeyPair};
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_ECCPUBLIC_BLOB, MS_KEY_STORAGE_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM,
        NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
        NCRYPT_SECURITY_DESCR_PROPERTY, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
        NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR,
    };

    use super::CertificateSigner;

    const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;

    struct CngRemote {
        provider: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE,
        public_key: Vec<u8>,
    }

    unsafe impl Send for CngRemote {}
    unsafe impl Sync for CngRemote {}

    impl Drop for CngRemote {
        fn drop(&mut self) {
            // SAFETY: Both handles were returned by NCrypt and remain owned by this value.
            unsafe {
                if self.key != 0 {
                    let _ = NCryptFreeObject(self.key);
                }
                if self.provider != 0 {
                    let _ = NCryptFreeObject(self.provider);
                }
            }
        }
    }

    impl RemoteKeyPair for CngRemote {
        fn public_key(&self) -> &[u8] {
            &self.public_key
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            let digest = Sha256::digest(message);
            let mut required = 0_u32;
            // SAFETY: The CNG key handle is valid, and the digest pointers remain live for the call.
            let status = unsafe {
                NCryptSignHash(
                    self.key,
                    ptr::null(),
                    digest.as_ptr(),
                    digest.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut required,
                    0,
                )
            };
            if status != 0 || required == 0 {
                return Err(Error::RemoteKeyError);
            }
            let mut raw = vec![0_u8; required as usize];
            // SAFETY: `raw` has the size requested by CNG and all handles/pointers are valid.
            let status = unsafe {
                NCryptSignHash(
                    self.key,
                    ptr::null(),
                    digest.as_ptr(),
                    digest.len() as u32,
                    raw.as_mut_ptr(),
                    raw.len() as u32,
                    &mut required,
                    0,
                )
            };
            if status != 0 || required as usize != raw.len() || raw.len() % 2 != 0 {
                return Err(Error::RemoteKeyError);
            }
            Ok(ecdsa_raw_to_der(&raw))
        }

        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    pub(super) fn create(generation: &str) -> Result<CertificateSigner, String> {
        let handle = handle(generation);
        let (provider, key) = open_provider_and_create(&handle)?;
        let key_pair = remote(provider, key)?;
        Ok(CertificateSigner {
            key_pair,
            kind: "windows-cng".into(),
            handle: Some(handle),
            serialized: None,
        })
    }

    pub(super) fn load(handle: &str) -> Result<KeyPair, String> {
        let (provider, key) = open_provider_and_key(handle)?
            .ok_or_else(|| format!("coding-agent proxy CNG key {handle:?} was not found"))?;
        remote(provider, key)
    }

    pub(super) fn remove(handle: &str) -> Result<(), String> {
        let Some((provider, key)) = open_provider_and_key(handle)? else {
            return Ok(());
        };
        // SAFETY: `key` is a current-user CNG key opened by this process.
        let status = unsafe { NCryptDeleteKey(key, 0) };
        // NCryptDeleteKey releases the key handle regardless of result ownership semantics.
        // SAFETY: `provider` remains separately owned and must be released.
        unsafe {
            let _ = NCryptFreeObject(provider);
        }
        status_result(status, "remove coding-agent proxy CNG key")?;
        if let Some((provider, key)) = open_provider_and_key(handle)? {
            // SAFETY: The verification handles are independently owned by this branch.
            unsafe {
                let _ = NCryptFreeObject(key);
                let _ = NCryptFreeObject(provider);
            }
            Err(format!(
                "coding-agent proxy CNG key {handle:?} still exists after deletion"
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn handle(generation: &str) -> String {
        format!("NVIDIA NeMo Relay Agent Proxy CA {generation}")
    }

    fn open_provider_and_create(
        handle: &str,
    ) -> Result<(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE), String> {
        let mut provider = 0;
        // SAFETY: Output points to initialized storage and the provider name is a static wide string.
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) };
        status_result(status, "open the current-user CNG provider")?;
        let name = wide(handle);
        let mut key = 0;
        // SAFETY: Provider and output handles are valid and `name` is NUL-terminated.
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                NCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        };
        if let Err(error) = status_result(status, "create non-exportable current-user CNG CA key") {
            // SAFETY: Provider was opened above and remains owned here.
            unsafe {
                let _ = NCryptFreeObject(provider);
            }
            return Err(error);
        }
        // SAFETY: Key is a newly created CNG key ready for finalization.
        let status = unsafe { NCryptFinalizeKey(key, 0) };
        if let Err(error) = status_result(status, "finalize current-user CNG CA key") {
            // SAFETY: Handles were created above and are still owned here.
            unsafe {
                let _ = NCryptDeleteKey(key, 0);
                let _ = NCryptFreeObject(provider);
            }
            return Err(error);
        }
        if let Err(error) = restrict_key_access(key) {
            // SAFETY: Handles were created above and are still owned here.
            unsafe {
                let _ = NCryptDeleteKey(key, 0);
                let _ = NCryptFreeObject(provider);
            }
            return Err(error);
        }
        if let Err(error) = validate_non_exportable(key) {
            // SAFETY: Handles were created above and are still owned here.
            unsafe {
                let _ = NCryptDeleteKey(key, 0);
                let _ = NCryptFreeObject(provider);
            }
            return Err(error);
        }
        Ok((provider, key))
    }

    fn restrict_key_access(key: NCRYPT_KEY_HANDLE) -> Result<(), String> {
        // `OW` is the key object's owner (the creating user); `SY` is LocalSystem.
        let descriptor_source = wide("D:P(A;;GA;;;SY)(A;;GA;;;OW)");
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: The SDDL string is NUL-terminated and the output points to initialized storage.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_source.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(format!(
                "failed to create the coding-agent proxy CNG owner/System ACL: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: `descriptor` was allocated by the conversion API and remains valid here.
        let descriptor_len = unsafe { GetSecurityDescriptorLength(descriptor) };
        // SAFETY: The CNG key and self-relative security descriptor are valid for this call.
        let status = unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                descriptor.cast(),
                descriptor_len,
                DACL_SECURITY_INFORMATION,
            )
        };
        // SAFETY: The conversion API allocated `descriptor` with LocalAlloc.
        unsafe {
            let _ = LocalFree(descriptor);
        }
        status_result(
            status,
            "restrict coding-agent proxy CNG key to its owner and System",
        )
    }

    fn open_provider_and_key(
        handle: &str,
    ) -> Result<Option<(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE)>, String> {
        let mut provider = 0;
        // SAFETY: Output points to initialized storage and the provider name is static.
        let status =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) };
        status_result(status, "open the current-user CNG provider")?;
        let name = wide(handle);
        let mut key = 0;
        // SAFETY: Provider is valid, name is NUL-terminated, and output storage is valid.
        let status = unsafe { NCryptOpenKey(provider, &mut key, name.as_ptr(), 0, 0) };
        if status == NTE_BAD_KEYSET {
            // SAFETY: Provider was opened above and remains owned here.
            unsafe {
                let _ = NCryptFreeObject(provider);
            }
            return Ok(None);
        }
        if let Err(error) = status_result(status, "open coding-agent proxy CNG key") {
            // SAFETY: Provider was opened above and remains owned here.
            unsafe {
                let _ = NCryptFreeObject(provider);
            }
            return Err(error);
        }
        Ok(Some((provider, key)))
    }

    fn validate_non_exportable(key: NCRYPT_KEY_HANDLE) -> Result<(), String> {
        let mut policy = 0_u32;
        let mut written = 0_u32;
        // SAFETY: `policy` is writable storage for the documented 32-bit export-policy property.
        let status = unsafe {
            NCryptGetProperty(
                key,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                (&mut policy as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut written,
                0,
            )
        };
        status_result(status, "read coding-agent proxy CNG export policy")?;
        if written != std::mem::size_of::<u32>() as u32 || policy != 0 {
            return Err(
                "current-user CNG returned an exportable coding-agent proxy CA key; refusing installation"
                    .into(),
            );
        }
        Ok(())
    }

    fn remote(provider: NCRYPT_PROV_HANDLE, key: NCRYPT_KEY_HANDLE) -> Result<KeyPair, String> {
        match export_public_key(key) {
            Ok(public_key) => KeyPair::from_remote(Box::new(CngRemote {
                provider,
                key,
                public_key,
            }))
            .map_err(|error| format!("failed to use coding-agent proxy CNG key: {error}")),
            Err(error) => {
                // SAFETY: Both handles are owned by this function on the error path.
                unsafe {
                    let _ = NCryptFreeObject(key);
                    let _ = NCryptFreeObject(provider);
                }
                Err(error)
            }
        }
    }

    fn export_public_key(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>, String> {
        let mut required = 0_u32;
        // SAFETY: The key handle is valid and the size output pointer is initialized.
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut required,
                0,
            )
        };
        status_result(status, "size coding-agent proxy CNG public key")?;
        let mut blob = vec![0_u8; required as usize];
        // SAFETY: `blob` has the exact size requested by CNG.
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut required,
                0,
            )
        };
        status_result(status, "export coding-agent proxy CNG public key")?;
        if blob.len() < 8 {
            return Err("coding-agent proxy CNG public key blob is truncated".into());
        }
        let coordinate_size =
            u32::from_le_bytes(blob[4..8].try_into().expect("four-byte CNG key size")) as usize;
        if coordinate_size != 32 || blob.len() != 8 + coordinate_size * 2 {
            return Err("coding-agent proxy CNG key is not ECDSA P-256".into());
        }
        let mut public_key = Vec::with_capacity(65);
        public_key.push(4);
        public_key.extend_from_slice(&blob[8..]);
        Ok(public_key)
    }

    fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
        fn integer(value: &[u8]) -> Vec<u8> {
            let first_nonzero = value
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(value.len() - 1);
            let value = &value[first_nonzero..];
            let needs_zero = value[0] & 0x80 != 0;
            let mut encoded = Vec::with_capacity(value.len() + 3);
            encoded.push(0x02);
            encoded.push((value.len() + usize::from(needs_zero)) as u8);
            if needs_zero {
                encoded.push(0);
            }
            encoded.extend_from_slice(value);
            encoded
        }
        let (r, s) = raw.split_at(raw.len() / 2);
        let r = integer(r);
        let s = integer(s);
        let mut sequence = Vec::with_capacity(r.len() + s.len() + 2);
        sequence.push(0x30);
        sequence.push((r.len() + s.len()) as u8);
        sequence.extend_from_slice(&r);
        sequence.extend_from_slice(&s);
        sequence
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn status_result(status: i32, operation: &str) -> Result<(), String> {
        if status == 0 {
            Ok(())
        } else {
            Err(format!("{operation} failed with CNG status 0x{status:08X}"))
        }
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/claude_desktop/certificate_tests.rs"]
mod tests;
