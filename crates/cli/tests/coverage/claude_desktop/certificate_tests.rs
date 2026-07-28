// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use rcgen::SanType;

#[test]
fn generated_identity_retains_private_ca_key_and_builds_tls_config() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate(temp.path(), "test-generation").unwrap();
    assert_eq!(certificate.root_sha1.len(), 40);
    assert!(certificate_files_exist(&certificate));
    assert!(certificate.ca_key_der.is_file());
    leaf_key_is_private(&certificate.ca_key_der).unwrap();
    validate_installed_identity(temp.path(), &certificate).unwrap();
    assert!(server_config(temp.path(), &certificate).is_ok());
    assert_eq!(certificate.root_sha256.len(), 64);
    assert_eq!(certificate.host_set_sha256, intercepted_host_set_sha256());
    assert!(!requires_rotation(temp.path(), &certificate));
    assert!(
        !certificate
            .root_der
            .parent()
            .unwrap()
            .join("leaf-cache")
            .exists(),
        "leaf certificates must be minted on first use"
    );
}

#[test]
fn dynamic_leaf_cache_records_expiry_and_refuses_stale_entries() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate(temp.path(), "dynamic-leaf").unwrap();
    let root = read(&certificate.root_der, "test root").unwrap();
    let cache_dir = certificate.root_der.parent().unwrap().join("leaf-cache");
    let resolver = ExactHostResolver {
        cache_dir: cache_dir.clone(),
        root: root.clone(),
        signer_kind: certificate.ca_signer_kind.clone(),
        signer_handle: certificate.ca_key_handle.clone(),
        ca_key_path: certificate.ca_key_der.clone(),
        root_common_name: certificate.root_common_name.clone(),
        root_not_before: certificate.not_before.clone(),
        root_not_after: certificate.not_after.clone(),
        permitted_hosts: INTERCEPTED_HOSTS
            .iter()
            .map(|host| (*host).to_string())
            .collect(),
        cached: Mutex::new(BTreeMap::new()),
    };

    resolver.generate_leaf("api.openai.com").unwrap();
    assert!(
        load_cached_leaf(&cache_dir, "api.openai.com", &root)
            .unwrap()
            .is_some()
    );
    leaf_key_is_private(&cache_dir.join("api.openai.com-key.der")).unwrap();
    let metadata_path = cache_dir.join("api.openai.com.json");
    crate::filesystem::atomic_write_private(
        &metadata_path,
        br#"{"host":"api.openai.com","not_after":"2020-01-01"}"#,
    )
    .unwrap();
    assert!(
        load_cached_leaf(&cache_dir, "api.openai.com", &root)
            .unwrap()
            .is_none()
    );
    assert!(
        leaf_cache_summary(&certificate)
            .unwrap()
            .contains("api.openai.com=refresh-needed")
    );
}

#[test]
fn certificate_rotation_detects_host_expansion_and_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate(temp.path(), "test-generation").unwrap();

    let mut stale_host_set = certificate.clone();
    stale_host_set.host_set_sha256 = "legacy-host-set".into();
    assert!(requires_rotation(temp.path(), &stale_host_set));

    std::fs::remove_file(&certificate.root_der).unwrap();
    assert!(requires_rotation(temp.path(), &certificate));
}

#[test]
fn first_enrollment_ca_covers_only_required_hosts_and_rotates_on_expansion() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate_for_hosts(temp.path(), "claude-only", &[INTERCEPTED_HOST]).unwrap();

    permitted_dns_hosts(&certificate).unwrap();
    validate_installed_identity(temp.path(), &certificate).unwrap();
    assert_ne!(certificate.host_set_sha256, intercepted_host_set_sha256());
    assert!(!requires_rotation_for_hosts(
        temp.path(),
        &certificate,
        &[INTERCEPTED_HOST]
    ));
    assert!(requires_rotation_for_hosts(
        temp.path(),
        &certificate,
        &["api.anthropic.com", "api.openai.com"]
    ));
    assert_eq!(
        permitted_dns_hosts(&certificate).unwrap(),
        vec!["api.anthropic.com"]
    );
}

#[test]
fn prior_constrained_host_subset_remains_removable_after_host_expansion() {
    let temp = tempfile::tempdir().unwrap();
    let mut certificate = generate(temp.path(), "prior-host-set").unwrap();
    rewrite_host_constraints_for_test(&mut certificate, &[INTERCEPTED_HOST]).unwrap();

    validate_for_removal(&certificate).unwrap();
    assert!(requires_rotation(temp.path(), &certificate));
}

#[test]
fn destructive_identity_validation_rejects_a_mismatched_signer() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let first = generate(first_root.path(), "first-generation").unwrap();
    let second = generate(second_root.path(), "second-generation").unwrap();
    std::fs::copy(&second.ca_key_der, &first.ca_key_der).unwrap();

    let error = validate_for_removal(&first).unwrap_err();
    assert!(
        error.contains("certificate and signer do not match"),
        "{error}"
    );
    assert!(remove_signer(&first).is_err());
}

#[test]
fn certificate_parameters_are_constrained_to_the_native_provider_hosts() {
    let start = time::OffsetDateTime::UNIX_EPOCH;
    let end = start + time::Duration::days(LEAF_VALIDITY_DAYS);
    let root = ca_parameters(
        "test root",
        start,
        end + time::Duration::days(1),
        INTERCEPTED_HOSTS,
    )
    .unwrap();
    assert_eq!(root.is_ca, IsCa::Ca(BasicConstraints::Constrained(0)));
    let constraints = root.name_constraints.unwrap();
    assert_eq!(
        constraints.permitted_subtrees,
        INTERCEPTED_HOSTS
            .iter()
            .map(|host| GeneralSubtree::DnsName((*host).into()))
            .chain(std::iter::once(GeneralSubtree::IpAddress(
                loopback_constraint(),
            )))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        constraints.excluded_subtrees,
        INTERCEPTED_HOSTS
            .iter()
            .map(|host| GeneralSubtree::DnsName(format!(".{host}")))
            .collect::<Vec<_>>()
    );

    let leaf = leaf_parameters(start, end).unwrap();
    assert_eq!(leaf.is_ca, IsCa::ExplicitNoCa);
    assert_eq!(
        leaf.not_after - leaf.not_before,
        time::Duration::days(LEAF_VALIDITY_DAYS)
    );
    assert_eq!(
        leaf.extended_key_usages,
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    );
    assert!(matches!(
        leaf.subject_alt_names.as_slice(),
        [SanType::DnsName(name)] if name.as_str() == INTERCEPTED_HOST
    ));
}

#[test]
fn generation_failure_rolls_back_the_directory_and_platform_signer() {
    let temp = tempfile::tempdir().unwrap();
    let generation = "incomplete-generation";
    let directory = temp.path().join("generations").join(generation);
    let root_der = directory.join("root-ca.der");
    TEST_SIGNER_ROLLBACKS.store(0, Ordering::Relaxed);
    crate::filesystem::fail_next_atomic_write(&root_der);

    let error = generate(temp.path(), generation).unwrap_err();

    assert!(error.contains("injected test failure"), "{error}");
    assert!(
        !directory.exists(),
        "a failed generation must not leave private material behind"
    );
    assert!(
        TEST_SIGNER_ROLLBACKS.load(Ordering::Relaxed) >= 1,
        "a failed generation must remove its platform signer handle"
    );
}
