// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use rcgen::SanType;

#[test]
fn generated_identity_has_no_persisted_ca_key_and_builds_tls_config() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate(temp.path(), "test-generation").unwrap();
    assert_eq!(certificate.root_sha1.len(), 40);
    assert!(certificate_files_exist(&certificate));
    assert!(
        !certificate
            .root_der
            .with_file_name("root-ca-key.der")
            .exists()
    );
    validate_installed_identity(temp.path(), &certificate).unwrap();
    assert!(server_config(temp.path(), &certificate).is_ok());
    assert_eq!(certificate.root_sha256.len(), 64);
}

#[test]
fn certificate_parameters_are_constrained_to_the_exact_anthropic_leaf() {
    let start = time::OffsetDateTime::UNIX_EPOCH;
    let end = start + time::Duration::days(LEAF_VALIDITY_DAYS);
    let root = ca_parameters("test root", start, end + time::Duration::days(1)).unwrap();
    assert_eq!(root.is_ca, IsCa::Ca(BasicConstraints::Constrained(0)));
    assert_eq!(
        root.name_constraints.unwrap().permitted_subtrees,
        vec![GeneralSubtree::DnsName(INTERCEPTED_HOST.into())]
    );

    let leaf = leaf_parameters(start, end).unwrap();
    assert_eq!(leaf.is_ca, IsCa::ExplicitNoCa);
    assert_eq!(leaf.not_after - leaf.not_before, time::Duration::days(730));
    assert_eq!(
        leaf.extended_key_usages,
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    );
    assert!(matches!(
        leaf.subject_alt_names.as_slice(),
        [SanType::DnsName(name)] if name.as_str() == INTERCEPTED_HOST
    ));
}
