use std::fs;

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

use reproit_core::{
    crypto::verification_key,
    identity::{Digest, ServiceId},
};
use reproit_sdk_rust::{
    MAX_MANAGED_DEPLOYMENT_METADATA_BYTES, MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
    ManagedWorkloadIdentityState, ManagedWorkloadRegistrationReceipt,
    load_or_create_managed_workload_key,
};

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn identity_state(root: &tempfile::TempDir) -> ManagedWorkloadIdentityState {
    ManagedWorkloadIdentityState::from_state_root(
        &root.path().canonicalize().unwrap(),
        Digest::of(b"project-binding"),
    )
    .unwrap()
}

fn receipt() -> ManagedWorkloadRegistrationReceipt {
    ManagedWorkloadRegistrationReceipt {
        deployment_digest: Digest::of(b"signed-deployment"),
        service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
            .parse::<ServiceId>()
            .unwrap(),
        workload_key_id: format!("managed-workload-{}", Digest::of(b"workload-public-key")),
    }
}

#[test]
fn managed_workload_state_is_private_stable_and_scoped() {
    let root = private_root();
    let state = identity_state(&root);
    assert_eq!(
        state.directory(),
        root.path()
            .canonicalize()
            .unwrap()
            .join("reproit/workloads")
            .join(Digest::of(b"project-binding").to_string())
    );
    let first = state.load_or_create_key().unwrap();
    let public_key = verification_key(&first);
    drop(first);
    let restarted = identity_state(&root);
    let second = restarted.load_or_create_key().unwrap();
    assert_eq!(verification_key(&second), public_key);
    let first_signed_at = "2026-01-01T00:00:00.000Z".parse().unwrap();
    let later_signed_at = "2026-01-02T00:00:00.000Z".parse().unwrap();
    assert_eq!(
        restarted
            .load_or_create_deployment_signed_at(Digest::of(b"project-binding"), &first_signed_at,)
            .unwrap(),
        first_signed_at
    );
    assert_eq!(
        identity_state(&root)
            .load_or_create_deployment_signed_at(Digest::of(b"project-binding"), &later_signed_at,)
            .unwrap(),
        first_signed_at
    );

    let receipt = receipt();
    assert_eq!(restarted.load_registration_receipt(&receipt).unwrap(), None);
    restarted.persist_registration_receipt(&receipt).unwrap();
    restarted.persist_registration_receipt(&receipt).unwrap();
    assert_eq!(
        identity_state(&root)
            .load_registration_receipt(&receipt)
            .unwrap(),
        Some(receipt)
    );

    #[cfg(unix)]
    {
        for directory in [
            root.path().join("reproit"),
            root.path().join("reproit/workloads"),
            state.directory().to_owned(),
        ] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(state.directory().join("workload.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(state.directory().join("deployment.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(state.directory().join("registration.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn managed_deployment_metadata_rejects_corruption_scope_drift_and_one_beyond_bound() {
    let root = private_root();
    let state = identity_state(&root);
    let signed_at = "2026-01-01T00:00:00.000Z".parse().unwrap();
    state
        .load_or_create_deployment_signed_at(Digest::of(b"project-binding"), &signed_at)
        .unwrap();
    assert!(
        state
            .load_or_create_deployment_signed_at(Digest::of(b"other-binding"), &signed_at)
            .is_err()
    );

    let path = state.directory().join("deployment.json");
    fs::write(&path, vec![b'a'; MAX_MANAGED_DEPLOYMENT_METADATA_BYTES + 1]).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        state
            .load_or_create_deployment_signed_at(Digest::of(b"project-binding"), &signed_at)
            .is_err()
    );
}

#[test]
fn managed_workload_receipt_fails_closed_for_corruption_and_scope_mismatch() {
    let root = private_root();
    let state = identity_state(&root);
    let expected = receipt();
    state.persist_registration_receipt(&expected).unwrap();

    for mismatch in [
        ManagedWorkloadRegistrationReceipt {
            deployment_digest: Digest::of(b"another-deployment"),
            ..expected.clone()
        },
        ManagedWorkloadRegistrationReceipt {
            service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789ac0".parse().unwrap(),
            ..expected.clone()
        },
        ManagedWorkloadRegistrationReceipt {
            workload_key_id: format!("managed-workload-{}", Digest::of(b"another-workload-key")),
            ..expected.clone()
        },
    ] {
        assert!(state.load_registration_receipt(&mismatch).is_err());
        assert!(state.persist_registration_receipt(&mismatch).is_err());
    }

    let path = state.directory().join("registration.json");
    fs::write(&path, b"not canonical JSON").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(state.load_registration_receipt(&expected).is_err());
}

#[test]
fn managed_workload_state_rejects_links_and_open_permissions() {
    #[cfg(unix)]
    {
        let root = private_root();
        let linked_root = private_root();
        let link = root.path().join("reproit");
        symlink(linked_root.path(), &link).unwrap();
        assert!(
            ManagedWorkloadIdentityState::from_state_root(
                &root.path().canonicalize().unwrap(),
                Digest::of(b"linked-binding")
            )
            .is_err()
        );
    }

    let root = private_root();
    let state = identity_state(&root);
    state.load_or_create_key().unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(state.directory(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(state.load_or_create_key().is_err());
        fs::set_permissions(state.directory(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            state.directory().join("workload.key"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(state.load_or_create_key().is_err());
    }
}

#[test]
fn managed_workload_receipt_rejects_one_byte_over_the_bound_and_links() {
    let root = private_root();
    let state = identity_state(&root);
    let path = state.directory().join("registration.json");
    fs::write(&path, vec![b'a'; MAX_MANAGED_WORKLOAD_RECEIPT_BYTES + 1]).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(state.load_registration_receipt(&receipt()).is_err());

    #[cfg(unix)]
    {
        fs::remove_file(&path).unwrap();
        let target = state.directory().join("receipt-target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(state.load_registration_receipt(&receipt()).is_err());
    }
}

#[test]
fn managed_workload_key_path_helper_rejects_corruption_and_links() {
    let root = private_root();
    let path = root.path().join("workload.key");
    let first = load_or_create_managed_workload_key(&path).unwrap();
    let first_public = verification_key(&first);
    drop(first);
    let second = load_or_create_managed_workload_key(&path).unwrap();
    assert_eq!(verification_key(&second), first_public);

    let corrupt = root.path().join("corrupt.key");
    fs::write(&corrupt, [0x41_u8; 31]).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_or_create_managed_workload_key(&corrupt).is_err());

    #[cfg(unix)]
    {
        let target = root.path().join("target.key");
        fs::write(&target, [0x42_u8; 32]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link.key");
        symlink(&target, &link).unwrap();
        assert!(load_or_create_managed_workload_key(&link).is_err());
    }
}
