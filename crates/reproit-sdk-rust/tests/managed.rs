#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use reproit_cloud_api::{
    CandidateKey, ManagedCandidateCommit, ManagedCandidateEncryptionGrantRequest,
    ManagedCandidateEncryptionResponse, ManagedCandidateLimits, ManagedCandidateStart,
    ManagedCandidateStatus, ManagedCandidateUploadRequest, ManagedCandidateUploadState,
    MissingObject, UploadMissingPage, managed_workload_key_id,
};
use reproit_core::{
    Error, canonical,
    crypto::{encode_base64url, open_managed_candidate, secret_key, sign_bytes, verification_key},
    identity::Digest,
    identity::UploadId,
    model::{
        Candidate, CandidateCipherSuite, CandidateDurability, ManagedCandidateCaptureGrant,
        ManagedCandidateCaptureGrantFormat, ManagedCandidateCaptureOperation, ProcessingMode,
        Subject, SubjectFormat, TriggerCompletion, WorldCheckpoint, WorldCheckpointFormat,
    },
};
use reproit_sdk_rust::{
    CandidateSink, ManagedCandidateGrantDelivery, ManagedCandidateIngressDelivery,
    PreparedManagedRustCandidate, Sdk, SealedManagedRustCandidate, package_running_rust_subject,
};

mod support;

#[derive(Default)]
struct Sink(Mutex<Vec<Candidate>>);

impl CandidateSink for Sink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        self.0.lock().unwrap().push(candidate);
        true
    }
}

struct GrantDelivery {
    calls: Mutex<Vec<ManagedCandidateEncryptionGrantRequest>>,
}

impl ManagedCandidateGrantDelivery for GrantDelivery {
    fn request_encryption_grant(
        &self,
        request: &ManagedCandidateEncryptionGrantRequest,
        _timeout: Duration,
    ) -> Result<ManagedCandidateEncryptionResponse, Error> {
        self.calls.lock().unwrap().push(request.clone());
        let signing_key = secret_key([0x83; 32]);
        let mut grant = ManagedCandidateCaptureGrant {
            candidate_identity_digest: request.candidate_identity_digest,
            candidate_key_reference: encode_base64url(&[0x91; 32]),
            capture_id: request.capture_id,
            cipher_suite: CandidateCipherSuite::Aes256GcmHkdfSha256,
            expires_at: "2026-01-01T00:01:00.000Z".parse().unwrap(),
            format: ManagedCandidateCaptureGrantFormat::V1,
            grant_id: encode_base64url(&[0x92; 32]),
            not_before: "2026-01-01T00:00:00.000Z".parse().unwrap(),
            operation: ManagedCandidateCaptureOperation::EncryptAndUploadCandidate,
            organization_id: request.organization_id,
            processing_mode: ProcessingMode::Managed,
            project_id: request.project_id,
            service_id: request.service_id,
            signature: String::new(),
            signer_key_id: "managed-candidate-capture-test".to_owned(),
        };
        grant.signature = sign_bytes(&canonical::canonical_bytes(&grant)?, &signing_key);
        Ok(ManagedCandidateEncryptionResponse {
            candidate_key: CandidateKey::new([0x42; 32]),
            capture_grant: grant,
        })
    }
}

struct ConflictingRenewal;

impl ManagedCandidateGrantDelivery for ConflictingRenewal {
    fn request_encryption_grant(
        &self,
        request: &ManagedCandidateEncryptionGrantRequest,
        timeout: Duration,
    ) -> Result<ManagedCandidateEncryptionResponse, Error> {
        let delivery = GrantDelivery {
            calls: Mutex::new(Vec::new()),
        };
        let mut response = delivery.request_encryption_grant(request, timeout)?;
        response.candidate_key = CandidateKey::new([0x43; 32]);
        Ok(response)
    }
}

#[derive(Default)]
struct IngressDelivery {
    active_uploads: AtomicUsize,
    expected: Mutex<BTreeSet<Digest>>,
    maximum_active_uploads: AtomicUsize,
    request: Mutex<Option<ManagedCandidateUploadRequest>>,
    uploaded: Mutex<BTreeSet<Digest>>,
}

impl ManagedCandidateIngressDelivery for IngressDelivery {
    fn start(
        &self,
        request: &ManagedCandidateUploadRequest,
        _timeout: Duration,
    ) -> Result<ManagedCandidateStart, Error> {
        let mut expected =
            BTreeSet::from([request.ciphertext_identity.manifest_object.cipher_digest]);
        expected.extend(
            request
                .ciphertext_identity
                .objects
                .iter()
                .flat_map(|object| object.chunks.iter().map(|chunk| chunk.cipher_digest)),
        );
        self.expected.lock().unwrap().clone_from(&expected);
        *self.request.lock().unwrap() = Some(request.clone());
        Ok(ManagedCandidateStart {
            expires_at: "2026-01-01T00:01:00.000Z".parse().unwrap(),
            limits: ManagedCandidateLimits::V1,
            missing_objects: expected
                .into_iter()
                .map(|digest| MissingObject {
                    cipher_digest: digest,
                    expires_at: "2026-01-01T00:01:00.000Z".parse().unwrap(),
                    upload_url: format!("https://upload.reproit.example/{digest}"),
                })
                .collect(),
            next_missing_cursor: None,
            state: ManagedCandidateUploadState::Open,
            upload_id: upload_id(),
            upload_token: encode_base64url(&[0x93; 32]),
        })
    }

    fn missing(
        &self,
        _upload_id: UploadId,
        _upload_token: &str,
        _cursor: Option<&str>,
        _timeout: Duration,
    ) -> Result<UploadMissingPage, Error> {
        panic!("one bounded page contains this fixture")
    }

    fn upload_object(
        &self,
        _upload_url: &str,
        digest: Digest,
        bytes: &[u8],
        _timeout: Duration,
    ) -> Result<(), Error> {
        let active = self.active_uploads.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum_active_uploads
            .fetch_max(active, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(Digest::of(bytes), digest);
        assert!(self.expected.lock().unwrap().contains(&digest));
        self.uploaded.lock().unwrap().insert(digest);
        self.active_uploads.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    fn commit(
        &self,
        upload_id: UploadId,
        _upload_token: &str,
        _timeout: Duration,
    ) -> Result<ManagedCandidateCommit, Error> {
        assert_eq!(
            *self.expected.lock().unwrap(),
            *self.uploaded.lock().unwrap()
        );
        let request = self.request.lock().unwrap().clone().unwrap();
        Ok(ManagedCandidateCommit {
            candidate_identity_digest: request.ciphertext_identity.candidate_identity_digest,
            candidate_key_reference: request.ciphertext_identity.candidate_key_reference,
            capture_id: request.ciphertext_identity.capture_id,
            encrypted_candidate_digest: request.encrypted_candidate_digest,
            state: CandidateDurability::CloudProtected,
            upload_id,
        })
    }

    fn cancel(
        &self,
        _upload_id: UploadId,
        _upload_token: &str,
        _timeout: Duration,
    ) -> Result<ManagedCandidateStatus, Error> {
        panic!("the successful fixture does not cancel")
    }
}

#[test]
fn managed_key_request_occurs_only_after_exact_local_closure() {
    let package = package_running_rust_subject().unwrap();
    let world = WorldCheckpoint {
        created_at: "2026-01-01T00:00:00.000Z".parse().unwrap(),
        format: WorldCheckpointFormat::V1,
        points: Vec::new(),
    };
    let mut fixture = support::fixture();
    fixture.start.world_id = world.world_id().unwrap();
    fixture.start.deployment.processing_mode = ProcessingMode::Managed;
    fixture.start.deployment.runtime_endpoint = "https://managed.reproit.example".to_owned();
    fixture.start.deployment.runtime_capabilities = vec![
        package.manifest.architecture.clone(),
        package.manifest.operating_system.clone(),
        "runtime.rust-native".to_owned(),
    ];
    fixture.start.deployment.subject = Subject {
        architecture: package.manifest.architecture.clone(),
        arguments: package.manifest.launch.arguments.clone(),
        artifact_digest: canonical::digest(&package.manifest).unwrap(),
        artifact_media_type: "application/vnd.reproit.subject-closure.v1+json".to_owned(),
        artifact_uri: "reproit-managed://immutable-subject".to_owned(),
        environment_names: package.manifest.launch.environment_names.clone(),
        executable: package.manifest.launch.executable.clone(),
        format: SubjectFormat::V1,
        operating_system: package.manifest.operating_system.clone(),
        working_directory: package.manifest.launch.working_directory.clone(),
    };
    fixture.start.deployment.signature = encode_base64url(&[0_u8; 64]);

    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .unwrap();
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();
    let candidate = sink.0.lock().unwrap().pop().unwrap();
    let delivery = GrantDelivery {
        calls: Mutex::new(Vec::new()),
    };

    let mut incomplete = candidate.clone();
    incomplete.world_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        .parse()
        .unwrap();
    let incomplete_package = package_running_rust_subject().unwrap();
    assert!(
        PreparedManagedRustCandidate::prepare(
            &incomplete,
            incomplete_package,
            &world,
            TriggerCompletion::Return,
        )
        .is_err()
    );
    assert!(delivery.calls.lock().unwrap().is_empty());

    let prepared = PreparedManagedRustCandidate::prepare(
        &candidate,
        package,
        &world,
        TriggerCompletion::Return,
    )
    .unwrap();
    let workload_signing_key = secret_key([0x84; 32]);
    let workload_public_key = verification_key(&workload_signing_key);
    let workload_key_id = managed_workload_key_id(&encode_base64url(&workload_public_key)).unwrap();
    let response = prepared
        .request_encryption_grant(&delivery, &workload_key_id, &workload_signing_key)
        .unwrap();
    let calls = delivery.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].candidate_identity_digest,
        canonical::digest(prepared.identity()).unwrap()
    );
    calls[0].verify(&workload_public_key).unwrap();
    drop(calls);
    assert_sealed_round_trip(
        prepared,
        response,
        &candidate,
        &workload_key_id,
        &workload_signing_key,
    );
}

fn assert_sealed_round_trip(
    prepared: PreparedManagedRustCandidate,
    response: ManagedCandidateEncryptionResponse,
    candidate: &Candidate,
    workload_key_id: &str,
    workload_signing_key: &reproit_core::crypto::SecretKey,
) {
    let signing_key = secret_key([0x83; 32]);
    let mut sealed = prepared
        .seal(
            response,
            &"2026-01-01T00:00:30.000Z".parse().unwrap(),
            "managed-candidate-capture-test",
            &verification_key(&signing_key),
        )
        .unwrap();
    let renewal = GrantDelivery {
        calls: Mutex::new(Vec::new()),
    };
    let renewed = sealed
        .request_capture_grant_renewal(&renewal, workload_key_id, workload_signing_key)
        .unwrap();
    sealed
        .apply_renewed_capture_grant(
            renewed,
            &"2026-01-01T00:00:30.000Z".parse().unwrap(),
            "managed-candidate-capture-test",
            &verification_key(&signing_key),
        )
        .unwrap();
    assert_eq!(renewal.calls.lock().unwrap().len(), 1);
    let conflicting = sealed
        .request_capture_grant_renewal(&ConflictingRenewal, workload_key_id, workload_signing_key)
        .unwrap();
    assert_eq!(
        sealed
            .apply_renewed_capture_grant(
                conflicting,
                &"2026-01-01T00:00:30.000Z".parse().unwrap(),
                "managed-candidate-capture-test",
                &verification_key(&signing_key),
            )
            .expect_err("a renewal cannot rotate the candidate key")
            .code,
        reproit_core::ErrorCode::CaptureIdConflict
    );
    sealed.request.validate().unwrap();
    let safe_request = serde_json::to_vec(&sealed.request).unwrap();
    assert!(
        !safe_request
            .windows(43)
            .any(|window| window == encode_base64url(&[0x42; 32]).as_bytes())
    );
    assert_sealed_ciphertext_opens(&sealed, candidate);
    let ingress = IngressDelivery::default();
    let committed = sealed.upload(&ingress).unwrap();
    assert_eq!(committed.state, CandidateDurability::CloudProtected);
    assert!(ingress.maximum_active_uploads.load(Ordering::SeqCst) > 1);
    assert!(ingress.maximum_active_uploads.load(Ordering::SeqCst) <= 8);
}

/// The sealed ciphertext must open only with the candidate key, reject a
/// missing shard, and reproduce the exact candidate bytes.
fn assert_sealed_ciphertext_opens(sealed: &SealedManagedRustCandidate, candidate: &Candidate) {
    for digest in sealed.ciphertext_digests() {
        let bytes = std::fs::read(sealed.ciphertext_path(digest).unwrap()).unwrap();
        assert_eq!(Digest::of(&bytes), digest);
    }
    let ciphertext = sealed
        .ciphertext_digests()
        .map(|digest| {
            (
                digest,
                std::fs::read(sealed.ciphertext_path(digest).unwrap()).unwrap(),
            )
        })
        .collect();
    let mut opened_objects = std::collections::BTreeMap::new();
    let opened_manifest = open_managed_candidate(
        &secret_key([0x42; 32]),
        &sealed.request.ciphertext_identity,
        &ciphertext,
        |descriptor, index, bytes| {
            let object = opened_objects
                .entry(descriptor.object_id)
                .or_insert_with(Vec::new);
            assert_eq!(object.len() / (8 * 1024 * 1024), index as usize);
            object.extend_from_slice(bytes);
            Ok(())
        },
    )
    .unwrap();
    assert!(
        open_managed_candidate(
            &secret_key([0x43; 32]),
            &sealed.request.ciphertext_identity,
            &ciphertext,
            |_descriptor, _index, _bytes| Ok(()),
        )
        .is_err()
    );
    let mut incomplete_ciphertext = ciphertext.clone();
    incomplete_ciphertext.pop_first();
    assert!(
        open_managed_candidate(
            &secret_key([0x42; 32]),
            &sealed.request.ciphertext_identity,
            &incomplete_ciphertext,
            |_descriptor, _index, _bytes| Ok(()),
        )
        .is_err()
    );
    let candidate_object = opened_manifest
        .candidate_identity
        .objects
        .iter()
        .find(|object| object.media_type == "application/vnd.reproit.candidate.v1+json")
        .unwrap();
    let opened_candidate: Candidate =
        canonical::parse_strict(&opened_objects[&candidate_object.object_id]).unwrap();
    assert_eq!(&opened_candidate, candidate);
}

fn upload_id() -> UploadId {
    "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac0".parse().unwrap()
}
