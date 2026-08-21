use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Read, Write as _},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use reproit_cloud_api::{
    ManagedCandidateCommit, ManagedCandidateEncryptionGrantRequest,
    ManagedCandidateEncryptionResponse, ManagedCandidateStart, ManagedCandidateStatus,
    ManagedCandidateUploadRequest, ManagedCandidateUploadState, UploadMissingPage,
};
use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::{
        NonceRegistry, SecretKey, decode_base64url_bytes, derive_chunk_key, derive_object_key,
        encode_base64url, encrypt_chunk, secret_key, sign_bytes,
    },
    identity::{Digest, ObjectId, OperationId, Timestamp, UploadId},
    model::{
        Candidate, CandidateCipherSuite, CandidateDurability, ChunkKeyContext,
        ChunkKeyContextFormat, DependencyCursorPayload, DependencyTranscript, EncryptedChunk,
        EncryptedObject, EventKind, FailurePayload, LogicalObject, LogicalObjectRole,
        ManagedCandidateCaptureGrantExpectation, ManagedCandidateCiphertextIdentity,
        ManagedCandidateCiphertextIdentityFormat, ManagedCandidateIdentity,
        ManagedCandidateIdentityFormat, ManagedCandidateManifest, ManagedCandidateManifestFormat,
        ManifestUploadObject, ObjectKeyContext, ObjectKeyContextFormat, OperationBeginPayload,
        OperationInputPayload, ProcessingMode, SubjectClosureManifest, Trigger, TriggerCompletion,
        TriggerFormat, TriggerInput, Validate, WorldCheckpoint,
        verify_managed_candidate_capture_grant,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{PackagedSubjectObject, RustSubjectPackage};

const CANDIDATE_MEDIA_TYPE: &str = "application/vnd.reproit.candidate.v1+json";
const FAILURE_MEDIA_TYPE: &str = "application/vnd.reproit.failure.v1+json";
const SUBJECT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.reproit.subject-closure.v1+json";
const TRIGGER_MEDIA_TYPE: &str = "application/vnd.reproit.trigger.v1+json";
const WORLD_MANIFEST_MEDIA_TYPE: &str = "application/vnd.reproit.world-manifest.v1+json";
const DEPENDENCY_TRANSCRIPT_MEDIA_TYPE: &str =
    "application/vnd.reproit.dependency-transcript.v1+json";
const GRANT_TIMEOUT: Duration = Duration::from_secs(5);
// The ingress verifies the digest and size of every declared ciphertext byte
// before it commits, so the commit wait scales with the declared closure. The
// floor covers control latency, the rate is a conservative verification
// throughput, and the cap bounds the wait for the maximum closure.
const COMMIT_TIMEOUT_FLOOR: Duration = Duration::from_secs(5);
const COMMIT_VERIFICATION_BYTES_PER_SECOND: u64 = 4 * 1024 * 1024;
const COMMIT_TIMEOUT_CAP: Duration = Duration::from_mins(3);

fn commit_timeout(total_ciphertext_bytes: u64) -> Duration {
    let verification_seconds =
        total_ciphertext_bytes.div_ceil(COMMIT_VERIFICATION_BYTES_PER_SECOND);
    COMMIT_TIMEOUT_CAP.min(COMMIT_TIMEOUT_FLOOR + Duration::from_secs(verification_seconds))
}
const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_ARTIFACT_BYTES: u64 = 274_878_824_448;
const MAX_CONCURRENT_OBJECT_UPLOADS: usize = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManagedCandidateArtifact {
    pub media_type: String,
    pub object_id: ObjectId,
    pub path: PathBuf,
    pub role: LogicalObjectRole,
    pub uri: String,
}

pub struct ManagedRustCaptureClosure {
    pub artifacts: Vec<ManagedCandidateArtifact>,
    pub completion: TriggerCompletion,
    pub world: WorldCheckpoint,
}

pub trait ManagedRustCaptureClosureProvider: Send + Sync + 'static {
    fn capture_closure(
        &self,
        operation_id: OperationId,
    ) -> Result<ManagedRustCaptureClosure, Error>;
}

impl<F> ManagedRustCaptureClosureProvider for F
where
    F: Fn(OperationId) -> Result<ManagedRustCaptureClosure, Error> + Send + Sync + 'static,
{
    fn capture_closure(
        &self,
        operation_id: OperationId,
    ) -> Result<ManagedRustCaptureClosure, Error> {
        self(operation_id)
    }
}

pub(crate) struct FrozenManagedRustCaptureClosure {
    pub closure: ManagedRustCaptureClosure,
    _spool: Option<TempDir>,
}

pub struct ManagedRustOperationClosure {
    closure: FrozenManagedRustCaptureClosure,
    operation_id: OperationId,
}

impl ManagedRustOperationClosure {
    pub fn capture<P>(operation_id: OperationId, provider: &P) -> Result<Self, Error>
    where
        P: ManagedRustCaptureClosureProvider + ?Sized,
    {
        let closure = provider.capture_closure(operation_id)?;
        let closure = FrozenManagedRustCaptureClosure::freeze(closure)?;
        closure.validate_operation_binding(operation_id)?;
        Ok(Self {
            closure,
            operation_id,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub fn world_id(&self) -> Result<Digest, Error> {
        self.closure.closure.world.world_id()
    }

    pub(crate) fn into_parts(self) -> (OperationId, FrozenManagedRustCaptureClosure) {
        (self.operation_id, self.closure)
    }
}

impl FrozenManagedRustCaptureClosure {
    pub fn freeze(closure: ManagedRustCaptureClosure) -> Result<Self, Error> {
        closure.world.validate()?;
        validate_static_artifact_set(&closure.world, &closure.artifacts)?;
        let spool = (!closure.artifacts.is_empty())
            .then(|| {
                tempfile::Builder::new()
                    .prefix("reproit-managed-world-")
                    .tempdir()
                    .map_err(|_| local_storage_error())
            })
            .transpose()?;
        let artifacts = match &spool {
            Some(spool) => closure
                .artifacts
                .iter()
                .map(|artifact| freeze_artifact(artifact, spool.path()))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        validate_static_artifact_set(&closure.world, &artifacts)?;
        Ok(Self {
            closure: ManagedRustCaptureClosure {
                artifacts,
                completion: closure.completion,
                world: closure.world,
            },
            _spool: spool,
        })
    }

    pub(crate) fn into_worker_owner(self) -> std::sync::Arc<Self> {
        std::sync::Arc::new(self)
    }

    pub fn validate_operation_binding(&self, operation_id: OperationId) -> Result<(), Error> {
        for artifact in self.closure.artifacts.iter().filter(|artifact| {
            artifact.role == LogicalObjectRole::DependencyTranscript
                && artifact.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        }) {
            let bytes = fs::read(&artifact.path).map_err(|_| incomplete_candidate())?;
            let transcript: DependencyTranscript = canonical::parse_strict(&bytes)?;
            transcript.validate()?;
            if transcript.interactions.iter().any(|interaction| {
                interaction.operation_id != operation_id
                    && interaction.causal_parent_id != Some(operation_id)
            }) {
                return Err(incomplete_candidate());
            }
        }
        Ok(())
    }
}

pub trait ManagedCandidateGrantDelivery: Send + Sync + 'static {
    fn request_encryption_grant(
        &self,
        request: &ManagedCandidateEncryptionGrantRequest,
        timeout: Duration,
    ) -> Result<ManagedCandidateEncryptionResponse, Error>;
}

pub trait ManagedCandidateIngressDelivery: Send + Sync + 'static {
    fn start(
        &self,
        request: &ManagedCandidateUploadRequest,
        timeout: Duration,
    ) -> Result<ManagedCandidateStart, Error>;

    fn missing(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        cursor: Option<&str>,
        timeout: Duration,
    ) -> Result<UploadMissingPage, Error>;

    fn upload_object(
        &self,
        upload_url: &str,
        digest: Digest,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), Error>;

    fn commit(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        timeout: Duration,
    ) -> Result<ManagedCandidateCommit, Error>;

    fn cancel(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        timeout: Duration,
    ) -> Result<ManagedCandidateStatus, Error>;
}

pub struct PreparedManagedRustCandidate {
    identity: ManagedCandidateIdentity,
    objects: Vec<PreparedCandidateObject>,
    _capture_spool: Option<TempDir>,
    _subject: std::sync::Arc<RustSubjectPackage>,
}

pub struct SealedManagedRustCandidate {
    pub request: ManagedCandidateUploadRequest,
    candidate_key: reproit_cloud_api::CandidateKey,
    ciphertext: BTreeMap<Digest, PathBuf>,
    deployment_digest: Digest,
    _spool: TempDir,
}

impl SealedManagedRustCandidate {
    pub fn ciphertext_path(&self, digest: Digest) -> Option<&PathBuf> {
        self.ciphertext.get(&digest)
    }

    pub fn ciphertext_digests(&self) -> impl Iterator<Item = Digest> + '_ {
        self.ciphertext.keys().copied()
    }

    pub fn request_capture_grant_renewal(
        &self,
        delivery: &dyn ManagedCandidateGrantDelivery,
        signer_key_id: &str,
        signing_key: &SecretKey,
    ) -> Result<ManagedCandidateEncryptionResponse, Error> {
        let identity = &self.request.ciphertext_identity;
        let request = signed_grant_request(
            identity.candidate_identity_digest,
            identity.capture_id,
            self.deployment_digest,
            identity.organization_id,
            identity.project_id,
            identity.service_id,
            signer_key_id,
            signing_key,
        )?;
        delivery.request_encryption_grant(&request, GRANT_TIMEOUT)
    }

    pub fn apply_renewed_capture_grant(
        &mut self,
        response: ManagedCandidateEncryptionResponse,
        now: &Timestamp,
        capture_signer_id: &str,
        capture_signer_public_key: &[u8; 32],
    ) -> Result<(), Error> {
        let identity = &self.request.ciphertext_identity;
        response.validate()?;
        if response.candidate_key != self.candidate_key
            || response.capture_grant.candidate_key_reference != identity.candidate_key_reference
        {
            return Err(Error::new(
                ErrorCode::CaptureIdConflict,
                "The renewed managed capture grant does not match the live candidate key.",
            ));
        }
        verify_managed_candidate_capture_grant(
            &response.capture_grant,
            &ManagedCandidateCaptureGrantExpectation {
                candidate_identity_digest: identity.candidate_identity_digest,
                candidate_key_reference: identity.candidate_key_reference.clone(),
                capture_id: identity.capture_id,
                organization_id: identity.organization_id,
                project_id: identity.project_id,
                service_id: identity.service_id,
                signer_key_id: capture_signer_id.to_owned(),
            },
            now,
            capture_signer_public_key,
        )?;
        self.request.capture_grant = response.capture_grant;
        self.request.validate()
    }

    pub fn upload(
        &self,
        delivery: &dyn ManagedCandidateIngressDelivery,
    ) -> Result<ManagedCandidateCommit, Error> {
        let commit_timeout =
            commit_timeout(self.request.ciphertext_identity.total_ciphertext_bytes);
        let start = delivery.start(&self.request, GRANT_TIMEOUT)?;
        if start.state == ManagedCandidateUploadState::Committed {
            return delivery.commit(start.upload_id, &start.upload_token, commit_timeout);
        }
        if !matches!(
            start.state,
            ManagedCandidateUploadState::Open | ManagedCandidateUploadState::Uploading
        ) {
            return Err(upload_state_error());
        }
        let result = self.upload_missing(delivery, &start);
        if result.is_err() {
            let _ = delivery.cancel(start.upload_id, &start.upload_token, GRANT_TIMEOUT);
        }
        result?;
        let commit = match delivery.commit(start.upload_id, &start.upload_token, commit_timeout) {
            Ok(commit) => commit,
            Err(error) => {
                let _ = delivery.cancel(start.upload_id, &start.upload_token, GRANT_TIMEOUT);
                return Err(error);
            }
        };
        if commit.capture_id != self.request.capture_grant.capture_id
            || commit.candidate_identity_digest
                != self.request.ciphertext_identity.candidate_identity_digest
            || commit.candidate_key_reference
                != self.request.ciphertext_identity.candidate_key_reference
            || commit.encrypted_candidate_digest != self.request.encrypted_candidate_digest
            || commit.state != CandidateDurability::CloudProtected
        {
            return Err(upload_state_error());
        }
        Ok(commit)
    }

    fn upload_missing(
        &self,
        delivery: &dyn ManagedCandidateIngressDelivery,
        start: &ManagedCandidateStart,
    ) -> Result<(), Error> {
        let mut page = UploadMissingPage {
            missing_objects: start.missing_objects.clone(),
            next_missing_cursor: start.next_missing_cursor.clone(),
        };
        let mut seen = BTreeSet::new();
        let maximum_pages = self.ciphertext.len().div_ceil(100).saturating_add(1);
        for _ in 0..maximum_pages {
            if page.missing_objects.len() > 100 {
                return Err(upload_state_error());
            }
            for missing in &page.missing_objects {
                if !seen.insert(missing.cipher_digest) {
                    return Err(upload_state_error());
                }
                if !self.ciphertext.contains_key(&missing.cipher_digest) {
                    return Err(upload_state_error());
                }
            }
            for batch in page.missing_objects.chunks(MAX_CONCURRENT_OBJECT_UPLOADS) {
                std::thread::scope(|scope| {
                    let handles = batch
                        .iter()
                        .map(|missing| {
                            let path = &self.ciphertext[&missing.cipher_digest];
                            scope.spawn(move || {
                                upload_missing_object(
                                    delivery,
                                    missing,
                                    path,
                                    start.limits.object_attempts,
                                )
                            })
                        })
                        .collect::<Vec<_>>();
                    for handle in handles {
                        handle.join().map_err(|_| upload_state_error())??;
                    }
                    Ok::<(), Error>(())
                })?;
            }
            let Some(cursor) = page.next_missing_cursor.as_deref() else {
                return Ok(());
            };
            page = delivery.missing(
                start.upload_id,
                &start.upload_token,
                Some(cursor),
                GRANT_TIMEOUT,
            )?;
        }
        Err(upload_state_error())
    }
}

fn upload_missing_object(
    delivery: &dyn ManagedCandidateIngressDelivery,
    missing: &reproit_cloud_api::MissingObject,
    path: &Path,
    attempts: u8,
) -> Result<(), Error> {
    let bytes = fs::read(path).map_err(|_| local_storage_error())?;
    if Digest::of(&bytes) != missing.cipher_digest {
        return Err(Error::object_digest_mismatch());
    }
    upload_with_bound(delivery, missing, &bytes, attempts)
}

fn upload_with_bound(
    delivery: &dyn ManagedCandidateIngressDelivery,
    missing: &reproit_cloud_api::MissingObject,
    bytes: &[u8],
    attempts: u8,
) -> Result<(), Error> {
    if attempts == 0 || attempts > 5 {
        return Err(upload_state_error());
    }
    let mut last_error = None;
    for _ in 0..attempts {
        match delivery.upload_object(
            &missing.upload_url,
            missing.cipher_digest,
            bytes,
            GRANT_TIMEOUT,
        ) {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(upload_state_error))
}

struct PreparedCandidateObject {
    descriptor: LogicalObject,
    source: PreparedObjectSource,
}

enum PreparedObjectSource {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl PreparedManagedRustCandidate {
    pub fn prepare(
        candidate: &Candidate,
        subject: RustSubjectPackage,
        world: &WorldCheckpoint,
        completion: TriggerCompletion,
    ) -> Result<Self, Error> {
        let closure = ManagedRustCaptureClosure {
            artifacts: Vec::new(),
            completion,
            world: world.clone(),
        };
        Self::prepare_complete_shared(candidate, std::sync::Arc::new(subject), &closure)
    }

    pub fn prepare_complete(
        candidate: &Candidate,
        subject: RustSubjectPackage,
        closure: &ManagedRustCaptureClosure,
    ) -> Result<Self, Error> {
        Self::prepare_complete_shared(candidate, std::sync::Arc::new(subject), closure)
    }

    pub fn prepare_complete_shared(
        candidate: &Candidate,
        subject: std::sync::Arc<RustSubjectPackage>,
        closure: &ManagedRustCaptureClosure,
    ) -> Result<Self, Error> {
        candidate.validate()?;
        subject.manifest.validate()?;
        closure.world.validate()?;
        if candidate.processing_mode != ProcessingMode::Managed {
            return Err(Error::new(
                ErrorCode::SchemaInvalid,
                "Managed capture requires a managed deployment.",
            ));
        }
        validate_subject_binding(candidate, &subject.manifest)?;
        if closure.world.world_id()? != candidate.world_id {
            return Err(incomplete_candidate());
        }

        let capture_spool = (!closure.artifacts.is_empty())
            .then(|| {
                tempfile::Builder::new()
                    .prefix("reproit-managed-closure-")
                    .tempdir()
                    .map_err(|_| local_storage_error())
            })
            .transpose()?;
        let mut objects = Vec::new();
        push_bytes(
            &mut objects,
            new_object_id()?,
            LogicalObjectRole::Candidate,
            CANDIDATE_MEDIA_TYPE,
            canonical::canonical_bytes(candidate)?,
        )?;
        push_subject(&mut objects, &subject)?;
        push_trigger_and_inputs(&mut objects, candidate, closure.completion)?;
        push_failure(&mut objects, candidate)?;
        push_bytes(
            &mut objects,
            new_object_id()?,
            LogicalObjectRole::WorldManifest,
            WORLD_MANIFEST_MEDIA_TYPE,
            canonical::canonical_bytes(&closure.world)?,
        )?;
        push_capture_artifacts(
            &mut objects,
            candidate,
            &closure.world,
            &closure.artifacts,
            capture_spool.as_ref().map(TempDir::path),
        )?;
        objects.sort_by_key(|object| object.descriptor.object_id);

        verify_local_closure(&objects)?;
        let descriptors = objects
            .iter()
            .map(|object| object.descriptor.clone())
            .collect::<Vec<_>>();
        let candidate_digest = canonical::digest(candidate)?;
        let subject_digest = canonical::digest(&subject.manifest)?;
        let total_plaintext_bytes = descriptors.iter().try_fold(0_u64, |total, object| {
            total
                .checked_add(object.plain_size)
                .ok_or_else(Error::schema_invalid)
        })?;
        let identity = ManagedCandidateIdentity {
            candidate_digest,
            capture_id: candidate.capture_id,
            deployment_digest: canonical::digest(&candidate.deployment)?,
            format: ManagedCandidateIdentityFormat::V1,
            objects: descriptors,
            organization_id: candidate.deployment.organization_id,
            processing_mode: ProcessingMode::Managed,
            project_id: candidate.deployment.project_id,
            required_capabilities: candidate.deployment.runtime_capabilities.clone(),
            service_id: candidate.deployment.service_id,
            subject_digest,
            total_plaintext_bytes,
        };
        identity.validate()?;
        Ok(Self {
            identity,
            objects,
            _capture_spool: capture_spool,
            _subject: subject,
        })
    }

    pub fn identity(&self) -> &ManagedCandidateIdentity {
        &self.identity
    }

    pub fn request_encryption_grant(
        &self,
        delivery: &dyn ManagedCandidateGrantDelivery,
        signer_key_id: &str,
        signing_key: &SecretKey,
    ) -> Result<ManagedCandidateEncryptionResponse, Error> {
        self.identity.validate()?;
        verify_local_closure(&self.objects)?;
        let request = signed_grant_request(
            canonical::digest(&self.identity)?,
            self.identity.capture_id,
            self.identity.deployment_digest,
            self.identity.organization_id,
            self.identity.project_id,
            self.identity.service_id,
            signer_key_id,
            signing_key,
        )?;
        delivery.request_encryption_grant(&request, GRANT_TIMEOUT)
    }

    pub fn seal(
        self,
        response: ManagedCandidateEncryptionResponse,
        now: &Timestamp,
        capture_signer_id: &str,
        capture_signer_public_key: &[u8; 32],
    ) -> Result<SealedManagedRustCandidate, Error> {
        response.validate()?;
        let identity_digest = canonical::digest(&self.identity)?;
        let key_reference = response.capture_grant.candidate_key_reference.clone();
        verify_managed_candidate_capture_grant(
            &response.capture_grant,
            &ManagedCandidateCaptureGrantExpectation {
                candidate_identity_digest: identity_digest,
                candidate_key_reference: key_reference.clone(),
                capture_id: self.identity.capture_id,
                organization_id: self.identity.organization_id,
                project_id: self.identity.project_id,
                service_id: self.identity.service_id,
                signer_key_id: capture_signer_id.to_owned(),
            },
            now,
            capture_signer_public_key,
        )?;
        verify_local_closure(&self.objects)?;

        let spool = tempfile::Builder::new()
            .prefix("reproit-managed-candidate-")
            .tempdir()
            .map_err(|_| local_storage_error())?;
        let key = secret_key(*response.candidate_key.expose());
        let mut ciphertext = BTreeMap::new();
        let mut encrypted_objects = Vec::with_capacity(self.objects.len());
        let mut nonces = NonceRegistry::default();
        for object in &self.objects {
            encrypted_objects.push(encrypt_object(
                &key,
                &self.identity,
                object,
                spool.path(),
                &mut ciphertext,
                &mut nonces,
            )?);
        }
        let manifest = ManagedCandidateManifest {
            candidate_identity: self.identity.clone(),
            candidate_identity_digest: identity_digest,
            candidate_key_reference: key_reference.clone(),
            cipher_suite: CandidateCipherSuite::Aes256GcmHkdfSha256,
            format: ManagedCandidateManifestFormat::V1,
        };
        manifest.validate()?;
        let manifest_object_id = new_object_id()?;
        let manifest_object = encrypt_manifest(
            &key,
            &self.identity,
            manifest_object_id,
            &canonical::canonical_bytes(&manifest)?,
            spool.path(),
            &mut ciphertext,
            &mut nonces,
        )?;
        let total_ciphertext_bytes = encrypted_objects
            .iter()
            .flat_map(|object| &object.chunks)
            .try_fold(manifest_object.cipher_size, |total, chunk| {
                total
                    .checked_add(chunk.cipher_size)
                    .ok_or_else(Error::schema_invalid)
            })?;
        let ciphertext_identity = ManagedCandidateCiphertextIdentity {
            candidate_identity_digest: identity_digest,
            candidate_key_reference: key_reference,
            capture_id: self.identity.capture_id,
            cipher_suite: CandidateCipherSuite::Aes256GcmHkdfSha256,
            format: ManagedCandidateCiphertextIdentityFormat::V1,
            manifest_object,
            objects: encrypted_objects,
            organization_id: self.identity.organization_id,
            processing_mode: ProcessingMode::Managed,
            project_id: self.identity.project_id,
            required_capabilities: self.identity.required_capabilities.clone(),
            service_id: self.identity.service_id,
            total_ciphertext_bytes,
        };
        ciphertext_identity.validate()?;
        let request = ManagedCandidateUploadRequest {
            capture_grant: response.capture_grant,
            encrypted_candidate_digest: canonical::digest(&ciphertext_identity)?,
            ciphertext_identity,
        };
        request.validate()?;
        Ok(SealedManagedRustCandidate {
            request,
            candidate_key: response.candidate_key,
            ciphertext,
            deployment_digest: self.identity.deployment_digest,
            _spool: spool,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_grant_request(
    candidate_identity_digest: Digest,
    capture_id: reproit_core::identity::CaptureId,
    deployment_digest: Digest,
    organization_id: reproit_core::identity::OrganizationId,
    project_id: reproit_core::identity::ProjectId,
    service_id: reproit_core::identity::ServiceId,
    signer_key_id: &str,
    signing_key: &SecretKey,
) -> Result<ManagedCandidateEncryptionGrantRequest, Error> {
    let mut request = ManagedCandidateEncryptionGrantRequest {
        candidate_identity_digest,
        capture_id,
        cipher_suite: CandidateCipherSuite::Aes256GcmHkdfSha256,
        deployment_digest,
        organization_id,
        processing_mode: ProcessingMode::Managed,
        project_id,
        service_id,
        signature: String::new(),
        signer_key_id: signer_key_id.to_owned(),
    };
    request.signature = sign_bytes(&canonical::canonical_bytes(&request)?, signing_key);
    request.validate()?;
    Ok(request)
}

fn encrypt_object(
    key: &reproit_core::crypto::SecretKey,
    identity: &ManagedCandidateIdentity,
    object: &PreparedCandidateObject,
    spool: &std::path::Path,
    ciphertext: &mut BTreeMap<Digest, PathBuf>,
    nonces: &mut NonceRegistry,
) -> Result<EncryptedObject, Error> {
    let chunk_count = object
        .descriptor
        .plain_size
        .max(1)
        .div_ceil(MAX_CHUNK_BYTES as u64);
    let chunk_count = u32::try_from(chunk_count).map_err(|_| incomplete_candidate())?;
    if chunk_count > 32_767 {
        return Err(incomplete_candidate());
    }
    let object_context = object_context(
        identity,
        object.descriptor.object_id,
        object.descriptor.role,
    );
    let object_context_digest = canonical::digest(&object_context)?;
    let object_key = derive_object_key(key, identity.capture_id, &object_context)?;
    let mut reader: Box<dyn Read> = match &object.source {
        PreparedObjectSource::Bytes(bytes) => Box::new(Cursor::new(bytes)),
        PreparedObjectSource::File(path) => {
            Box::new(File::open(path).map_err(|_| incomplete_candidate())?)
        }
    };
    let mut remaining = object.descriptor.plain_size;
    let mut plain_hasher = Sha256::new();
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for index in 0..chunk_count {
        let plain_size = remaining.min(MAX_CHUNK_BYTES as u64);
        let mut plaintext =
            vec![0_u8; usize::try_from(plain_size).map_err(|_| incomplete_candidate())?];
        reader
            .read_exact(&mut plaintext)
            .map_err(|_| incomplete_candidate())?;
        plain_hasher.update(&plaintext);
        let context = ChunkKeyContext {
            chunk_count,
            chunk_index: index,
            format: ChunkKeyContextFormat::V1,
            object_context_digest,
            plain_size,
        };
        let chunk_key = derive_chunk_key(&object_key, &context)?;
        let nonce = random_nonce(nonces)?;
        let stored = encrypt_chunk(&chunk_key, nonce, &plaintext, &context)?;
        chunks.push(store_ciphertext(spool, ciphertext, index, nonce, &stored)?);
        remaining = remaining.saturating_sub(plain_size);
    }
    let mut trailing = [0_u8; 1];
    if remaining != 0
        || reader
            .read(&mut trailing)
            .map_err(|_| incomplete_candidate())?
            != 0
        || Digest::from_bytes(plain_hasher.finalize().into()) != object.descriptor.plain_digest
    {
        return Err(incomplete_candidate());
    }
    Ok(EncryptedObject {
        chunks,
        descriptor: object.descriptor.clone(),
    })
}

fn encrypt_manifest(
    key: &reproit_core::crypto::SecretKey,
    identity: &ManagedCandidateIdentity,
    object_id: ObjectId,
    plaintext: &[u8],
    spool: &std::path::Path,
    ciphertext: &mut BTreeMap<Digest, PathBuf>,
    nonces: &mut NonceRegistry,
) -> Result<ManifestUploadObject, Error> {
    if plaintext.len() > MAX_CHUNK_BYTES {
        return Err(incomplete_candidate());
    }
    let object_context =
        object_context(identity, object_id, LogicalObjectRole::CaptureBatchManifest);
    let context = ChunkKeyContext {
        chunk_count: 1,
        chunk_index: 0,
        format: ChunkKeyContextFormat::V1,
        object_context_digest: canonical::digest(&object_context)?,
        plain_size: u64::try_from(plaintext.len()).map_err(|_| incomplete_candidate())?,
    };
    let object_key = derive_object_key(key, identity.capture_id, &object_context)?;
    let chunk_key = derive_chunk_key(&object_key, &context)?;
    let nonce = random_nonce(nonces)?;
    let stored = encrypt_chunk(&chunk_key, nonce, plaintext, &context)?;
    let chunk = store_ciphertext(spool, ciphertext, 0, nonce, &stored)?;
    Ok(ManifestUploadObject {
        cipher_digest: chunk.cipher_digest,
        cipher_size: chunk.cipher_size,
        nonce: chunk.nonce,
        object_id,
    })
}

fn object_context(
    identity: &ManagedCandidateIdentity,
    object_id: ObjectId,
    role: LogicalObjectRole,
) -> ObjectKeyContext {
    ObjectKeyContext {
        capture_batch_format: "reproit.capture-batch.v1".to_owned(),
        capture_id: identity.capture_id,
        format: ObjectKeyContextFormat::V1,
        object_id,
        organization_id: identity.organization_id,
        processing_mode: ProcessingMode::Managed,
        project_id: identity.project_id,
        role,
        service_id: identity.service_id,
    }
}

fn store_ciphertext(
    spool: &std::path::Path,
    ciphertext: &mut BTreeMap<Digest, PathBuf>,
    index: u32,
    nonce: [u8; 12],
    stored: &[u8],
) -> Result<EncryptedChunk, Error> {
    let digest = Digest::of(stored);
    let path = spool.join(digest_name(digest));
    if !path.exists() {
        fs::write(&path, stored).map_err(|_| local_storage_error())?;
    }
    if let Some(existing) = ciphertext.insert(digest, path.clone())
        && existing != path
    {
        return Err(Error::object_digest_mismatch());
    }
    Ok(EncryptedChunk {
        cipher_digest: digest,
        cipher_size: u64::try_from(stored.len()).map_err(|_| incomplete_candidate())?,
        index,
        nonce: encode_base64url(&nonce),
    })
}

fn random_nonce(registry: &mut NonceRegistry) -> Result<[u8; 12], Error> {
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| local_storage_error())?;
    registry.register(nonce)?;
    Ok(nonce)
}

fn digest_name(digest: Digest) -> String {
    digest
        .to_string()
        .strip_prefix("sha256:")
        .expect("Digest display always has the sha256 prefix")
        .to_owned()
}

fn validate_subject_binding(
    candidate: &Candidate,
    manifest: &SubjectClosureManifest,
) -> Result<(), Error> {
    let subject = &candidate.deployment.subject;
    let manifest_digest = canonical::digest(manifest)?;
    if subject.artifact_digest != manifest_digest
        || subject.artifact_media_type != SUBJECT_MANIFEST_MEDIA_TYPE
        || subject.architecture != manifest.architecture
        || subject.operating_system != manifest.operating_system
        || subject.arguments != manifest.launch.arguments
        || subject.environment_names != manifest.launch.environment_names
        || subject.executable != manifest.launch.executable
        || subject.working_directory != manifest.launch.working_directory
        || !candidate
            .deployment
            .runtime_capabilities
            .contains(&manifest.architecture)
        || !candidate
            .deployment
            .runtime_capabilities
            .contains(&manifest.operating_system)
    {
        return Err(Error::new(
            ErrorCode::SubjectDigestMismatch,
            "The managed deployment does not match the running subject package.",
        ));
    }
    Ok(())
}

fn push_subject(
    objects: &mut Vec<PreparedCandidateObject>,
    subject: &RustSubjectPackage,
) -> Result<(), Error> {
    push_bytes(
        objects,
        new_object_id()?,
        LogicalObjectRole::Subject,
        SUBJECT_MANIFEST_MEDIA_TYPE,
        canonical::canonical_bytes(&subject.manifest)?,
    )?;
    let declared = subject
        .manifest
        .objects
        .iter()
        .map(|object| (object.digest, (object.media_type.as_str(), object.size)))
        .collect::<BTreeMap<_, _>>();
    if declared.len() != subject.objects.len() {
        return Err(incomplete_candidate());
    }
    for object in &subject.objects {
        let (media_type, size) = declared
            .get(&object.digest)
            .copied()
            .ok_or_else(incomplete_candidate)?;
        if size != object.size {
            return Err(incomplete_candidate());
        }
        push_file(objects, new_object_id()?, media_type, object)?;
    }
    Ok(())
}

fn push_capture_artifacts(
    objects: &mut Vec<PreparedCandidateObject>,
    candidate: &Candidate,
    world: &WorldCheckpoint,
    artifacts: &[ManagedCandidateArtifact],
    spool: Option<&Path>,
) -> Result<(), Error> {
    if artifacts.len() > 32_767
        || artifacts.is_empty() && closure_requires_artifacts(candidate, world)
    {
        return Err(incomplete_candidate());
    }
    let expected_world = world
        .points
        .iter()
        .flat_map(|point| &point.artifacts)
        .map(|artifact| {
            (
                artifact.uri.clone(),
                artifact.digest,
                artifact.size,
                artifact.media_type.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let supplied_world = artifacts
        .iter()
        .filter(|artifact| artifact.role == LogicalObjectRole::WorldState)
        .map(|artifact| artifact.uri.clone())
        .collect::<BTreeSet<_>>();
    if expected_world.len() != supplied_world.len()
        || expected_world
            .iter()
            .any(|(uri, _, _, _)| !supplied_world.contains(uri))
    {
        return Err(incomplete_candidate());
    }
    let spool = match (artifacts.is_empty(), spool) {
        (true, _) => return validate_dependency_closure(candidate, objects),
        (false, Some(spool)) => spool,
        (false, None) => return Err(local_storage_error()),
    };
    let mut seen_uris = BTreeSet::new();
    for artifact in artifacts {
        if !matches!(
            artifact.role,
            LogicalObjectRole::DependencyTranscript | LogicalObjectRole::WorldState
        ) || artifact.uri.is_empty()
            || artifact.uri.len() > 2_048
            || !seen_uris.insert(artifact.uri.clone())
        {
            return Err(incomplete_candidate());
        }
        let captured = capture_artifact(artifact, spool)?;
        if artifact.role == LogicalObjectRole::WorldState
            && !expected_world.contains(&(
                artifact.uri.clone(),
                captured.descriptor.plain_digest,
                captured.descriptor.plain_size,
                artifact.media_type.clone(),
            ))
        {
            return Err(incomplete_candidate());
        }
        objects.push(captured);
    }
    validate_dependency_closure(candidate, objects)
}

fn validate_static_artifact_set(
    world: &WorldCheckpoint,
    artifacts: &[ManagedCandidateArtifact],
) -> Result<(), Error> {
    if artifacts.len() > 32_767 {
        return Err(incomplete_candidate());
    }
    let expected_world = world
        .points
        .iter()
        .flat_map(|point| &point.artifacts)
        .map(|artifact| {
            (
                artifact.uri.clone(),
                artifact.digest,
                artifact.size,
                artifact.media_type.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let supplied_world = artifacts
        .iter()
        .filter(|artifact| artifact.role == LogicalObjectRole::WorldState)
        .map(|artifact| artifact.uri.clone())
        .collect::<BTreeSet<_>>();
    if expected_world.len() != supplied_world.len()
        || expected_world
            .iter()
            .any(|(uri, _, _, _)| !supplied_world.contains(uri))
    {
        return Err(incomplete_candidate());
    }
    let mut object_ids = BTreeSet::new();
    let mut uris = BTreeSet::new();
    for artifact in artifacts {
        if !matches!(
            artifact.role,
            LogicalObjectRole::DependencyTranscript | LogicalObjectRole::WorldState
        ) || artifact.uri.is_empty()
            || artifact.uri.len() > 2_048
            || artifact.media_type.is_empty()
            || artifact.media_type.len() > 256
            || !object_ids.insert(artifact.object_id)
            || !uris.insert(artifact.uri.clone())
        {
            return Err(incomplete_candidate());
        }
        let metadata = fs::symlink_metadata(&artifact.path).map_err(|_| incomplete_candidate())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_CAPTURE_ARTIFACT_BYTES
        {
            return Err(incomplete_candidate());
        }
        let (size, digest) = hash_file(&artifact.path)?;
        if artifact.role == LogicalObjectRole::WorldState
            && !expected_world.contains(&(
                artifact.uri.clone(),
                digest,
                size,
                artifact.media_type.clone(),
            ))
        {
            return Err(incomplete_candidate());
        }
        if artifact.role == LogicalObjectRole::DependencyTranscript
            && artifact.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        {
            if size > MAX_CHUNK_BYTES as u64 {
                return Err(incomplete_candidate());
            }
            let bytes = fs::read(&artifact.path).map_err(|_| incomplete_candidate())?;
            let transcript: DependencyTranscript = canonical::parse_strict(&bytes)?;
            transcript.validate()?;
        }
    }
    Ok(())
}

fn freeze_artifact(
    artifact: &ManagedCandidateArtifact,
    spool: &Path,
) -> Result<ManagedCandidateArtifact, Error> {
    let captured = capture_artifact(artifact, spool)?;
    let PreparedObjectSource::File(path) = captured.source else {
        return Err(incomplete_candidate());
    };
    Ok(ManagedCandidateArtifact {
        media_type: captured.descriptor.media_type,
        object_id: captured.descriptor.object_id,
        path,
        role: captured.descriptor.role,
        uri: artifact.uri.clone(),
    })
}

fn closure_requires_artifacts(candidate: &Candidate, world: &WorldCheckpoint) -> bool {
    world.points.iter().any(|point| !point.artifacts.is_empty())
        || candidate
            .records
            .iter()
            .any(|record| record.kind == EventKind::Dependency)
}

fn capture_artifact(
    artifact: &ManagedCandidateArtifact,
    spool: &Path,
) -> Result<PreparedCandidateObject, Error> {
    let metadata = fs::symlink_metadata(&artifact.path).map_err(|_| incomplete_candidate())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CAPTURE_ARTIFACT_BYTES
    {
        return Err(incomplete_candidate());
    }
    let temporary = spool.join(format!("artifact-{}", new_object_id()?));
    let (first_digest, copied) = copy_and_digest(&artifact.path, &temporary, metadata.len())?;
    let (second_digest, verified) = digest_file(&artifact.path, metadata.len())?;
    if first_digest != second_digest || copied != verified {
        return Err(incomplete_candidate());
    }
    let path = spool.join(digest_name(first_digest));
    if path.exists() {
        let (stored_digest, stored_size) = digest_file(&path, copied)?;
        if stored_digest != first_digest || stored_size != copied {
            return Err(Error::object_digest_mismatch());
        }
        fs::remove_file(&temporary).map_err(|_| local_storage_error())?;
    } else {
        fs::rename(&temporary, &path).map_err(|_| local_storage_error())?;
    }
    let descriptor = LogicalObject {
        media_type: artifact.media_type.clone(),
        object_id: artifact.object_id,
        plain_digest: first_digest,
        plain_size: copied,
        role: artifact.role,
    };
    descriptor.validate()?;
    Ok(PreparedCandidateObject {
        descriptor,
        source: PreparedObjectSource::File(path),
    })
}

fn copy_and_digest(source: &Path, target: &Path, expected: u64) -> Result<(Digest, u64), Error> {
    let mut source = File::open(source).map_err(|_| incomplete_candidate())?;
    let mut target = File::create(target).map_err(|_| local_storage_error())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|_| incomplete_candidate())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| incomplete_candidate())?)
            .ok_or_else(incomplete_candidate)?;
        if total > expected {
            return Err(incomplete_candidate());
        }
        hasher.update(&buffer[..count]);
        target
            .write_all(&buffer[..count])
            .map_err(|_| local_storage_error())?;
    }
    target.flush().map_err(|_| local_storage_error())?;
    if total != expected {
        return Err(incomplete_candidate());
    }
    Ok((Digest::from_bytes(hasher.finalize().into()), total))
}

fn digest_file(path: &Path, expected: u64) -> Result<(Digest, u64), Error> {
    let mut source = File::open(path).map_err(|_| incomplete_candidate())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|_| incomplete_candidate())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| incomplete_candidate())?)
            .ok_or_else(incomplete_candidate)?;
        if total > expected {
            return Err(incomplete_candidate());
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected {
        return Err(incomplete_candidate());
    }
    Ok((Digest::from_bytes(hasher.finalize().into()), total))
}

fn validate_dependency_closure(
    candidate: &Candidate,
    objects: &[PreparedCandidateObject],
) -> Result<(), Error> {
    let cursors = candidate
        .records
        .iter()
        .filter(|record| record.kind == EventKind::Dependency)
        .map(decode_record::<DependencyCursorPayload>)
        .collect::<Result<Vec<_>, _>>()?;
    let mut transcripts = Vec::new();
    let descriptor_by_id = objects
        .iter()
        .map(|object| (object.descriptor.object_id, &object.descriptor))
        .collect::<BTreeMap<_, _>>();
    for object in objects.iter().filter(|object| {
        object.descriptor.role == LogicalObjectRole::DependencyTranscript
            && object.descriptor.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
    }) {
        let bytes = read_prepared_object(object)?;
        let transcript: DependencyTranscript = canonical::parse_strict(&bytes)?;
        transcript.validate()?;
        for interaction in &transcript.interactions {
            if interaction.operation_id != candidate.operation_id
                && interaction.causal_parent_id != Some(candidate.operation_id)
                || !descriptor_matches(
                    &descriptor_by_id,
                    interaction.request_object_id,
                    interaction.request_digest,
                )
                || !descriptor_matches(
                    &descriptor_by_id,
                    interaction.response_object_id,
                    interaction.response_digest,
                )
            {
                return Err(incomplete_candidate());
            }
        }
        transcripts.push(transcript);
    }
    if cursors.len() != transcripts.len()
        || cursors.iter().any(|cursor| {
            transcripts
                .iter()
                .filter(|transcript| {
                    transcript.adapter_id == cursor.adapter_id
                        && transcript.adapter_version == cursor.adapter_version
                })
                .count()
                != 1
        })
    {
        return Err(incomplete_candidate());
    }
    Ok(())
}

fn descriptor_matches(
    objects: &BTreeMap<ObjectId, &LogicalObject>,
    object_id: ObjectId,
    digest: Digest,
) -> bool {
    objects
        .get(&object_id)
        .is_some_and(|object| object.plain_digest == digest)
}

fn read_prepared_object(object: &PreparedCandidateObject) -> Result<Vec<u8>, Error> {
    if object.descriptor.plain_size > MAX_CHUNK_BYTES as u64 {
        return Err(incomplete_candidate());
    }
    match &object.source {
        PreparedObjectSource::Bytes(bytes) => Ok(bytes.clone()),
        PreparedObjectSource::File(path) => fs::read(path).map_err(|_| incomplete_candidate()),
    }
}

fn push_trigger_and_inputs(
    objects: &mut Vec<PreparedCandidateObject>,
    candidate: &Candidate,
    completion: TriggerCompletion,
) -> Result<(), Error> {
    let begin_record = candidate.records.first().ok_or_else(incomplete_candidate)?;
    let begin: OperationBeginPayload = decode_record(begin_record)?;
    let mut inputs = Vec::new();
    for record in candidate
        .records
        .iter()
        .filter(|record| record.kind == EventKind::Input)
    {
        let input: OperationInputPayload = decode_record(record)?;
        let bytes = decode_base64url_bytes(&input.value)?;
        let object_id = new_object_id()?;
        inputs.push(TriggerInput {
            channel: input.channel,
            object_id,
            plain_digest: input.value_digest,
            sequence: u16::try_from(inputs.len()).map_err(|_| incomplete_candidate())?,
        });
        push_bytes(
            objects,
            object_id,
            LogicalObjectRole::Trigger,
            &input.content_type,
            bytes,
        )?;
    }
    let trigger = Trigger {
        adapter_id: begin.adapter_id,
        adapter_version: begin.adapter_version,
        causal_parent_ids: begin.causal_parent_ids,
        completion,
        format: TriggerFormat::V1,
        inputs,
        operation_id: candidate.operation_id,
        operation_kind: begin.operation_kind,
        operation_name: begin.operation_name,
    };
    trigger.validate()?;
    push_bytes(
        objects,
        new_object_id()?,
        LogicalObjectRole::Trigger,
        TRIGGER_MEDIA_TYPE,
        canonical::canonical_bytes(&trigger)?,
    )
}

fn push_failure(
    objects: &mut Vec<PreparedCandidateObject>,
    candidate: &Candidate,
) -> Result<(), Error> {
    let record = candidate
        .records
        .iter()
        .find(|record| record.kind == EventKind::Failure)
        .ok_or_else(incomplete_candidate)?;
    let failure: FailurePayload = decode_record(record)?;
    push_bytes(
        objects,
        failure.failure.object_id,
        LogicalObjectRole::Failure,
        FAILURE_MEDIA_TYPE,
        canonical::canonical_bytes(&failure)?,
    )
}

fn decode_record<T: serde::de::DeserializeOwned>(
    record: &reproit_core::model::EventRecord,
) -> Result<T, Error> {
    canonical::parse_strict(&decode_base64url_bytes(&record.payload)?)
}

fn push_bytes(
    objects: &mut Vec<PreparedCandidateObject>,
    object_id: ObjectId,
    role: LogicalObjectRole,
    media_type: &str,
    bytes: Vec<u8>,
) -> Result<(), Error> {
    let plain_size = u64::try_from(bytes.len()).map_err(|_| incomplete_candidate())?;
    let descriptor = LogicalObject {
        media_type: media_type.to_owned(),
        object_id,
        plain_digest: Digest::of(&bytes),
        plain_size,
        role,
    };
    descriptor.validate()?;
    objects.push(PreparedCandidateObject {
        descriptor,
        source: PreparedObjectSource::Bytes(bytes),
    });
    Ok(())
}

fn push_file(
    objects: &mut Vec<PreparedCandidateObject>,
    object_id: ObjectId,
    media_type: &str,
    object: &PackagedSubjectObject,
) -> Result<(), Error> {
    let descriptor = LogicalObject {
        media_type: media_type.to_owned(),
        object_id,
        plain_digest: object.digest,
        plain_size: object.size,
        role: LogicalObjectRole::Subject,
    };
    descriptor.validate()?;
    objects.push(PreparedCandidateObject {
        descriptor,
        source: PreparedObjectSource::File(object.path.clone()),
    });
    Ok(())
}

fn verify_local_closure(objects: &[PreparedCandidateObject]) -> Result<(), Error> {
    if objects.len() < 5 || objects.len() > 32_767 {
        return Err(incomplete_candidate());
    }
    let mut object_ids = BTreeSet::new();
    for object in objects {
        object.descriptor.validate()?;
        if !object_ids.insert(object.descriptor.object_id) {
            return Err(incomplete_candidate());
        }
        let actual = match &object.source {
            PreparedObjectSource::Bytes(bytes) => (
                u64::try_from(bytes.len()).map_err(|_| incomplete_candidate())?,
                Digest::of(bytes),
            ),
            PreparedObjectSource::File(path) => hash_file(path)?,
        };
        if actual != (object.descriptor.plain_size, object.descriptor.plain_digest) {
            return Err(incomplete_candidate());
        }
    }
    Ok(())
}

fn hash_file(path: &std::path::Path) -> Result<(u64, Digest), Error> {
    let before = fs::metadata(path).map_err(|_| incomplete_candidate())?;
    if !before.is_file() {
        return Err(incomplete_candidate());
    }
    let mut file = File::open(path).map_err(|_| incomplete_candidate())?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| incomplete_candidate())?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|_| incomplete_candidate())?)
            .ok_or_else(incomplete_candidate)?;
        hasher.update(&buffer[..read]);
    }
    let after = fs::metadata(path).map_err(|_| incomplete_candidate())?;
    if before.len() != size
        || after.len() != size
        || before.modified().ok() != after.modified().ok()
    {
        return Err(incomplete_candidate());
    }
    Ok((size, Digest::from_bytes(hasher.finalize().into())))
}

fn new_object_id() -> Result<ObjectId, Error> {
    ObjectId::from_str(&format!("obj_{}", Uuid::now_v7()))
}

fn incomplete_candidate() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The managed candidate is incomplete and cannot be uploaded.",
    )
}

fn local_storage_error() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Repro It could not create the bounded local ciphertext staging area.",
    )
}

fn upload_state_error() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed candidate upload did not reach a valid durable state.",
    )
}

#[cfg(test)]
mod commit_timeout_tests {
    use super::*;

    #[test]
    fn commit_timeout_scales_with_the_declared_closure_and_stays_bounded() {
        assert_eq!(commit_timeout(0), COMMIT_TIMEOUT_FLOOR);
        assert_eq!(
            commit_timeout(1),
            COMMIT_TIMEOUT_FLOOR + Duration::from_secs(1)
        );
        assert_eq!(
            commit_timeout(COMMIT_VERIFICATION_BYTES_PER_SECOND),
            COMMIT_TIMEOUT_FLOOR + Duration::from_secs(1)
        );
        assert_eq!(
            commit_timeout(512 * 1024 * 1024),
            Duration::from_secs(5 + 128)
        );
        assert_eq!(commit_timeout(u64::MAX), COMMIT_TIMEOUT_CAP);
    }
}

#[cfg(test)]
mod closure_tests {
    use super::*;
    use reproit_core::model::{
        DependencyOutcome, DependencyTranscriptFormat, DependencyTranscriptInteraction,
        WorldCheckpointFormat,
    };

    #[test]
    fn static_closure_rejects_an_invalid_transcript() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transcript.json");
        fs::write(&path, b"not-json").unwrap();
        let result = FrozenManagedRustCaptureClosure::freeze(ManagedRustCaptureClosure {
            artifacts: vec![ManagedCandidateArtifact {
                media_type: DEPENDENCY_TRANSCRIPT_MEDIA_TYPE.to_owned(),
                object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7".parse().unwrap(),
                path,
                role: LogicalObjectRole::DependencyTranscript,
                uri: "reproit-managed://dependency-transcript".to_owned(),
            }],
            completion: TriggerCompletion::Return,
            world: empty_world(),
        });
        let Err(error) = result else {
            panic!("the invalid transcript must stay local");
        };
        assert_eq!(error.code, ErrorCode::SchemaInvalid);
    }

    #[test]
    fn static_closure_freezes_artifact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("response.bin");
        fs::write(&path, b"captured").unwrap();
        let frozen = FrozenManagedRustCaptureClosure::freeze(ManagedRustCaptureClosure {
            artifacts: vec![ManagedCandidateArtifact {
                media_type: "application/octet-stream".to_owned(),
                object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7".parse().unwrap(),
                path: path.clone(),
                role: LogicalObjectRole::DependencyTranscript,
                uri: "reproit-managed://dependency-response".to_owned(),
            }],
            completion: TriggerCompletion::Return,
            world: empty_world(),
        })
        .unwrap();
        fs::write(path, b"changed").unwrap();
        assert_eq!(
            fs::read(&frozen.closure.artifacts[0].path).unwrap(),
            b"captured"
        );
    }

    #[test]
    fn worker_owner_keeps_frozen_artifact_bytes_alive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("response.bin");
        fs::write(&path, b"captured").unwrap();
        let frozen = FrozenManagedRustCaptureClosure::freeze(ManagedRustCaptureClosure {
            artifacts: vec![ManagedCandidateArtifact {
                media_type: "application/octet-stream".to_owned(),
                object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7".parse().unwrap(),
                path,
                role: LogicalObjectRole::DependencyTranscript,
                uri: "reproit-managed://dependency-response".to_owned(),
            }],
            completion: TriggerCompletion::Return,
            world: empty_world(),
        })
        .unwrap();
        let owner = frozen.into_worker_owner();
        drop(directory);

        let bytes = std::thread::spawn(move || fs::read(&owner.closure.artifacts[0].path))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"captured");
    }

    #[test]
    fn operation_closure_rejects_a_transcript_for_another_operation() {
        let operation_id: OperationId = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1".parse().unwrap();
        let other_operation_id = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab2".parse().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transcript.json");
        let transcript = DependencyTranscript {
            adapter_id: "http-transcript".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            format: DependencyTranscriptFormat::V1,
            interactions: vec![DependencyTranscriptInteraction {
                causal_parent_id: None,
                operation_id,
                outcome: DependencyOutcome::Response,
                request_digest: Digest::of(b"request"),
                request_object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4".parse().unwrap(),
                response_digest: Digest::of(b"response"),
                response_object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab5".parse().unwrap(),
                sequence: 0,
                session_position: 0,
            }],
        };
        fs::write(&path, canonical::canonical_bytes(&transcript).unwrap()).unwrap();
        let frozen = FrozenManagedRustCaptureClosure::freeze(ManagedRustCaptureClosure {
            artifacts: vec![ManagedCandidateArtifact {
                media_type: DEPENDENCY_TRANSCRIPT_MEDIA_TYPE.to_owned(),
                object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab6".parse().unwrap(),
                path,
                role: LogicalObjectRole::DependencyTranscript,
                uri: "reproit-managed://dependency-transcript".to_owned(),
            }],
            completion: TriggerCompletion::Return,
            world: empty_world(),
        })
        .unwrap();
        frozen.validate_operation_binding(operation_id).unwrap();
        assert_eq!(
            frozen
                .validate_operation_binding(other_operation_id)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
    }

    #[test]
    fn incomplete_operation_provider_stops_before_a_network_client_is_needed() {
        let operation_id = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1".parse().unwrap();
        let provider = |_operation_id| Err(incomplete_candidate());
        let error = ManagedRustOperationClosure::capture(operation_id, &provider)
            .err()
            .expect("the incomplete closure must stay local");
        assert_eq!(error.code, ErrorCode::IncompleteCandidate);
    }

    fn empty_world() -> WorldCheckpoint {
        WorldCheckpoint {
            created_at: "2026-01-01T00:00:00.000Z".parse().unwrap(),
            format: WorldCheckpointFormat::V1,
            points: Vec::new(),
        }
    }
}
