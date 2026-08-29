use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::encode_base64url,
    identity::{Digest, ObjectId, OperationId, Timestamp},
    model::{
        ArtifactReference, AutomaticObservationClass, AutomaticObservationPayload,
        AutomaticObservationPayloadFormat, CheckpointScope, CheckpointScopeKind, ClosurePolicy,
        ClosurePolicyFormat, ClosureReceipt, ClosureRule, DependencyOutcome,
        DependencyTranscriptInteraction, LogicalObjectRole, NativeObservationFenceReceipt,
        NativeObservationFenceReceiptFormat, ProviderResourceClaim, RecoverablePoint,
        RecoverablePointFormat, SemanticAdapterOwnership, SemanticDependencyRequest,
        SemanticDependencyResponse, SemanticObservationOperation, SemanticObservationOutcome,
        SemanticObservationRequest, SemanticObservationResponse, TriggerCompletion, Validate as _,
        WorldCheckpoint, WorldCheckpointFormat, WorldClosure, WorldClosureFormat,
        validate_semantic_dependency_pair, validate_semantic_observation_pair,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    MAX_EVENTS, MAX_WORLD_ARTIFACT_BYTES, MAX_WORLD_BYTES, ManagedCandidateArtifact,
    ManagedRustCaptureClosure, Sdk,
};

#[path = "automatic_world_artifacts.rs"]
mod automatic_world_artifacts;

const ADAPTER_ID: &str = "reproit-native";
const ADAPTER_VERSION: &str = "1.0.0";
const CAPABILITY: &str = "capture.automatic-world.v1";
const DEPENDENCY_TRANSCRIPT_MEDIA_TYPE: &str =
    "application/vnd.reproit.dependency-transcript.v1+json";
const OBSERVATION_OBJECT_MEDIA_TYPE: &str = "application/octet-stream";
const FENCE_ID: &str = "reproit-native-observation-fence";
#[cfg(unix)]
const MAX_AMBIENT_ENVIRONMENT_BYTES: usize = 512 * 1_024;
#[cfg(unix)]
const MAX_AMBIENT_ENVIRONMENT_VALUES: usize = 4_096;
pub(crate) const MAX_NATIVE_SENTINEL_EVIDENCE_BYTES: usize = 256;
const MAX_RECOVERABLE_SECONDS: i64 = 1_800;
const MAX_SESSION_POSITION: u64 = 9_007_199_254_740_991;
const MAX_SEMANTIC_RECORD_BYTES: u64 = 64 * 1_024;

pub(crate) const MAX_AUTOMATIC_OBSERVATION_CHUNK_BYTES: usize = 32 * 1_024;
pub(crate) const MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES: usize = 8 * 1_024;
pub(crate) const MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutomaticObservationAction {
    Capture,
    #[allow(dead_code)]
    Replay,
}

impl AutomaticObservationAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Replay => "replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutomaticObservationStream {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AutomaticObservationSessionState {
    Request,
    Capture,
    Replay { response_offset: u64 },
    Overflowed,
}

pub(crate) struct AutomaticWorldCoordinator {
    artifacts: Vec<ObservationArtifact>,
    dependency_interactions: Vec<DependencyTranscriptInteraction>,
    dropped_observation_count: u64,
    incomplete_session: bool,
    #[cfg(unix)]
    next_internal_session: u64,
    observations: Vec<AutomaticObservationPayload>,
    operation_id: OperationId,
    overflowed: bool,
    registrations: BTreeMap<AutomaticObservationClass, AutomaticObservationRegistration>,
    reservation: crate::resources::LogicalByteReservation,
    sdk: Sdk,
    sessions: BTreeMap<u64, ObservationSession>,
    next_session_positions: BTreeMap<AutomaticObservationClass, u64>,
    spool: TempDir,
}

#[derive(Clone)]
pub(crate) struct AutomaticObservationRegistration {
    adapter_id: String,
    adapter_version: String,
    class: AutomaticObservationClass,
    implementation_digest: Digest,
    sentinel_coverage_digest: Option<Digest>,
}

impl AutomaticObservationRegistration {
    pub(crate) fn new(
        class: AutomaticObservationClass,
        adapter_id: String,
        adapter_version: String,
        implementation_digest: Digest,
    ) -> Result<Self, Error> {
        SemanticAdapterOwnership {
            adapter_id: adapter_id.clone(),
            adapter_version: adapter_version.clone(),
            boundary_id: class.boundary_id().to_owned(),
            implementation_digest,
            observation_class: class,
        }
        .validate()?;
        Ok(Self {
            adapter_id,
            adapter_version,
            class,
            implementation_digest,
            sentinel_coverage_digest: None,
        })
    }

    fn ownership(&self) -> SemanticAdapterOwnership {
        SemanticAdapterOwnership {
            adapter_id: self.adapter_id.clone(),
            adapter_version: self.adapter_version.clone(),
            boundary_id: self.class.boundary_id().to_owned(),
            implementation_digest: self.implementation_digest,
            observation_class: self.class,
        }
    }
}

pub(crate) struct AutomaticWorldCapture {
    pub(crate) closure: ManagedRustCaptureClosure,
    pub(crate) fence: NativeObservationFenceReceipt,
    _reservation: crate::resources::LogicalByteReservation,
    _spool: TempDir,
}

struct ObservationArtifact {
    artifact: ManagedCandidateArtifact,
    reference: Option<ArtifactReference>,
}

struct ObservationSession {
    causal_parent_id: Option<OperationId>,
    class: AutomaticObservationClass,
    request_bytes: u64,
    request_path: PathBuf,
    response_bytes: u64,
    response_path: PathBuf,
    session_position: u64,
    semantic_contract: Option<SemanticContract>,
    state: AutomaticObservationSessionState,
}

#[derive(Clone, Copy)]
enum SemanticContract {
    Dependency,
    ProcessObservation,
}

impl ObservationSession {
    fn validate_semantic_request(&self) -> Result<(), Error> {
        let Some(contract) = self.semantic_contract else {
            return Ok(());
        };
        let class = match contract {
            SemanticContract::Dependency => {
                read_semantic_record::<SemanticDependencyRequest>(
                    &self.request_path,
                    self.request_bytes,
                )?
                .observation_class
            }
            SemanticContract::ProcessObservation => {
                let request = read_semantic_record::<SemanticObservationRequest>(
                    &self.request_path,
                    self.request_bytes,
                )?;
                observation_class(request.operation)
            }
        };
        if class != self.class {
            return Err(invalid_transition());
        }
        Ok(())
    }

    fn validate_semantic_pair(&self, outcome: DependencyOutcome) -> Result<(), Error> {
        let Some(contract) = self.semantic_contract else {
            return Ok(());
        };
        let semantic_outcome = match contract {
            SemanticContract::Dependency => {
                let request = read_semantic_record::<SemanticDependencyRequest>(
                    &self.request_path,
                    self.request_bytes,
                )?;
                let response = read_semantic_record::<SemanticDependencyResponse>(
                    &self.response_path,
                    self.response_bytes,
                )?;
                validate_semantic_dependency_pair(&request, &response)
                    .map_err(|_| invalid_transition())?;
                response.outcome
            }
            SemanticContract::ProcessObservation => {
                let request = read_semantic_record::<SemanticObservationRequest>(
                    &self.request_path,
                    self.request_bytes,
                )?;
                let response = read_semantic_record::<SemanticObservationResponse>(
                    &self.response_path,
                    self.response_bytes,
                )?;
                validate_semantic_observation_pair(&request, &response)
                    .map_err(|_| invalid_transition())?;
                response.outcome
            }
        };
        if dependency_outcome(semantic_outcome) != outcome {
            return Err(invalid_transition());
        }
        Ok(())
    }
}

impl AutomaticWorldCoordinator {
    #[cfg(test)]
    fn new(sdk: Sdk, operation_id: OperationId) -> Result<Self, Error> {
        Self::new_with_registrations(sdk, operation_id, BTreeMap::new())
    }

    pub(crate) fn new_with_registrations(
        sdk: Sdk,
        operation_id: OperationId,
        registrations: BTreeMap<AutomaticObservationClass, AutomaticObservationRegistration>,
    ) -> Result<Self, Error> {
        let spool = tempfile::Builder::new()
            .prefix("reproit-automatic-world-")
            .tempdir()
            .map_err(local_storage_error)?;
        Ok(Self {
            artifacts: Vec::new(),
            dependency_interactions: Vec::new(),
            dropped_observation_count: 0,
            incomplete_session: false,
            #[cfg(unix)]
            next_internal_session: u64::MAX,
            observations: Vec::new(),
            operation_id,
            overflowed: false,
            registrations,
            reservation: crate::resources::LogicalByteReservation::new(),
            sdk,
            sessions: BTreeMap::new(),
            next_session_positions: BTreeMap::new(),
            spool,
        })
    }

    #[cfg(test)]
    fn register_observation_adapter(
        &mut self,
        class: AutomaticObservationClass,
        adapter_id: String,
        adapter_version: String,
        implementation_digest: Digest,
    ) -> Result<(), Error> {
        if !self.sessions.is_empty() || !self.observations.is_empty() {
            return Err(invalid_transition());
        }
        let registration = AutomaticObservationRegistration::new(
            class,
            adapter_id,
            adapter_version,
            implementation_digest,
        )?;
        if self.registrations.insert(class, registration).is_some() {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }

    pub(crate) fn bind_native_sentinel_coverage(&mut self, evidence: &[u8]) -> Result<(), Error> {
        if evidence.is_empty() || evidence.len() > MAX_NATIVE_SENTINEL_EVIDENCE_BYTES {
            self.incomplete_session = true;
            return Err(capture_limit());
        }
        let required_classes = AutomaticObservationClass::ALL
            .into_iter()
            .collect::<BTreeSet<_>>();
        let registered_classes = self.registrations.keys().copied().collect::<BTreeSet<_>>();
        if registered_classes != required_classes
            || self
                .registrations
                .values()
                .any(|registration| registration.sentinel_coverage_digest.is_some())
        {
            self.incomplete_session = true;
            return Err(world_not_closed());
        }
        for registration in self.registrations.values_mut() {
            registration.sentinel_coverage_digest = Some(sentinel_coverage_digest(
                &registration.ownership(),
                evidence,
            )?);
        }
        Ok(())
    }

    pub(crate) fn invalidate_ambient_context(&mut self) {
        self.incomplete_session = true;
    }

    pub(crate) fn open_observation(
        &mut self,
        session_id: u64,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
    ) -> Result<u64, Error> {
        self.open_observation_inner(session_id, class, causal_parent_id, true)
    }

    fn open_observation_inner(
        &mut self,
        session_id: u64,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
        semantic_contract: bool,
    ) -> Result<u64, Error> {
        if !self.registrations.contains_key(&class) {
            self.incomplete_session = true;
            return Err(world_not_closed());
        }
        if self.sessions.len() >= MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION
            || self.sessions.contains_key(&session_id)
        {
            self.incomplete_session = true;
            return Err(capture_limit());
        }
        let request_path = self
            .spool
            .path()
            .join(format!("session-{session_id}-request"));
        let response_path = self
            .spool
            .path()
            .join(format!("session-{session_id}-response"));
        fs::File::create(&request_path).map_err(local_storage_error)?;
        fs::File::create(&response_path).map_err(local_storage_error)?;
        let session_position = *self.next_session_positions.entry(class).or_default();
        let next_position = session_position
            .checked_add(1)
            .filter(|position| *position <= MAX_SESSION_POSITION)
            .ok_or_else(capture_limit)?;
        self.next_session_positions.insert(class, next_position);
        self.sessions.insert(
            session_id,
            ObservationSession {
                causal_parent_id,
                class,
                request_bytes: 0,
                request_path,
                response_bytes: 0,
                response_path,
                session_position,
                semantic_contract: semantic_contract.then(|| semantic_contract_for(class)),
                state: AutomaticObservationSessionState::Request,
            },
        );
        Ok(session_position)
    }

    pub(crate) fn write_observation(
        &mut self,
        session_id: u64,
        stream: AutomaticObservationStream,
        chunk: &[u8],
    ) -> Result<(), Error> {
        if chunk.is_empty() || chunk.len() > MAX_AUTOMATIC_OBSERVATION_CHUNK_BYTES {
            self.overflow_session(session_id);
            return Err(capture_limit());
        }
        let session = self.sessions.get(&session_id).ok_or_else(not_found)?;
        let valid_state = matches!(
            (session.state, stream),
            (
                AutomaticObservationSessionState::Request,
                AutomaticObservationStream::Request
            ) | (
                AutomaticObservationSessionState::Capture,
                AutomaticObservationStream::Response
            )
        );
        if !valid_state {
            self.overflow_session(session_id);
            return Err(invalid_transition());
        }
        let chunk_bytes = u64::try_from(chunk.len()).map_err(|_| capture_limit())?;
        let current_bytes = match stream {
            AutomaticObservationStream::Request => session.request_bytes,
            AutomaticObservationStream::Response => session.response_bytes,
        };
        let next_bytes = current_bytes
            .checked_add(chunk_bytes)
            .ok_or_else(capture_limit)?;
        if next_bytes > MAX_WORLD_ARTIFACT_BYTES || !self.reservation.reserve(chunk_bytes) {
            self.overflow_session(session_id);
            return Err(capture_limit());
        }
        let session = self.sessions.get_mut(&session_id).ok_or_else(not_found)?;
        let path = match stream {
            AutomaticObservationStream::Request => {
                session.request_bytes = next_bytes;
                &session.request_path
            }
            AutomaticObservationStream::Response => {
                session.response_bytes = next_bytes;
                &session.response_path
            }
        };
        append_chunk(path, chunk).inspect_err(|_| self.incomplete_session = true)
    }

    #[cfg(test)]
    fn write_observation_request(&mut self, session_id: u64, chunk: &[u8]) -> Result<(), Error> {
        self.write_observation(session_id, AutomaticObservationStream::Request, chunk)
    }

    #[cfg(test)]
    fn write_observation_response(&mut self, session_id: u64, chunk: &[u8]) -> Result<(), Error> {
        self.write_observation(session_id, AutomaticObservationStream::Response, chunk)
    }

    pub(crate) fn dispatch_observation(
        &mut self,
        session_id: u64,
    ) -> Result<AutomaticObservationAction, Error> {
        self.sessions
            .get(&session_id)
            .ok_or_else(not_found)?
            .validate_semantic_request()?;
        let session = self.sessions.get_mut(&session_id).ok_or_else(not_found)?;
        if session.state != AutomaticObservationSessionState::Request || session.request_bytes == 0
        {
            session.state = AutomaticObservationSessionState::Overflowed;
            self.incomplete_session = true;
            return Err(invalid_transition());
        }
        session.state = AutomaticObservationSessionState::Capture;
        Ok(AutomaticObservationAction::Capture)
    }

    pub(crate) fn read_observation_response(
        &mut self,
        session_id: u64,
    ) -> Result<(Vec<u8>, bool), Error> {
        let session = self.sessions.get_mut(&session_id).ok_or_else(not_found)?;
        let AutomaticObservationSessionState::Replay { response_offset } = &mut session.state
        else {
            return Err(invalid_transition());
        };
        let mut file = File::open(&session.response_path).map_err(local_storage_error)?;
        file.seek(std::io::SeekFrom::Start(*response_offset))
            .map_err(local_storage_error)?;
        let mut chunk = vec![0_u8; MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES];
        let count = file.read(&mut chunk).map_err(local_storage_error)?;
        chunk.truncate(count);
        *response_offset = response_offset
            .checked_add(u64::try_from(count).map_err(|_| capture_limit())?)
            .ok_or_else(capture_limit)?;
        Ok((chunk, *response_offset == session.response_bytes))
    }

    pub(crate) fn finish_observation(
        &mut self,
        session_id: u64,
        outcome: DependencyOutcome,
        session_position: u64,
    ) -> Result<(), Error> {
        let Some(session) = self.sessions.remove(&session_id) else {
            return Err(not_found());
        };
        let response_complete = match session.state {
            AutomaticObservationSessionState::Capture => true,
            AutomaticObservationSessionState::Replay { response_offset } => {
                response_offset == session.response_bytes
            }
            AutomaticObservationSessionState::Request
            | AutomaticObservationSessionState::Overflowed => false,
        };
        if !response_complete
            || session.request_bytes == 0
            || session.response_bytes == 0
            || session_position > MAX_SESSION_POSITION
        {
            self.incomplete_session = true;
            return Err(invalid_transition());
        }
        if session_position != session.session_position {
            self.incomplete_session = true;
            return Err(invalid_transition());
        }
        if let Err(error) = session.validate_semantic_pair(outcome) {
            self.incomplete_session = true;
            return Err(error);
        }
        if let Err(error) = self.commit_session(&session, outcome, session_position) {
            self.incomplete_session = true;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn abandon_observation(&mut self, session_id: u64) -> Result<(), Error> {
        self.sessions.remove(&session_id).ok_or_else(not_found)?;
        self.incomplete_session = true;
        Ok(())
    }

    #[cfg_attr(not(unix), allow(clippy::unused_self))]
    pub(crate) fn capture_ambient(&mut self) -> Result<(), Error> {
        #[cfg(not(unix))]
        {
            Err(Error::new(
                ErrorCode::Unsupported,
                "Automatic environment capture requires a supported production host.",
            ))
        }
        #[cfg(unix)]
        {
            let mut environment = BTreeMap::new();
            let mut environment_bytes = 0_usize;
            for (name, value) in std::env::vars_os() {
                let name = name.as_os_str().as_bytes();
                let value = value.as_os_str().as_bytes();
                let next_bytes = environment_bytes
                    .checked_add(name.len())
                    .and_then(|bytes| bytes.checked_add(value.len()));
                let Some(next_bytes) = next_bytes else {
                    self.overflowed = true;
                    self.dropped_observation_count =
                        self.dropped_observation_count.saturating_add(1);
                    return Err(capture_limit());
                };
                environment_bytes = next_bytes;
                if environment.len() >= MAX_AMBIENT_ENVIRONMENT_VALUES
                    || environment_bytes > MAX_AMBIENT_ENVIRONMENT_BYTES
                {
                    self.overflowed = true;
                    self.dropped_observation_count =
                        self.dropped_observation_count.saturating_add(1);
                    return Err(capture_limit());
                }
                environment.insert(encode_base64url(name), encode_base64url(value));
            }
            let environment_bytes = canonical::canonical_bytes(&environment)?;
            self.capture_internal(
                AutomaticObservationClass::Environment,
                b"process-environment",
                &environment_bytes,
            )?;
            let clock = timestamp(OffsetDateTime::now_utc())?;
            self.capture_internal(
                AutomaticObservationClass::Clock,
                b"wall-clock",
                clock.as_str().as_bytes(),
            )
        }
    }

    pub(crate) fn mark_unowned(
        &mut self,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
        evidence: &[u8],
    ) -> Result<(), Error> {
        if evidence.is_empty()
            || self.observations.len() >= MAX_EVENTS
            || evidence.len() as u64 > MAX_WORLD_ARTIFACT_BYTES
        {
            self.overflowed = true;
            self.dropped_observation_count = self.dropped_observation_count.saturating_add(1);
            return Err(capture_limit());
        }
        let evidence_bytes = u64::try_from(evidence.len()).map_err(|_| capture_limit())?;
        if !self.reservation.reserve(evidence_bytes) {
            self.overflowed = true;
            self.dropped_observation_count = self.dropped_observation_count.saturating_add(1);
            return Err(capture_limit());
        }
        let sequence = u16::try_from(self.observations.len()).map_err(|_| capture_limit())?;
        let digest = Digest::of(evidence);
        let path = self.spool.path().join(format!("unowned-{sequence}"));
        fs::write(&path, evidence).map_err(local_storage_error)?;
        let uri = format!("reproit-managed://automatic-unowned/{sequence}/{digest}");
        self.artifacts.push(ObservationArtifact {
            artifact: ManagedCandidateArtifact {
                media_type: OBSERVATION_OBJECT_MEDIA_TYPE.to_owned(),
                object_id: new_object_id()?,
                path,
                role: LogicalObjectRole::WorldState,
                uri: uri.clone(),
            },
            reference: Some(ArtifactReference {
                digest,
                media_type: OBSERVATION_OBJECT_MEDIA_TYPE.to_owned(),
                size: evidence_bytes,
                uri,
            }),
        });
        let observation = AutomaticObservationPayload {
            boundary_id: class.boundary_id().to_owned(),
            causal_parent_id,
            evidence_digest: digest,
            format: AutomaticObservationPayloadFormat::V1,
            observation_class: class,
            observation_sequence: sequence,
            operation_id: self.operation_id,
            owner_adapter_id: None,
        };
        self.sdk
            .record_observation(self.operation_id, &observation)?;
        self.observations.push(observation);
        Ok(())
    }

    pub(crate) fn close(
        mut self,
        completion: TriggerCompletion,
    ) -> Result<AutomaticWorldCapture, Error> {
        let registered_classes = self.registrations.keys().copied().collect::<BTreeSet<_>>();
        let sentinel_complete = self
            .registrations
            .values()
            .all(|registration| registration.sentinel_coverage_digest.is_some());
        if self.overflowed
            || self.incomplete_session
            || !self.sessions.is_empty()
            || self.dropped_observation_count != 0
            || self
                .observations
                .iter()
                .any(|observation| observation.owner_adapter_id.is_none())
            || registered_classes != AutomaticObservationClass::ALL.into_iter().collect()
            || !sentinel_complete
        {
            return Err(world_not_closed());
        }
        self.commit_dependency_transcript()?;
        let policy = closure_policy();
        let world_closure = self.world_closure(&policy)?;
        let world = self.world_checkpoint(&policy)?;
        let fence = self.fence(world_closure)?;
        let artifacts = self
            .artifacts
            .into_iter()
            .map(|artifact| artifact.artifact)
            .collect();
        Ok(AutomaticWorldCapture {
            closure: ManagedRustCaptureClosure {
                artifacts,
                completion,
                world,
            },
            fence,
            _reservation: self.reservation,
            _spool: self.spool,
        })
    }

    #[cfg(unix)]
    fn capture_internal(
        &mut self,
        class: AutomaticObservationClass,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), Error> {
        let session_id = self.next_internal_session;
        self.next_internal_session = self
            .next_internal_session
            .checked_sub(1)
            .ok_or_else(capture_limit)?;
        let session_position = self.open_observation_inner(session_id, class, None, false)?;
        self.write_observation(session_id, AutomaticObservationStream::Request, request)?;
        self.dispatch_observation(session_id)?;
        self.write_observation(session_id, AutomaticObservationStream::Response, response)?;
        self.finish_observation(session_id, DependencyOutcome::Response, session_position)
    }

    fn world_checkpoint(&self, policy: &ClosurePolicy) -> Result<WorldCheckpoint, Error> {
        let published_at = timestamp(OffsetDateTime::now_utc())?;
        let recoverable_until = timestamp(
            OffsetDateTime::now_utc() + time::Duration::seconds(MAX_RECOVERABLE_SECONDS),
        )?;
        let references = self
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.reference.clone())
            .collect::<Vec<_>>();
        let total_bytes = references.iter().try_fold(0_u64, |total, reference| {
            total.checked_add(reference.size).ok_or_else(capture_limit)
        })?;
        if total_bytes > MAX_WORLD_BYTES {
            return Err(capture_limit());
        }
        let configuration_digest = canonical::digest(policy)?;
        let point = RecoverablePoint {
            artifacts: references,
            capabilities: vec![CAPABILITY.to_owned()],
            configuration_digest,
            engine_identity: ADAPTER_ID.to_owned(),
            engine_version: ADAPTER_VERSION.to_owned(),
            format: RecoverablePointFormat::V1,
            generation: 1,
            point: encode_base64url(configuration_digest.as_bytes()),
            provider_id: "automatic-world".to_owned(),
            published_at: published_at.clone(),
            recoverable_until,
            resource_claim: ProviderResourceClaim {
                materialized_bytes: total_bytes,
                objects: u64::try_from(
                    self.artifacts
                        .iter()
                        .filter(|artifact| artifact.reference.is_some())
                        .count(),
                )
                .map_err(|_| capture_limit())?,
                pinned_bytes: total_bytes,
                temporary_bytes: total_bytes,
            },
            scope: CheckpointScope {
                kind: CheckpointScopeKind::Full,
                rules: Vec::new(),
            },
        };
        let world = WorldCheckpoint {
            created_at: published_at,
            format: WorldCheckpointFormat::V1,
            points: vec![point],
        };
        world.validate()?;
        Ok(world)
    }

    fn world_closure(&self, policy: &ClosurePolicy) -> Result<WorldClosure, Error> {
        let mut digests = self
            .registrations
            .iter()
            .map(|(class, registration)| {
                registration
                    .sentinel_coverage_digest
                    .map(|digest| (*class, vec![digest]))
                    .ok_or_else(world_not_closed)
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;
        for observation in &self.observations {
            digests
                .entry(observation.observation_class)
                .or_default()
                .push(observation.evidence_digest);
        }
        let receipts = AutomaticObservationClass::ALL
            .into_iter()
            .map(|class| {
                let evidence = digests.get(&class).map_or(&[][..], Vec::as_slice);
                Ok(ClosureReceipt {
                    boundary_id: class.boundary_id().to_owned(),
                    evidence_digest: canonical::digest(&evidence)?,
                    mechanism: class.closure_mechanism(),
                    observation_class: class.closure_class(),
                    version: 1,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let closure = WorldClosure {
            format: WorldClosureFormat::V1,
            policy_digest: canonical::digest(policy)?,
            receipts,
        };
        closure.validate()?;
        Ok(closure)
    }

    fn fence(&self, world_closure: WorldClosure) -> Result<NativeObservationFenceReceipt, Error> {
        Ok(NativeObservationFenceReceipt {
            adapter_ownership: adapter_ownership(&self.registrations),
            deployment_digest: Digest::of(b"pending automatic deployment"),
            dropped_observation_count: self.dropped_observation_count,
            fence_id: FENCE_ID.to_owned(),
            fence_version: ADAPTER_VERSION.to_owned(),
            format: NativeObservationFenceReceiptFormat::V1,
            observation_count: u16::try_from(self.observations.len())
                .map_err(|_| capture_limit())?,
            observations_digest: canonical::digest(&self.observations)?,
            operation_id: self.operation_id,
            overflowed: self.overflowed,
            signature: encode_base64url(&[0_u8; 64]),
            signer_key_id: "pending-managed-registration".to_owned(),
            subject_digest: Digest::of(b"pending automatic subject"),
            unowned_observation_count: 0,
            world_closure,
        })
    }

    fn overflow_session(&mut self, session_id: u64) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.state = AutomaticObservationSessionState::Overflowed;
        }
        self.incomplete_session = true;
        self.overflowed = true;
        self.dropped_observation_count = self.dropped_observation_count.saturating_add(1);
    }
}

fn append_chunk(path: &Path, chunk: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(local_storage_error)?;
    file.write_all(chunk).map_err(local_storage_error)?;
    file.flush().map_err(local_storage_error)
}

fn semantic_contract_for(class: AutomaticObservationClass) -> SemanticContract {
    match class {
        AutomaticObservationClass::Database
        | AutomaticObservationClass::OutboundHttp
        | AutomaticObservationClass::Queue => SemanticContract::Dependency,
        AutomaticObservationClass::Clock
        | AutomaticObservationClass::Environment
        | AutomaticObservationClass::Filesystem
        | AutomaticObservationClass::Randomness => SemanticContract::ProcessObservation,
    }
}

fn observation_class(operation: SemanticObservationOperation) -> AutomaticObservationClass {
    match operation {
        SemanticObservationOperation::ClockWallTime => AutomaticObservationClass::Clock,
        SemanticObservationOperation::EnvironmentRead => AutomaticObservationClass::Environment,
        SemanticObservationOperation::FilesystemRead => AutomaticObservationClass::Filesystem,
        SemanticObservationOperation::RandomBytes => AutomaticObservationClass::Randomness,
    }
}

fn dependency_outcome(outcome: SemanticObservationOutcome) -> DependencyOutcome {
    match outcome {
        SemanticObservationOutcome::Error => DependencyOutcome::Error,
        SemanticObservationOutcome::Response => DependencyOutcome::Response,
    }
}

fn read_semantic_record<T>(path: &Path, declared_bytes: u64) -> Result<T, Error>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + reproit_core::model::Validate,
{
    if declared_bytes == 0 || declared_bytes > MAX_SEMANTIC_RECORD_BYTES {
        return Err(invalid_transition());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(declared_bytes).unwrap_or_default());
    File::open(path)
        .map_err(local_storage_error)?
        .take(MAX_SEMANTIC_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(local_storage_error)?;
    if u64::try_from(bytes.len()).ok() != Some(declared_bytes) {
        return Err(invalid_transition());
    }
    let record: T = canonical::parse_strict(&bytes).map_err(|_| invalid_transition())?;
    record.validate().map_err(|_| invalid_transition())?;
    let canonical = canonical::canonical_bytes(&record).map_err(|_| invalid_transition())?;
    if canonical != bytes {
        return Err(invalid_transition());
    }
    Ok(record)
}

fn adapter_ownership(
    registrations: &BTreeMap<AutomaticObservationClass, AutomaticObservationRegistration>,
) -> Vec<SemanticAdapterOwnership> {
    registrations
        .values()
        .map(AutomaticObservationRegistration::ownership)
        .collect()
}

fn sentinel_coverage_digest(
    ownership: &SemanticAdapterOwnership,
    evidence: &[u8],
) -> Result<Digest, Error> {
    const DOMAIN: &[u8] = b"reproit.native-sentinel-coverage.v1\0";

    let ownership = canonical::canonical_bytes(ownership)?;
    let ownership_bytes = u64::try_from(ownership.len()).map_err(|_| capture_limit())?;
    let evidence_bytes = u64::try_from(evidence.len()).map_err(|_| capture_limit())?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(ownership_bytes.to_be_bytes());
    hasher.update(&ownership);
    hasher.update(evidence_bytes.to_be_bytes());
    hasher.update(evidence);
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn closure_policy() -> ClosurePolicy {
    ClosurePolicy {
        format: ClosurePolicyFormat::V1,
        rules: AutomaticObservationClass::ALL
            .into_iter()
            .map(|class| ClosureRule {
                allowed_mechanisms: vec![class.closure_mechanism()],
                boundary_id: class.boundary_id().to_owned(),
                observation_class: class.closure_class(),
            })
            .collect(),
    }
}

fn timestamp(value: OffsetDateTime) -> Result<Timestamp, Error> {
    let month = u8::from(value.month());
    format!(
        "{:04}-{month:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.millisecond(),
    )
    .parse()
}

fn new_object_id() -> Result<ObjectId, Error> {
    format!("obj_{}", Uuid::now_v7()).parse()
}

fn capture_limit() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The automatic World capture limit was reached.",
    )
}

fn invalid_transition() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The automatic observation session transition is invalid.",
    )
}

fn local_storage_error(_error: std::io::Error) -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Repro It could not store the automatic World locally.",
    )
}

fn not_found() -> Error {
    Error::new(
        ErrorCode::NotFound,
        "The automatic observation session does not exist.",
    )
}

fn world_not_closed() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "Repro It could not own every automatic application observation.",
    )
}

#[cfg(test)]
#[path = "../tests/support/automatic_world_internal.rs"]
mod tests;
