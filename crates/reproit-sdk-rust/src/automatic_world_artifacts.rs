use std::{
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
};

use reproit_core::{
    Error, canonical,
    crypto::encode_base64url,
    identity::{Digest, ObjectId},
    model::{
        ArtifactReference, AutomaticObservationClass, AutomaticObservationPayload,
        AutomaticObservationPayloadFormat, DependencyCursorFormat, DependencyCursorPayload,
        DependencyOutcome, DependencyTranscript, DependencyTranscriptFormat,
        DependencyTranscriptInteraction, LogicalObjectRole, Validate as _,
    },
};
use sha2::{Digest as _, Sha256};

use crate::{MAX_EVENTS, ManagedCandidateArtifact};

use super::{
    ADAPTER_ID, ADAPTER_VERSION, AutomaticWorldCoordinator, DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
    OBSERVATION_OBJECT_MEDIA_TYPE, ObservationArtifact, ObservationSession, capture_limit,
    local_storage_error, new_object_id, world_not_closed,
};

impl AutomaticWorldCoordinator {
    pub(super) fn commit_session(
        &mut self,
        session: &ObservationSession,
        outcome: DependencyOutcome,
        session_position: u64,
    ) -> Result<(), Error> {
        if self.observations.len() >= MAX_EVENTS {
            return Err(capture_limit());
        }
        let request_digest = digest_file(&session.request_path, session.request_bytes)?;
        let response_digest = digest_file(&session.response_path, session.response_bytes)?;
        let evidence_digest = if is_dependency_class(session.class) {
            self.commit_dependency_interaction(
                session,
                outcome,
                session_position,
                request_digest,
                response_digest,
            )?
        } else {
            self.commit_state_artifact(
                session.class,
                outcome,
                session_position,
                request_digest,
                response_digest,
                session.response_bytes,
                session.response_path.clone(),
            )?
        };
        let observation_sequence =
            u16::try_from(self.observations.len()).map_err(|_| capture_limit())?;
        let owner_adapter_id = self
            .registrations
            .get(&session.class)
            .ok_or_else(world_not_closed)?
            .adapter_id
            .clone();
        let observation = AutomaticObservationPayload {
            boundary_id: session.class.boundary_id().to_owned(),
            causal_parent_id: session.causal_parent_id,
            evidence_digest,
            format: AutomaticObservationPayloadFormat::V1,
            observation_class: session.class,
            observation_sequence,
            operation_id: self.operation_id,
            owner_adapter_id: Some(owner_adapter_id),
        };
        self.sdk
            .record_observation(self.operation_id, &observation)?;
        self.observations.push(observation);
        Ok(())
    }

    fn commit_dependency_interaction(
        &mut self,
        session: &ObservationSession,
        outcome: DependencyOutcome,
        session_position: u64,
        request_digest: Digest,
        response_digest: Digest,
    ) -> Result<Digest, Error> {
        let request_object_id = new_object_id()?;
        let response_object_id = new_object_id()?;
        let interaction = DependencyTranscriptInteraction {
            causal_parent_id: session.causal_parent_id,
            operation_id: self.operation_id,
            outcome,
            request_digest,
            request_object_id,
            response_digest,
            response_object_id,
            sequence: u16::try_from(self.dependency_interactions.len())
                .map_err(|_| capture_limit())?,
            session_position,
        };
        let uri = format!(
            "reproit-managed://automatic-dependency/{}/{}",
            session.class.boundary_id(),
            request_digest
        );
        self.artifacts.push(raw_dependency_artifact(
            request_object_id,
            session.request_path.clone(),
            format!("{uri}/request"),
        ));
        self.artifacts.push(raw_dependency_artifact(
            response_object_id,
            session.response_path.clone(),
            format!("{uri}/response"),
        ));
        let evidence_digest = canonical::digest(&interaction)?;
        self.dependency_interactions.push(interaction);
        Ok(evidence_digest)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_state_artifact(
        &mut self,
        class: AutomaticObservationClass,
        outcome: DependencyOutcome,
        session_position: u64,
        request_digest: Digest,
        response_digest: Digest,
        response_size: u64,
        response_path: PathBuf,
    ) -> Result<Digest, Error> {
        let outcome = match outcome {
            DependencyOutcome::Error => "error",
            DependencyOutcome::Response => "response",
        };
        let uri = format!(
            "reproit-managed://automatic-world/{}/{}/{session_position}/{outcome}",
            class.boundary_id(),
            request_digest
        );
        let reference = ArtifactReference {
            digest: response_digest,
            media_type: OBSERVATION_OBJECT_MEDIA_TYPE.to_owned(),
            size: response_size,
            uri: uri.clone(),
        };
        let evidence_digest = canonical::digest(&reference)?;
        self.artifacts.push(ObservationArtifact {
            artifact: ManagedCandidateArtifact {
                media_type: OBSERVATION_OBJECT_MEDIA_TYPE.to_owned(),
                object_id: new_object_id()?,
                path: response_path,
                role: LogicalObjectRole::WorldState,
                uri,
            },
            reference: Some(reference),
        });
        Ok(evidence_digest)
    }

    pub(super) fn commit_dependency_transcript(&mut self) -> Result<(), Error> {
        if self.dependency_interactions.is_empty() {
            return Ok(());
        }
        let transcript = DependencyTranscript {
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: ADAPTER_VERSION.to_owned(),
            format: DependencyTranscriptFormat::V1,
            interactions: self.dependency_interactions.clone(),
        };
        transcript.validate()?;
        let bytes = canonical::canonical_bytes(&transcript)?;
        let digest = Digest::of(&bytes);
        if !self
            .reservation
            .reserve(u64::try_from(bytes.len()).map_err(|_| capture_limit())?)
        {
            return Err(capture_limit());
        }
        let path = self.spool.path().join("dependency-transcript.json");
        fs::write(&path, &bytes).map_err(local_storage_error)?;
        let cursor_bytes = *digest.as_bytes();
        let cursor = encode_base64url(&cursor_bytes);
        let payload = DependencyCursorPayload {
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: ADAPTER_VERSION.to_owned(),
            causal_parent_id: None,
            cursor,
            cursor_digest: Digest::of(&cursor_bytes),
            format: DependencyCursorFormat::V1,
        };
        payload.validate()?;
        self.sdk.record_dependency(self.operation_id, &payload)?;
        self.artifacts.push(ObservationArtifact {
            artifact: ManagedCandidateArtifact {
                media_type: DEPENDENCY_TRANSCRIPT_MEDIA_TYPE.to_owned(),
                object_id: new_object_id()?,
                path,
                role: LogicalObjectRole::DependencyTranscript,
                uri: format!("reproit-managed://automatic-dependency/transcript/{digest}"),
            },
            reference: None,
        });
        Ok(())
    }
}

fn digest_file(path: &Path, expected_bytes: u64) -> Result<Digest, Error> {
    const BUFFER_BYTES: usize = 64 * 1_024;

    let mut file = File::open(path).map_err(local_storage_error)?;
    let mut buffer = vec![0_u8; BUFFER_BYTES].into_boxed_slice();
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(local_storage_error)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| capture_limit())?)
            .ok_or_else(capture_limit)?;
        if total > expected_bytes {
            return Err(world_not_closed());
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_bytes {
        return Err(world_not_closed());
    }
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn raw_dependency_artifact(object_id: ObjectId, path: PathBuf, uri: String) -> ObservationArtifact {
    ObservationArtifact {
        artifact: ManagedCandidateArtifact {
            media_type: OBSERVATION_OBJECT_MEDIA_TYPE.to_owned(),
            object_id,
            path,
            role: LogicalObjectRole::DependencyTranscript,
            uri,
        },
        reference: None,
    }
}

const fn is_dependency_class(class: AutomaticObservationClass) -> bool {
    matches!(
        class,
        AutomaticObservationClass::Clock
            | AutomaticObservationClass::Database
            | AutomaticObservationClass::OutboundHttp
            | AutomaticObservationClass::Queue
            | AutomaticObservationClass::Randomness
    )
}
