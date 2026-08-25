use reproit_core::{
    Error, ErrorCode, canonical,
    model::{
        AutomaticObservationClass, DependencyOutcome, MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
        SemanticDependencyMetadata, SemanticDependencyOperation, SemanticDependencyRequest,
        SemanticDependencyRequestFormat, SemanticDependencyResponse,
        SemanticDependencyResponseFormat, SemanticObservationErrorCode, SemanticObservationOutcome,
        Validate, validate_semantic_dependency_pair,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{Registry, not_found, observation::ObservationStreamInput, sentinel};
use reproit_core::identity::OperationId;
use reproit_sdk_rust::AutomaticManagedOperation;

pub(super) struct SemanticDependencySession {
    action: Option<DependencyAction>,
    canonical_session_position: Option<u64>,
    class: AutomaticObservationClass,
    request: Vec<u8>,
    response: Vec<u8>,
    validated_request: Option<SemanticDependencyRequest>,
    validated_response: Option<SemanticDependencyResponse>,
}

impl SemanticDependencySession {
    pub(super) fn for_class(class: AutomaticObservationClass) -> Option<Self> {
        matches!(
            class,
            AutomaticObservationClass::Database
                | AutomaticObservationClass::OutboundHttp
                | AutomaticObservationClass::Queue
        )
        .then(|| Self {
            action: None,
            canonical_session_position: None,
            class,
            request: Vec::new(),
            response: Vec::new(),
            validated_request: None,
            validated_response: None,
        })
    }

    pub(super) fn bind_action(&mut self, action: &str) -> Result<(), Error> {
        let action = match action {
            "capture" => DependencyAction::Capture,
            "replay" => DependencyAction::Replay,
            _ => return Err(invalid_dependency()),
        };
        if self.action.replace(action).is_some() {
            return Err(invalid_dependency());
        }
        Ok(())
    }

    pub(super) fn validate_finish_input(&self, has_response: bool) -> Result<(), Error> {
        if !matches!(
            (self.action, has_response),
            (Some(DependencyAction::Capture), true) | (Some(DependencyAction::Replay), false)
        ) {
            return Err(invalid_dependency());
        }
        Ok(())
    }

    pub(super) fn canonical_request(
        input: SemanticDependencyRequestInput,
    ) -> Result<Vec<u8>, Error> {
        let request = input.into_request();
        request.validate().map_err(|_| invalid_dependency())?;
        canonical::canonical_bytes(&request).map_err(|_| invalid_dependency())
    }

    pub(super) fn bind_canonical_session_position(
        &mut self,
        session_position: u64,
    ) -> Result<(), Error> {
        if self
            .canonical_session_position
            .replace(session_position)
            .is_some()
        {
            return Err(invalid_dependency());
        }
        Ok(())
    }

    pub(super) fn canonical_session_position(&self) -> Result<u64, Error> {
        self.canonical_session_position
            .ok_or_else(invalid_dependency)
    }

    pub(super) fn canonical_response(
        &self,
        input: SemanticDependencyResponseInput,
    ) -> Result<(Vec<u8>, SemanticDependencyResponse), Error> {
        let request = self
            .validated_request
            .as_ref()
            .ok_or_else(invalid_dependency)?;
        let response = input.into_response(request)?;
        validate_semantic_dependency_pair(request, &response).map_err(|_| invalid_dependency())?;
        let bytes = canonical::canonical_bytes(&response).map_err(|_| invalid_dependency())?;
        Ok((bytes, response))
    }

    pub(super) fn cache_validated_response(
        &mut self,
        response: SemanticDependencyResponse,
    ) -> Result<(), Error> {
        if self.validated_response.replace(response).is_some() {
            return Err(invalid_dependency());
        }
        Ok(())
    }

    pub(super) fn write(
        &mut self,
        stream: ObservationStreamInput,
        chunk: &[u8],
    ) -> Result<(), Error> {
        let destination = match (stream, self.validated_request.is_some()) {
            (ObservationStreamInput::Request, false) => &mut self.request,
            (ObservationStreamInput::Response, true) => &mut self.response,
            _ => return Err(invalid_dependency()),
        };
        if matches!(stream, ObservationStreamInput::Response) {
            self.validated_response = None;
        }
        let new_length = destination
            .len()
            .checked_add(chunk.len())
            .ok_or_else(dependency_limit)?;
        if new_length > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES {
            return Err(dependency_limit());
        }
        destination.extend_from_slice(chunk);
        Ok(())
    }

    pub(super) fn dispatch(&mut self) -> Result<(), Error> {
        if self.validated_request.is_some() || !self.response.is_empty() {
            return Err(invalid_dependency());
        }
        let request = parse_canonical::<SemanticDependencyRequest>(&self.request)?;
        if request.observation_class != self.class {
            return Err(invalid_dependency());
        }
        self.validated_request = Some(request);
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        outcome: DependencyOutcome,
    ) -> Result<SemanticDependencyResponse, Error> {
        let response = self.validated_response()?;
        if dependency_outcome(response.outcome) != outcome {
            return Err(invalid_dependency());
        }
        Ok(response)
    }

    pub(super) fn validated_response(&mut self) -> Result<SemanticDependencyResponse, Error> {
        if let Some(response) = self.validated_response.as_ref() {
            return Ok(response.clone());
        }
        let request = self
            .validated_request
            .as_ref()
            .ok_or_else(invalid_dependency)?;
        let response = parse_canonical::<SemanticDependencyResponse>(&self.response)?;
        validate_semantic_dependency_pair(request, &response).map_err(|_| invalid_dependency())?;
        self.validated_response = Some(response.clone());
        Ok(response)
    }
}

#[derive(Clone, Copy)]
enum DependencyAction {
    Capture,
    Replay,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticDependencyRequestInput {
    encoding: String,
    metadata: Vec<SemanticDependencyMetadata>,
    method: Option<String>,
    observation_class: AutomaticObservationClass,
    operation: SemanticDependencyOperation,
    payload: String,
    protocol: String,
    target: String,
}

impl SemanticDependencyRequestInput {
    fn into_request(self) -> SemanticDependencyRequest {
        SemanticDependencyRequest {
            encoding: self.encoding,
            format: SemanticDependencyRequestFormat::V1,
            metadata: self.metadata,
            method: self.method,
            observation_class: self.observation_class,
            operation: self.operation,
            payload: self.payload,
            protocol: self.protocol,
            target: self.target,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticDependencyResponseInput {
    error_code: Option<SemanticObservationErrorCode>,
    error_number: Option<u32>,
    metadata: Vec<SemanticDependencyMetadata>,
    outcome: SemanticObservationOutcome,
    payload: Option<String>,
    status: Option<String>,
    status_code: Option<u16>,
}

impl SemanticDependencyResponseInput {
    fn into_response(
        self,
        request: &SemanticDependencyRequest,
    ) -> Result<SemanticDependencyResponse, Error> {
        Ok(SemanticDependencyResponse {
            error_code: self.error_code,
            error_number: self.error_number,
            format: SemanticDependencyResponseFormat::V1,
            metadata: self.metadata,
            observation_class: request.observation_class,
            operation: request.operation,
            outcome: self.outcome,
            payload: self.payload,
            request_digest: canonical::digest(request).map_err(|_| invalid_dependency())?,
            status: self.status,
            status_code: self.status_code,
        })
    }
}

pub(super) fn dependency_outcome(outcome: SemanticObservationOutcome) -> DependencyOutcome {
    match outcome {
        SemanticObservationOutcome::Error => DependencyOutcome::Error,
        SemanticObservationOutcome::Response => DependencyOutcome::Response,
    }
}

impl Registry {
    pub(super) fn open_dependency(
        &mut self,
        operation_handle: u64,
        causal_parent_id: Option<OperationId>,
        request: SemanticDependencyRequestInput,
    ) -> Result<Value, Error> {
        let class = request.observation_class;
        let request_bytes = SemanticDependencySession::canonical_request(request)?;
        let opened = self.open_observation(operation_handle, class, causal_parent_id)?;
        let dependency_handle = opened
            .get("observation_handle")
            .and_then(Value::as_u64)
            .ok_or_else(Error::schema_invalid)?;
        let session_position = opened
            .get("session_position")
            .and_then(Value::as_u64)
            .ok_or_else(Error::schema_invalid)?;
        sentinel::observation_opened(dependency_handle, operation_handle, class);
        let bind_result = self
            .observations
            .get_mut(&dependency_handle)
            .ok_or_else(not_found)?
            .semantic_dependency
            .as_mut()
            .ok_or_else(invalid_dependency)?
            .bind_canonical_session_position(session_position);
        if let Err(error) = bind_result {
            self.cleanup_dependency(dependency_handle);
            return Err(error);
        }
        if let Err(error) = self.write_dependency_record(
            dependency_handle,
            ObservationStreamInput::Request,
            &request_bytes,
        ) {
            self.cleanup_dependency(dependency_handle);
            return Err(error);
        }
        let dispatched = match self.dispatch_observation(dependency_handle) {
            Ok(dispatched) => dispatched,
            Err(error) => {
                self.cleanup_dependency(dependency_handle);
                return Err(error);
            }
        };
        sentinel::observation_dispatched(dependency_handle);
        let Some(action) = dispatched.get("action").and_then(Value::as_str) else {
            self.cleanup_dependency(dependency_handle);
            return Err(Error::schema_invalid());
        };
        let bind_action = self
            .observations
            .get_mut(&dependency_handle)
            .ok_or_else(not_found)?
            .semantic_dependency
            .as_mut()
            .ok_or_else(invalid_dependency)?
            .bind_action(action);
        if let Err(error) = bind_action {
            self.cleanup_dependency(dependency_handle);
            return Err(error);
        }
        Ok(json!({
            "action": action,
            "dependency_handle": dependency_handle,
        }))
    }

    pub(super) fn finish_dependency(
        &mut self,
        dependency_handle: u64,
        response: Option<SemanticDependencyResponseInput>,
    ) -> Result<Value, Error> {
        let Some(entry) = self.observations.get(&dependency_handle) else {
            return Err(not_found());
        };
        let session_position = entry
            .semantic_dependency
            .as_ref()
            .ok_or_else(invalid_dependency)
            .and_then(SemanticDependencySession::canonical_session_position);
        let session_position = match session_position {
            Ok(session_position) => session_position,
            Err(error) => {
                self.cleanup_dependency(dependency_handle);
                return Err(error);
            }
        };
        let finish_input = self
            .observations
            .get(&dependency_handle)
            .ok_or_else(not_found)?
            .semantic_dependency
            .as_ref()
            .ok_or_else(invalid_dependency)?
            .validate_finish_input(response.is_some());
        if let Err(error) = finish_input {
            self.cleanup_dependency(dependency_handle);
            return Err(error);
        }
        if let Some(response) = response {
            let response = self
                .observations
                .get(&dependency_handle)
                .ok_or_else(not_found)?
                .semantic_dependency
                .as_ref()
                .ok_or_else(invalid_dependency)?
                .canonical_response(response);
            let (response_bytes, validated_response) = match response {
                Ok(response) => response,
                Err(error) => {
                    self.cleanup_dependency(dependency_handle);
                    return Err(error);
                }
            };
            if let Err(error) = self.write_dependency_record(
                dependency_handle,
                ObservationStreamInput::Response,
                &response_bytes,
            ) {
                self.cleanup_dependency(dependency_handle);
                return Err(error);
            }
            let cached = self
                .observations
                .get_mut(&dependency_handle)
                .ok_or_else(not_found)?
                .semantic_dependency
                .as_mut()
                .ok_or_else(invalid_dependency)?
                .cache_validated_response(validated_response);
            if let Err(error) = cached {
                self.cleanup_dependency(dependency_handle);
                return Err(error);
            }
        }
        let response = self
            .observations
            .get_mut(&dependency_handle)
            .ok_or_else(not_found)?
            .semantic_dependency
            .as_mut()
            .ok_or_else(invalid_dependency)?
            .validated_response();
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.cleanup_dependency(dependency_handle);
                return Err(error);
            }
        };
        let outcome = dependency_outcome(response.outcome);
        let finished =
            match self.finish_observation_inner(dependency_handle, outcome, session_position) {
                Ok(finished) => finished,
                Err(error) => {
                    self.cleanup_dependency(dependency_handle);
                    return Err(error);
                }
            };
        if finished.is_none() {
            self.cleanup_dependency(dependency_handle);
            return Err(invalid_dependency());
        }
        sentinel::observation_finished(dependency_handle);
        Ok(json!({ "outcome": response.outcome }))
    }

    fn cleanup_dependency(&mut self, dependency_handle: u64) {
        sentinel::observation_finished(dependency_handle);
        self.invalidate_semantic_observation(dependency_handle);
    }

    fn write_dependency_record(
        &mut self,
        dependency_handle: u64,
        stream: ObservationStreamInput,
        record: &[u8],
    ) -> Result<(), Error> {
        for chunk in record.chunks(AutomaticManagedOperation::MAX_OBSERVATION_CHUNK_BYTES) {
            self.write_observation_bytes(dependency_handle, stream, chunk)?;
        }
        Ok(())
    }
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: DeserializeOwned + Serialize + Validate,
{
    if bytes.is_empty() || bytes.len() > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES {
        return Err(invalid_dependency());
    }
    let value: T = canonical::parse_strict(bytes).map_err(|_| invalid_dependency())?;
    value.validate().map_err(|_| invalid_dependency())?;
    let canonical_bytes = canonical::canonical_bytes(&value).map_err(|_| invalid_dependency())?;
    if canonical_bytes != bytes {
        return Err(invalid_dependency());
    }
    Ok(value)
}

fn invalid_dependency() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The semantic dependency observation is invalid.",
    )
}

fn dependency_limit() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The semantic dependency record limit was reached.",
    )
}

#[cfg(test)]
mod tests {
    use reproit_core::{
        crypto::encode_base64url,
        model::{SemanticDependencyOperation, SemanticDependencyResponseFormat},
    };

    use super::*;

    fn request(class: AutomaticObservationClass) -> SemanticDependencyRequest {
        request_input(class).into_request()
    }

    fn request_input(class: AutomaticObservationClass) -> SemanticDependencyRequestInput {
        let (operation, method) = match class {
            AutomaticObservationClass::Database => {
                (SemanticDependencyOperation::DatabaseExecute, None)
            }
            AutomaticObservationClass::OutboundHttp => (
                SemanticDependencyOperation::OutboundHttpRequest,
                Some("POST".to_owned()),
            ),
            AutomaticObservationClass::Queue => (SemanticDependencyOperation::QueuePublish, None),
            _ => unreachable!(),
        };
        SemanticDependencyRequestInput {
            encoding: "canonical-json".to_owned(),
            metadata: Vec::new(),
            method,
            observation_class: class,
            operation,
            payload: encode_base64url(b"request"),
            protocol: "test-protocol".to_owned(),
            target: encode_base64url(b"test-target"),
        }
    }

    fn response(request: &SemanticDependencyRequest) -> SemanticDependencyResponse {
        SemanticDependencyResponse {
            error_code: None,
            error_number: None,
            format: SemanticDependencyResponseFormat::V1,
            metadata: Vec::new(),
            observation_class: request.observation_class,
            operation: request.operation,
            outcome: SemanticObservationOutcome::Response,
            payload: Some(encode_base64url(b"response")),
            request_digest: canonical::digest(request).unwrap(),
            status: None,
            status_code: (request.observation_class == AutomaticObservationClass::OutboundHttp)
                .then_some(200),
        }
    }

    fn response_input() -> SemanticDependencyResponseInput {
        SemanticDependencyResponseInput {
            error_code: None,
            error_number: None,
            metadata: Vec::new(),
            outcome: SemanticObservationOutcome::Response,
            payload: Some(encode_base64url(b"response")),
            status: None,
            status_code: None,
        }
    }

    fn complete_session(class: AutomaticObservationClass) -> SemanticDependencySession {
        let request = request(class);
        let request_bytes = canonical::canonical_bytes(&request).unwrap();
        let response_bytes = canonical::canonical_bytes(&response(&request)).unwrap();
        let mut session = SemanticDependencySession::for_class(class).unwrap();
        session
            .write(ObservationStreamInput::Request, &request_bytes)
            .unwrap();
        session.dispatch().unwrap();
        session
            .write(ObservationStreamInput::Response, &response_bytes)
            .unwrap();
        session
    }

    fn replay_session(
        class: AutomaticObservationClass,
        response_bytes: &[u8],
    ) -> SemanticDependencySession {
        let request = request(class);
        let request_bytes = canonical::canonical_bytes(&request).unwrap();
        let mut session = SemanticDependencySession::for_class(class).unwrap();
        session
            .write(ObservationStreamInput::Request, &request_bytes)
            .unwrap();
        session.dispatch().unwrap();
        for chunk in response_bytes.chunks(7) {
            session
                .write(ObservationStreamInput::Response, chunk)
                .unwrap();
        }
        session
    }

    #[test]
    fn validates_all_owned_dependency_classes() {
        for class in [
            AutomaticObservationClass::Database,
            AutomaticObservationClass::OutboundHttp,
            AutomaticObservationClass::Queue,
        ] {
            complete_session(class)
                .finish(DependencyOutcome::Response)
                .unwrap();
        }
    }

    #[test]
    fn compact_capture_constructs_derived_core_fields() {
        for class in [
            AutomaticObservationClass::Database,
            AutomaticObservationClass::OutboundHttp,
            AutomaticObservationClass::Queue,
        ] {
            let request_bytes =
                SemanticDependencySession::canonical_request(request_input(class)).unwrap();
            let mut session = SemanticDependencySession::for_class(class).unwrap();
            session.bind_canonical_session_position(7).unwrap();
            session
                .write(ObservationStreamInput::Request, &request_bytes)
                .unwrap();
            session.dispatch().unwrap();
            let mut input = response_input();
            input.status_code = (class == AutomaticObservationClass::OutboundHttp).then_some(200);
            let (response_bytes, response) = session.canonical_response(input).unwrap();
            session
                .write(ObservationStreamInput::Response, &response_bytes)
                .unwrap();
            session.cache_validated_response(response).unwrap();

            let response = session.finish(DependencyOutcome::Response).unwrap();
            assert_eq!(response.observation_class, class);
            assert_eq!(session.canonical_session_position().unwrap(), 7);
        }
    }

    #[test]
    fn compact_error_response_preserves_bounded_payload_and_request_identity() {
        let request_bytes = SemanticDependencySession::canonical_request(request_input(
            AutomaticObservationClass::Database,
        ))
        .unwrap();
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        session
            .write(ObservationStreamInput::Request, &request_bytes)
            .unwrap();
        session.dispatch().unwrap();
        let input = SemanticDependencyResponseInput {
            error_code: Some(SemanticObservationErrorCode::NotFound),
            error_number: Some(2),
            metadata: Vec::new(),
            outcome: SemanticObservationOutcome::Error,
            payload: Some(encode_base64url(br#"{"kind":"missing-row"}"#)),
            status: None,
            status_code: None,
        };
        let (response_bytes, response) = session.canonical_response(input).unwrap();
        session
            .write(ObservationStreamInput::Response, &response_bytes)
            .unwrap();
        session.cache_validated_response(response).unwrap();

        let response = session.finish(DependencyOutcome::Error).unwrap();
        assert_eq!(
            response.error_code,
            Some(SemanticObservationErrorCode::NotFound)
        );
        assert_eq!(
            response.payload,
            Some(encode_base64url(br#"{"kind":"missing-row"}"#))
        );
    }

    #[test]
    fn compact_inputs_preserve_duplicate_metadata_in_order() {
        let duplicate = SemanticDependencyMetadata {
            name: encode_base64url(b"x-test"),
            value: encode_base64url(b"one"),
        };
        let mut input = request_input(AutomaticObservationClass::Database);
        input.metadata = vec![duplicate.clone(), duplicate];
        let request_bytes = SemanticDependencySession::canonical_request(input).unwrap();
        let request: SemanticDependencyRequest = parse_canonical(&request_bytes).unwrap();
        assert_eq!(request.metadata.len(), 2);
        assert_eq!(request.metadata[0], request.metadata[1]);
    }

    #[test]
    fn compact_request_rejects_class_operation_mismatch_and_one_over_payload() {
        let mut mismatch = request_input(AutomaticObservationClass::Database);
        mismatch.operation = SemanticDependencyOperation::QueuePublish;
        assert_eq!(
            SemanticDependencySession::canonical_request(mismatch)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );

        let mut one_over = request_input(AutomaticObservationClass::Database);
        one_over.payload = encode_base64url(&vec![
            0_u8;
            reproit_core::model::MAX_SEMANTIC_DEPENDENCY_PAYLOAD_BYTES
                + 1
        ]);
        assert_eq!(
            SemanticDependencySession::canonical_request(one_over)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
    }

    #[test]
    fn dependency_cleanup_releases_engine_and_sentinel_slots() {
        let mut registry = Registry::new();
        let dependency_handle = 700;
        let operation_handle = 701;
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        session.bind_canonical_session_position(0).unwrap();
        registry.observations.insert(
            dependency_handle,
            crate::ObservationEntry {
                operation_handle,
                semantic_dependency: Some(session),
            },
        );
        sentinel::observation_opened(
            dependency_handle,
            operation_handle,
            AutomaticObservationClass::Database,
        );
        assert!(sentinel::observation_is_active(dependency_handle));

        registry.cleanup_dependency(dependency_handle);

        assert!(!registry.observations.contains_key(&dependency_handle));
        assert!(!sentinel::observation_is_active(dependency_handle));
    }

    #[test]
    fn dependency_finish_mode_errors_release_all_state() {
        let dependency_handle = 710;

        let mut capture = registry_dependency(dependency_handle, "capture", None);
        assert_eq!(
            capture
                .finish_dependency(dependency_handle, None)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
        assert_dependency_is_clean(&capture, dependency_handle);

        let mut replay = registry_dependency(dependency_handle, "replay", None);
        assert_eq!(
            replay
                .finish_dependency(dependency_handle, Some(response_input()))
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
        assert_dependency_is_clean(&replay, dependency_handle);

        let mut invalid_capture = registry_dependency(dependency_handle, "capture", None);
        let mut invalid_response = response_input();
        invalid_response.status_code = Some(200);
        assert_eq!(
            invalid_capture
                .finish_dependency(dependency_handle, Some(invalid_response))
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
        assert_dependency_is_clean(&invalid_capture, dependency_handle);

        let mut canonical_finish_error = registry_dependency(dependency_handle, "capture", None);
        assert_eq!(
            canonical_finish_error
                .finish_dependency(dependency_handle, Some(response_input()))
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        assert_dependency_is_clean(&canonical_finish_error, dependency_handle);
    }

    fn registry_dependency(
        dependency_handle: u64,
        action: &str,
        response_bytes: Option<&[u8]>,
    ) -> Registry {
        let operation_handle = 711;
        let request_bytes = SemanticDependencySession::canonical_request(request_input(
            AutomaticObservationClass::Database,
        ))
        .unwrap();
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        session.bind_canonical_session_position(0).unwrap();
        session
            .write(ObservationStreamInput::Request, &request_bytes)
            .unwrap();
        session.dispatch().unwrap();
        session.bind_action(action).unwrap();
        if let Some(response_bytes) = response_bytes {
            session
                .write(ObservationStreamInput::Response, response_bytes)
                .unwrap();
        }
        let mut registry = Registry::new();
        registry.observations.insert(
            dependency_handle,
            crate::ObservationEntry {
                operation_handle,
                semantic_dependency: Some(session),
            },
        );
        sentinel::observation_opened(
            dependency_handle,
            operation_handle,
            AutomaticObservationClass::Database,
        );
        registry
    }

    fn assert_dependency_is_clean(registry: &Registry, dependency_handle: u64) {
        assert!(!registry.observations.contains_key(&dependency_handle));
        assert!(!sentinel::observation_is_active(dependency_handle));
    }

    #[test]
    fn validates_a_canonical_replay_response_across_reads() {
        let request = request(AutomaticObservationClass::OutboundHttp);
        let response_bytes = canonical::canonical_bytes(&response(&request)).unwrap();
        replay_session(AutomaticObservationClass::OutboundHttp, &response_bytes)
            .finish(DependencyOutcome::Response)
            .unwrap();
    }

    #[test]
    fn rejects_a_replay_response_for_a_different_request() {
        let database_request = request(AutomaticObservationClass::Database);
        let mut response = response(&database_request);
        response.request_digest =
            canonical::digest(&request(AutomaticObservationClass::OutboundHttp)).unwrap();
        let response_bytes = canonical::canonical_bytes(&response).unwrap();
        assert_eq!(
            replay_session(AutomaticObservationClass::Database, &response_bytes)
                .finish(DependencyOutcome::Response)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
    }

    #[test]
    fn rejects_one_byte_over_replay_response_bound() {
        let request = request(AutomaticObservationClass::Database);
        let request_bytes = canonical::canonical_bytes(&request).unwrap();
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        session
            .write(ObservationStreamInput::Request, &request_bytes)
            .unwrap();
        session.dispatch().unwrap();
        let at_limit = vec![0; MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES];
        session
            .write(ObservationStreamInput::Response, &at_limit)
            .unwrap();
        assert_eq!(
            session
                .write(ObservationStreamInput::Response, &[0])
                .unwrap_err()
                .code,
            ErrorCode::RuntimeQuota
        );
    }

    #[test]
    fn rejects_noncanonical_and_mismatched_records() {
        let request = request(AutomaticObservationClass::Database);
        let request_bytes = canonical::canonical_bytes(&request).unwrap();
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&request_bytes);
        session
            .write(ObservationStreamInput::Request, &noncanonical)
            .unwrap();
        assert_eq!(
            session.dispatch().unwrap_err().code,
            ErrorCode::IncompleteCandidate
        );

        assert_eq!(
            complete_session(AutomaticObservationClass::Database)
                .finish(DependencyOutcome::Error)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteCandidate
        );
    }

    #[test]
    fn rejects_one_byte_over_record_bound() {
        let mut session =
            SemanticDependencySession::for_class(AutomaticObservationClass::Database).unwrap();
        let at_limit = vec![0; MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES];
        session
            .write(ObservationStreamInput::Request, &at_limit)
            .unwrap();
        assert_eq!(
            session
                .write(ObservationStreamInput::Request, &[0])
                .unwrap_err()
                .code,
            ErrorCode::RuntimeQuota
        );
    }
}
