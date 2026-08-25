use reproit_core::{
    Error, ErrorCode, canonical,
    model::{
        AutomaticObservationClass, DependencyOutcome, MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
        SemanticDependencyRequest, SemanticDependencyResponse, SemanticObservationOutcome,
        Validate, validate_semantic_dependency_pair,
    },
};
use serde::{Serialize, de::DeserializeOwned};

use crate::observation::ObservationStreamInput;

pub(super) struct SemanticDependencySession {
    class: AutomaticObservationClass,
    request: Vec<u8>,
    response: Vec<u8>,
    validated_request: Option<SemanticDependencyRequest>,
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
            class,
            request: Vec::new(),
            response: Vec::new(),
            validated_request: None,
        })
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

    pub(super) fn finish(&self, outcome: DependencyOutcome) -> Result<(), Error> {
        let request = self
            .validated_request
            .as_ref()
            .ok_or_else(invalid_dependency)?;
        let response = parse_canonical::<SemanticDependencyResponse>(&self.response)?;
        validate_semantic_dependency_pair(request, &response).map_err(|_| invalid_dependency())?;
        if !outcomes_match(outcome, response.outcome) {
            return Err(invalid_dependency());
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

fn outcomes_match(left: DependencyOutcome, right: SemanticObservationOutcome) -> bool {
    matches!(
        (left, right),
        (DependencyOutcome::Error, SemanticObservationOutcome::Error)
            | (
                DependencyOutcome::Response,
                SemanticObservationOutcome::Response
            )
    )
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
        model::{
            SemanticDependencyOperation, SemanticDependencyRequestFormat,
            SemanticDependencyResponseFormat,
        },
    };

    use super::*;

    fn request(class: AutomaticObservationClass) -> SemanticDependencyRequest {
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
        SemanticDependencyRequest {
            encoding: "canonical-json".to_owned(),
            format: SemanticDependencyRequestFormat::V1,
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
