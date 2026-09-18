use std::{fs::File, io::Read as _, path::Path};

use reproit_core::{
    Error, canonical,
    model::{
        AutomaticObservationClass, DependencyOutcome, SemanticDependencyRequest,
        SemanticDependencyResponse, SemanticObservationOperation, SemanticObservationOutcome,
        SemanticObservationRequest, SemanticObservationResponse, validate_semantic_dependency_pair,
        validate_semantic_observation_pair,
    },
};

use super::{
    MAX_SEMANTIC_RECORD_BYTES, ObservationSession, SemanticContract, invalid_transition,
    local_storage_error,
};

impl ObservationSession {
    pub(super) fn validate_semantic_request(&self) -> Result<(), Error> {
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

    pub(super) fn validate_semantic_pair(&self, outcome: DependencyOutcome) -> Result<(), Error> {
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

pub(super) fn semantic_contract_for(class: AutomaticObservationClass) -> SemanticContract {
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
