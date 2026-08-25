use reproit_core::{
    Error, ErrorCode,
    crypto::{decode_base64url_bytes, encode_base64url},
    identity::{Digest, OperationId},
    model::{AutomaticObservationClass, DependencyOutcome},
};
use reproit_sdk_rust::AutomaticManagedOperation;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ObservationEntry, Registry, not_found};

pub const MAX_OBSERVATION_SESSIONS: usize = 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAdapterInput {
    pub adapter_id: String,
    pub adapter_version: String,
    pub class: AutomaticObservationClass,
    pub implementation_digest: Digest,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservationStreamInput {
    Request,
    Response,
}

pub fn decode_chunk(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, Error> {
    let maximum_encoded_bytes = maximum_bytes
        .checked_add(2)
        .and_then(|bytes| bytes.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .ok_or_else(quota_error)?;
    if value.is_empty() || value.len() > maximum_encoded_bytes {
        return Err(quota_error());
    }
    let bytes = decode_base64url_bytes(value)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(quota_error());
    }
    Ok(bytes)
}

impl Registry {
    pub(super) fn open_observation(
        &mut self,
        operation_handle: u64,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
    ) -> Result<Value, Error> {
        if self.observations.len() >= MAX_OBSERVATION_SESSIONS {
            return Err(quota_error());
        }
        let observation_handle = self.allocate_handle()?;
        let session_position = self
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .open_observation(observation_handle, class, causal_parent_id)?;
        self.observations
            .insert(observation_handle, ObservationEntry { operation_handle });
        Ok(json!({
            "observation_handle": observation_handle,
            "session_position": session_position,
        }))
    }

    pub(super) fn write_observation(
        &mut self,
        observation_handle: u64,
        stream: ObservationStreamInput,
        chunk: &str,
    ) -> Result<Value, Error> {
        let chunk = decode_chunk(
            chunk,
            AutomaticManagedOperation::MAX_OBSERVATION_CHUNK_BYTES,
        )?;
        let operation_handle = self.operation_for_observation(observation_handle)?;
        let operation = &mut self
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation;
        match stream {
            ObservationStreamInput::Request => {
                operation.write_observation_request(observation_handle, &chunk)?;
            }
            ObservationStreamInput::Response => {
                operation.write_observation_response(observation_handle, &chunk)?;
            }
        }
        Ok(json!({}))
    }

    pub(super) fn dispatch_observation(&mut self, observation_handle: u64) -> Result<Value, Error> {
        let operation_handle = self.operation_for_observation(observation_handle)?;
        let action = self
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .dispatch_observation(observation_handle)?;
        Ok(json!({ "action": action }))
    }

    pub(super) fn read_observation(&mut self, observation_handle: u64) -> Result<Value, Error> {
        let operation_handle = self.operation_for_observation(observation_handle)?;
        let (chunk, eof) = self
            .operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .read_observation_response(observation_handle)?;
        encode_observation_read_result(&chunk, eof)
    }

    pub(super) fn finish_observation(
        &mut self,
        observation_handle: u64,
        outcome: DependencyOutcome,
        session_position: u64,
    ) -> Result<Value, Error> {
        let operation_handle = self.take_observation(observation_handle)?;
        self.operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .finish_observation(observation_handle, outcome, session_position)?;
        Ok(json!({}))
    }

    pub(super) fn abandon_observation(&mut self, observation_handle: u64) -> Result<Value, Error> {
        let observations = &mut self.observations;
        let operations = &mut self.operations;
        abandon_observation_entry(observations, observation_handle, |operation_handle| {
            operations
                .get_mut(&operation_handle)
                .ok_or_else(not_found)?
                .operation
                .abandon_observation(observation_handle)
        })?;
        Ok(json!({}))
    }

    fn operation_for_observation(&self, observation_handle: u64) -> Result<u64, Error> {
        self.observations
            .get(&observation_handle)
            .map(|entry| entry.operation_handle)
            .ok_or_else(not_found)
    }

    fn take_observation(&mut self, observation_handle: u64) -> Result<u64, Error> {
        self.observations
            .remove(&observation_handle)
            .map(|entry| entry.operation_handle)
            .ok_or_else(not_found)
    }
}

fn abandon_observation_entry(
    observations: &mut std::collections::BTreeMap<u64, ObservationEntry>,
    observation_handle: u64,
    abandon: impl FnOnce(u64) -> Result<(), Error>,
) -> Result<(), Error> {
    let operation_handle = observations
        .get(&observation_handle)
        .map(|entry| entry.operation_handle)
        .ok_or_else(not_found)?;
    abandon(operation_handle)?;
    observations
        .remove(&observation_handle)
        .ok_or_else(not_found)?;
    Ok(())
}

pub(super) fn encode_observation_read_result(chunk: &[u8], eof: bool) -> Result<Value, Error> {
    if chunk.len() > AutomaticManagedOperation::MAX_OBSERVATION_RESPONSE_READ_BYTES {
        return Err(quota_error());
    }
    Ok(json!({
        "chunk": encode_base64url(chunk),
        "eof": eof,
    }))
}

fn quota_error() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The automatic observation chunk limit was reached.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use reproit_core::crypto::encode_base64url;

    #[test]
    fn chunk_bound_accepts_the_limit_and_rejects_one_byte_over() {
        let at_limit = vec![0_u8; 32 * 1_024];
        assert_eq!(
            decode_chunk(&encode_base64url(&at_limit), at_limit.len())
                .unwrap()
                .len(),
            at_limit.len()
        );
        let one_over = vec![0_u8; at_limit.len() + 1];
        assert_eq!(
            decode_chunk(&encode_base64url(&one_over), at_limit.len())
                .unwrap_err()
                .code,
            ErrorCode::RuntimeQuota
        );
    }

    #[test]
    fn read_result_rejects_one_byte_over_the_raw_limit() {
        let one_over =
            vec![0_u8; AutomaticManagedOperation::MAX_OBSERVATION_RESPONSE_READ_BYTES + 1];
        assert_eq!(
            encode_observation_read_result(&one_over, false)
                .unwrap_err()
                .code,
            ErrorCode::RuntimeQuota
        );
    }

    #[test]
    fn successful_abandon_releases_the_global_slot_once() {
        let mut observations = std::collections::BTreeMap::from([(
            7,
            ObservationEntry {
                operation_handle: 11,
            },
        )]);
        let mut abandon_calls = 0;
        abandon_observation_entry(&mut observations, 7, |operation_handle| {
            assert_eq!(operation_handle, 11);
            abandon_calls += 1;
            Ok(())
        })
        .unwrap();

        assert!(observations.is_empty());
        assert_eq!(abandon_calls, 1);
        assert_eq!(
            abandon_observation_entry(&mut observations, 7, |_| Ok(()))
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        observations.insert(
            8,
            ObservationEntry {
                operation_handle: 11,
            },
        );
        super::super::remove_operation_observations(&mut observations, 11);
        super::super::remove_operation_observations(&mut observations, 11);
        assert!(observations.is_empty());
    }
}
