#![deny(clippy::all, clippy::pedantic)]
#![allow(unsafe_code)]

use std::{
    collections::BTreeMap,
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    slice,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use reproit_backend::config::BackendSdk;
use reproit_core::{
    Error, ErrorCode,
    crypto::decode_base64url_bytes,
    identity::{Digest, OperationId},
    model::{
        AutomaticObservationClass, DependencyOutcome, FailureIdentity, OperationBeginPayload,
        OperationInputPayload, SubjectClosureManifest, TriggerCompletion,
    },
};
use reproit_sdk_rust::{
    AutomaticManagedEngine, AutomaticManagedOperation, ManagedProjectToken, OfficialManagedProject,
    PackagedSubjectObject, SubjectPackage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod failure_delivery;
mod observation;
mod semantic_dependency;
mod sentinel;

use failure_delivery::{FailureTask, FailureWork, FailureWorker, MAX_FAILURE_TASKS};
use observation::{ObservationAdapterInput, ObservationStreamInput};
use semantic_dependency::SemanticDependencySession;

#[cfg(test)]
use failure_delivery::ReadySink;

const ABI_VERSION: u32 = 1;
const ABI_CONTRACT: &str = include_str!("../sdk-engine-abi.json");
const CALL_FORMAT: &str = "reproit.sdk-engine-call.v1";
const RESPONSE_FORMAT: &str = "reproit.sdk-engine-response.v1";
const MAX_CALL_BYTES: usize = 1_048_576;
const MIN_RESPONSE_CAPACITY: usize = 16_384;
const MAX_ERROR_RESPONSE_BYTES: usize = 256;
const MAX_ENGINES: usize = 64;
const MAX_EVIDENCE_BYTES: usize = 785_408;
const MAX_OPERATIONS: usize = 512;
const MAX_SINKS: usize = MAX_FAILURE_TASKS;
const MAX_SINK_WAIT_MS: u64 = reproit_sdk_rust::CANDIDATE_DELIVERY_LIFETIME_MS;
const RESULT_INVALID_CALL_BOUNDARY: isize = -1;
const RESULT_ENGINE_PANIC: isize = -2;
const RESULT_OUTPUT_CAPACITY_EXCEEDED: isize = -3;
const RESULT_RESPONSE_LENGTH_OVERFLOW: isize = -4;

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static FAILURE_WORKER: OnceLock<FailureWorker> = OnceLock::new();

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum EngineCall {
    Contract {
        format: String,
    },
    EngineOpen {
        build_repository_id: String,
        format: String,
        #[serde(default)]
        observation_adapters: Vec<ObservationAdapterInput>,
        project_toml: String,
        sdk: BackendSdk,
        source_revision: String,
        subject_manifest: SubjectClosureManifest,
        subject_objects: Vec<SubjectObjectInput>,
    },
    EngineClose {
        engine_handle: u64,
        format: String,
    },
    OperationBegin {
        begin: OperationBeginPayload,
        engine_handle: u64,
        format: String,
    },
    OperationInput {
        format: String,
        input: OperationInputPayload,
        operation_handle: u64,
    },
    ObservationOpen {
        causal_parent_id: Option<OperationId>,
        class: AutomaticObservationClass,
        format: String,
        operation_handle: u64,
    },
    ObservationRead {
        format: String,
        observation_handle: u64,
    },
    ObservationWrite {
        chunk: String,
        format: String,
        observation_handle: u64,
        stream: ObservationStreamInput,
    },
    ObservationDispatch {
        format: String,
        observation_handle: u64,
    },
    ObservationFinish {
        format: String,
        observation_handle: u64,
        outcome: DependencyOutcome,
        session_position: u64,
    },
    ObservationAbandon {
        format: String,
        observation_handle: u64,
    },
    OperationUnowned {
        causal_parent_id: Option<OperationId>,
        class: AutomaticObservationClass,
        evidence: String,
        format: String,
        operation_handle: u64,
    },
    OperationCloseWorld {
        completion: TriggerCompletion,
        format: String,
        operation_handle: u64,
    },
    OperationSucceed {
        format: String,
        operation_handle: u64,
    },
    OperationAbandon {
        format: String,
        operation_handle: u64,
    },
    OperationFail {
        failure: FailureIdentity,
        format: String,
        operation_handle: u64,
        project_token: String,
    },
    SinkWait {
        format: String,
        sink_handle: u64,
        timeout_ms: u64,
    },
}

impl EngineCall {
    fn format(&self) -> &str {
        match self {
            Self::Contract { format }
            | Self::EngineOpen { format, .. }
            | Self::EngineClose { format, .. }
            | Self::ObservationAbandon { format, .. }
            | Self::ObservationDispatch { format, .. }
            | Self::ObservationFinish { format, .. }
            | Self::ObservationOpen { format, .. }
            | Self::ObservationRead { format, .. }
            | Self::ObservationWrite { format, .. }
            | Self::OperationBegin { format, .. }
            | Self::OperationInput { format, .. }
            | Self::OperationUnowned { format, .. }
            | Self::OperationCloseWorld { format, .. }
            | Self::OperationSucceed { format, .. }
            | Self::OperationAbandon { format, .. }
            | Self::OperationFail { format, .. }
            | Self::SinkWait { format, .. } => format,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectObjectInput {
    digest: Digest,
    path: PathBuf,
    size: u64,
}

struct EngineOpenConfiguration {
    build_repository_id: String,
    observation_adapters: Vec<ObservationAdapterInput>,
    project_toml: String,
    sdk: BackendSdk,
    source_revision: String,
    subject_manifest: SubjectClosureManifest,
    subject_objects: Vec<SubjectObjectInput>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EngineResponse {
    error_code: Option<&'static str>,
    format: &'static str,
    ok: bool,
    result: Value,
}

struct OperationEntry {
    engine_handle: u64,
    operation: AutomaticManagedOperation,
}

struct SinkEntry {
    engine_handle: u64,
    task: Arc<FailureTask>,
}

struct ObservationEntry {
    operation_handle: u64,
    semantic_dependency: Option<SemanticDependencySession>,
}

struct Registry {
    engines: BTreeMap<u64, AutomaticManagedEngine>,
    next_handle: u64,
    observations: BTreeMap<u64, ObservationEntry>,
    operations: BTreeMap<u64, OperationEntry>,
    sinks: BTreeMap<u64, SinkEntry>,
}

impl Registry {
    fn new() -> Self {
        Self {
            engines: BTreeMap::new(),
            next_handle: 1,
            observations: BTreeMap::new(),
            operations: BTreeMap::new(),
            sinks: BTreeMap::new(),
        }
    }

    fn allocate_handle(&mut self) -> Result<u64, Error> {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).ok_or_else(quota_error)?;
        Ok(handle)
    }

    fn dispatch_immediate(&mut self, call: EngineCall) -> Result<Value, Error> {
        match call {
            EngineCall::Contract { .. } => {
                serde_json::from_str(ABI_CONTRACT).map_err(|_| Error::schema_invalid())
            }
            EngineCall::EngineOpen {
                build_repository_id,
                observation_adapters,
                project_toml,
                sdk,
                source_revision,
                subject_manifest,
                subject_objects,
                ..
            } => self.open_engine(EngineOpenConfiguration {
                build_repository_id,
                observation_adapters,
                project_toml,
                sdk,
                source_revision,
                subject_manifest,
                subject_objects,
            }),
            EngineCall::EngineClose { engine_handle, .. } => self.close_engine(engine_handle),
            operation_call => self.dispatch_operation(operation_call),
        }
    }

    fn dispatch_operation(&mut self, call: EngineCall) -> Result<Value, Error> {
        match call {
            EngineCall::OperationBegin {
                begin,
                engine_handle,
                ..
            } => self.begin_operation(engine_handle, &begin),
            EngineCall::OperationInput {
                input,
                operation_handle,
                ..
            } => {
                self.operations
                    .get(&operation_handle)
                    .ok_or_else(not_found)?
                    .operation
                    .record_input(&input)?;
                Ok(json!({}))
            }
            observation_call @ (EngineCall::ObservationOpen { .. }
            | EngineCall::ObservationWrite { .. }
            | EngineCall::ObservationDispatch { .. }
            | EngineCall::ObservationRead { .. }
            | EngineCall::ObservationFinish { .. }
            | EngineCall::ObservationAbandon { .. }) => {
                self.dispatch_observation_call(observation_call)
            }
            EngineCall::OperationUnowned {
                causal_parent_id,
                class,
                evidence,
                operation_handle,
                ..
            } => self.record_unowned(operation_handle, class, causal_parent_id, &evidence),
            EngineCall::OperationCloseWorld {
                completion,
                operation_handle,
                ..
            } => self.close_world(operation_handle, completion),
            EngineCall::OperationSucceed {
                operation_handle, ..
            } => self.succeed_operation(operation_handle),
            EngineCall::OperationAbandon {
                operation_handle, ..
            } => self.abandon_operation(operation_handle),
            EngineCall::OperationFail { .. } | EngineCall::SinkWait { .. } => {
                Err(Error::schema_invalid())
            }
            EngineCall::Contract { .. }
            | EngineCall::EngineOpen { .. }
            | EngineCall::EngineClose { .. } => Err(Error::schema_invalid()),
        }
    }

    fn dispatch_observation_call(&mut self, call: EngineCall) -> Result<Value, Error> {
        match call {
            EngineCall::ObservationOpen {
                causal_parent_id,
                class,
                operation_handle,
                ..
            } => {
                let result = self.open_observation(operation_handle, class, causal_parent_id)?;
                let observation_handle = result
                    .get("observation_handle")
                    .and_then(Value::as_u64)
                    .ok_or_else(Error::schema_invalid)?;
                sentinel::observation_opened(observation_handle, operation_handle, class);
                Ok(result)
            }
            EngineCall::ObservationWrite {
                chunk,
                observation_handle,
                stream,
                ..
            } => self.write_observation(observation_handle, stream, &chunk),
            EngineCall::ObservationDispatch {
                observation_handle, ..
            } => {
                let result = self.dispatch_observation(observation_handle)?;
                sentinel::observation_dispatched(observation_handle);
                Ok(result)
            }
            EngineCall::ObservationRead {
                observation_handle, ..
            } => self.read_observation(observation_handle),
            EngineCall::ObservationFinish {
                observation_handle,
                outcome,
                session_position,
                ..
            } => {
                sentinel::observation_finished(observation_handle);
                self.finish_observation(observation_handle, outcome, session_position)
            }
            EngineCall::ObservationAbandon {
                observation_handle, ..
            } => {
                sentinel::observation_finished(observation_handle);
                self.abandon_observation(observation_handle)
            }
            _ => Err(Error::schema_invalid()),
        }
    }

    fn succeed_operation(&mut self, operation_handle: u64) -> Result<Value, Error> {
        remove_operation_observations(&mut self.observations, operation_handle);
        sentinel::operation_removed(operation_handle);
        self.operations
            .remove(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .succeed();
        Ok(json!({}))
    }

    fn abandon_operation(&mut self, operation_handle: u64) -> Result<Value, Error> {
        remove_operation_observations(&mut self.observations, operation_handle);
        sentinel::operation_removed(operation_handle);
        self.operations
            .remove(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .abandon_incomplete();
        Ok(json!({}))
    }

    fn open_engine(&mut self, configuration: EngineOpenConfiguration) -> Result<Value, Error> {
        if self.engines.len() >= MAX_ENGINES {
            return Err(quota_error());
        }
        let project = OfficialManagedProject::from_build_for_sdk(
            &configuration.project_toml,
            &configuration.build_repository_id,
            &configuration.source_revision,
            configuration.sdk,
        )?;
        let objects = configuration
            .subject_objects
            .into_iter()
            .map(|object| PackagedSubjectObject {
                digest: object.digest,
                path: object.path,
                size: object.size,
            })
            .collect::<Vec<_>>();
        let subject = SubjectPackage::freeze(configuration.subject_manifest, &objects)?;
        let mut engine = AutomaticManagedEngine::new(project, subject);
        for adapter in configuration.observation_adapters {
            engine.register_observation_adapter(
                adapter.class,
                adapter.adapter_id,
                adapter.adapter_version,
                adapter.implementation_digest,
            )?;
        }
        let handle = self.allocate_handle()?;
        self.engines.insert(handle, engine);
        sentinel::engine_opened();
        Ok(json!({ "engine_handle": handle }))
    }

    fn close_engine(&mut self, engine_handle: u64) -> Result<Value, Error> {
        if self.engines.remove(&engine_handle).is_none() {
            return Err(not_found());
        }
        let operation_handles = self
            .operations
            .iter()
            .filter_map(|(handle, entry)| (entry.engine_handle == engine_handle).then_some(*handle))
            .collect::<Vec<_>>();
        for operation_handle in operation_handles {
            remove_operation_observations(&mut self.observations, operation_handle);
            sentinel::operation_removed(operation_handle);
        }
        remove_engine_entries(&mut self.operations, engine_handle, |entry| {
            entry.engine_handle
        });
        remove_engine_sinks(&mut self.sinks, engine_handle);
        sentinel::engine_closed();
        Ok(json!({}))
    }

    fn begin_operation(
        &mut self,
        engine_handle: u64,
        begin: &OperationBeginPayload,
    ) -> Result<Value, Error> {
        if self.operations.len() >= MAX_OPERATIONS {
            return Err(quota_error());
        }
        let operation = self
            .engines
            .get(&engine_handle)
            .ok_or_else(not_found)?
            .start(begin)?;
        let operation_id = operation.operation_id().to_string();
        let handle = self.allocate_handle()?;
        self.operations.insert(
            handle,
            OperationEntry {
                engine_handle,
                operation,
            },
        );
        sentinel::operation_started(handle);
        Ok(json!({
            "operation_handle": handle,
            "operation_id": operation_id,
        }))
    }

    fn record_unowned(
        &mut self,
        operation_handle: u64,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
        evidence: &str,
    ) -> Result<Value, Error> {
        if evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(quota_error());
        }
        let evidence = decode_base64url_bytes(evidence)?;
        self.operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .mark_unowned(class, causal_parent_id, &evidence)?;
        Ok(json!({}))
    }

    fn close_world(
        &mut self,
        operation_handle: u64,
        completion: TriggerCompletion,
    ) -> Result<Value, Error> {
        let _coverage = sentinel::operation_finished(operation_handle);
        self.operations
            .get_mut(&operation_handle)
            .ok_or_else(not_found)?
            .operation
            .close_world(completion)?;
        Ok(json!({}))
    }

    fn prepare_failure(
        &mut self,
        entry: OperationEntry,
        failure: FailureIdentity,
        project_token: ManagedProjectToken,
    ) -> Result<(u64, Arc<FailureTask>, FailureWork), Error> {
        let handle = match self.allocate_handle() {
            Ok(handle) => handle,
            Err(error) => {
                entry.operation.abandon_incomplete();
                return Err(error);
            }
        };
        let task = FailureTask::pending(entry.operation, failure, project_token);
        self.sinks.insert(
            handle,
            SinkEntry {
                engine_handle: entry.engine_handle,
                task: task.clone(),
            },
        );
        let work = task.work();
        Ok((handle, task, work))
    }
}

fn dispatch_call(registry: &Mutex<Registry>, call: EngineCall) -> Result<Value, Error> {
    if call.format() != CALL_FORMAT {
        return Err(Error::schema_invalid());
    }
    match call {
        EngineCall::OperationFail {
            failure,
            operation_handle,
            project_token,
            ..
        } => enqueue_failure(registry, operation_handle, failure, project_token),
        EngineCall::SinkWait {
            sink_handle,
            timeout_ms,
            ..
        } => wait_for_sink(registry, sink_handle, timeout_ms),
        immediate => registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dispatch_immediate(immediate),
    }
}

fn enqueue_failure(
    registry: &Mutex<Registry>,
    operation_handle: u64,
    failure: FailureIdentity,
    project_token: String,
) -> Result<Value, Error> {
    let worker = FAILURE_WORKER.get_or_init(FailureWorker::start);
    let (sink_handle, task, work) = {
        let mut registry = registry.lock().unwrap_or_else(PoisonError::into_inner);
        let at_capacity = registry.sinks.len() >= MAX_SINKS;
        let entry = take_failure_operation(
            &mut registry.operations,
            operation_handle,
            at_capacity,
            |entry| entry.operation.abandon_incomplete(),
        );
        remove_operation_observations(&mut registry.observations, operation_handle);
        sentinel::operation_removed(operation_handle);
        let entry = entry?;
        let (entry, project_token) = validate_failure_token(entry, project_token, |entry| {
            entry.operation.abandon_incomplete();
        })?;
        registry.prepare_failure(entry, failure, project_token)?
    };
    if let Err(error) = worker.try_send(work) {
        reject_failure_enqueue(registry, sink_handle, &task);
        return Err(error);
    }
    Ok(json!({ "sink_handle": sink_handle }))
}

fn wait_for_sink(
    registry: &Mutex<Registry>,
    sink_handle: u64,
    timeout_ms: u64,
) -> Result<Value, Error> {
    if timeout_ms > MAX_SINK_WAIT_MS {
        return Err(quota_error());
    }
    let task = registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .sinks
        .get(&sink_handle)
        .ok_or_else(not_found)?
        .task
        .clone();
    let result = task.wait_until_idle(Duration::from_millis(timeout_ms));
    match result {
        Ok(idle) => {
            if idle {
                remove_sink_if_same(registry, sink_handle, &task);
            }
            Ok(json!({ "idle": idle }))
        }
        Err(error) => {
            remove_sink_if_same(registry, sink_handle, &task);
            Err(error)
        }
    }
}

fn remove_sink_if_same(registry: &Mutex<Registry>, sink_handle: u64, task: &Arc<FailureTask>) {
    let mut registry = registry.lock().unwrap_or_else(PoisonError::into_inner);
    let same = registry
        .sinks
        .get(&sink_handle)
        .is_some_and(|entry| Arc::ptr_eq(&entry.task, task));
    if same {
        registry.sinks.remove(&sink_handle);
    }
}

fn reject_failure_enqueue(registry: &Mutex<Registry>, sink_handle: u64, task: &Arc<FailureTask>) {
    task.cancel();
    remove_sink_if_same(registry, sink_handle, task);
}

fn remove_engine_entries<T>(
    entries: &mut BTreeMap<u64, T>,
    engine_handle: u64,
    owner: impl Fn(&T) -> u64,
) {
    entries.retain(|_, entry| owner(entry) != engine_handle);
}

fn remove_operation_observations(
    observations: &mut BTreeMap<u64, ObservationEntry>,
    operation_handle: u64,
) {
    observations.retain(|_, entry| entry.operation_handle != operation_handle);
}

fn take_failure_operation<T>(
    operations: &mut BTreeMap<u64, T>,
    operation_handle: u64,
    at_capacity: bool,
    abandon: impl FnOnce(T),
) -> Result<T, Error> {
    let operation = operations.remove(&operation_handle).ok_or_else(not_found)?;
    if at_capacity {
        abandon(operation);
        return Err(quota_error());
    }
    Ok(operation)
}

fn validate_failure_token<T>(
    operation: T,
    project_token: String,
    abandon: impl FnOnce(T),
) -> Result<(T, ManagedProjectToken), Error> {
    match ManagedProjectToken::new(project_token) {
        Ok(token) => Ok((operation, token)),
        Err(error) => {
            abandon(operation);
            Err(error)
        }
    }
}

fn remove_engine_sinks(sinks: &mut BTreeMap<u64, SinkEntry>, engine_handle: u64) {
    sinks.retain(|_, entry| {
        if entry.engine_handle == engine_handle {
            entry.task.cancel();
            false
        } else {
            true
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn reproit_sdk_engine_abi_version() -> u32 {
    ABI_VERSION
}

/// Execute one bounded engine call.
///
/// # Safety
///
/// `input` must reference `input_len` readable bytes. `output` must reference
/// `output_capacity` writable bytes. The buffers must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reproit_sdk_engine_call(
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_capacity: usize,
) -> isize {
    if input.is_null()
        || output.is_null()
        || input_len == 0
        || input_len > MAX_CALL_BYTES
        || output_capacity < MIN_RESPONSE_CAPACITY
    {
        return RESULT_INVALID_CALL_BOUNDARY;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Safety: The caller contract is checked above and documented on this function.
        let input = unsafe { slice::from_raw_parts(input.cast::<u8>(), input_len) };
        execute(input)
    }));
    let Ok(response) = result else {
        return RESULT_ENGINE_PANIC;
    };
    if response.len() > output_capacity {
        return RESULT_OUTPUT_CAPACITY_EXCEEDED;
    }
    let Ok(response_len) = isize::try_from(response.len()) else {
        return RESULT_RESPONSE_LENGTH_OVERFLOW;
    };
    // Safety: The caller contract is checked above. The source is a distinct Rust buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(response.as_ptr(), output.cast::<u8>(), response.len());
    }
    response_len
}

fn execute(input: &[u8]) -> Vec<u8> {
    let response = match serde_json::from_slice::<EngineCall>(input) {
        Ok(call) => {
            let _engine_call_guard = sentinel::engine_call_scope();
            let registry = REGISTRY.get_or_init(|| Mutex::new(Registry::new()));
            match dispatch_call(registry, call) {
                Ok(result) => EngineResponse {
                    error_code: None,
                    format: RESPONSE_FORMAT,
                    ok: true,
                    result,
                },
                Err(error) => error_response(&error),
            }
        }
        Err(_) => error_response(&Error::schema_invalid()),
    };
    serialize_response(&response)
}

fn serialize_response(response: &EngineResponse) -> Vec<u8> {
    const FALLBACK: &[u8] =
        br#"{"error_code":"SCHEMA_INVALID","format":"reproit.sdk-engine-response.v1","ok":false,"result":{}}"#;

    let bytes = serde_json::to_vec(response).unwrap_or_else(|_| FALLBACK.to_vec());
    if !response.ok && bytes.len() > MAX_ERROR_RESPONSE_BYTES {
        return FALLBACK.to_vec();
    }
    bytes
}

fn error_response(error: &Error) -> EngineResponse {
    EngineResponse {
        error_code: Some(error.code.as_str()),
        format: RESPONSE_FORMAT,
        ok: false,
        result: json!({}),
    }
}

fn quota_error() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The shared SDK engine limit was reached.",
    )
}

fn not_found() -> Error {
    Error::new(
        ErrorCode::NotFound,
        "The shared SDK engine handle does not exist.",
    )
}

#[cfg(test)]
mod tests;
