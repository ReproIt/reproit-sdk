use super::*;
use crate::observation::MAX_OBSERVATION_SESSIONS;
use reproit_core::crypto::encode_base64url;
use std::{
    cell::Cell,
    sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
        mpsc::sync_channel,
    },
    thread,
};

const OPERATIONS: [&str; 17] = [
    "contract",
    "engine-close",
    "engine-open",
    "observation-abandon",
    "observation-dispatch",
    "observation-finish",
    "observation-open",
    "observation-read",
    "observation-write",
    "operation-abandon",
    "operation-begin",
    "operation-close-world",
    "operation-fail",
    "operation-input",
    "operation-succeed",
    "operation-unowned",
    "sink-wait",
];

#[test]
fn contract_call_returns_the_exact_abi_version() {
    let response = execute(br#"{"format":"reproit.sdk-engine-call.v1","operation":"contract"}"#);
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["format"], RESPONSE_FORMAT);
    assert_eq!(value["ok"], true);
    assert_eq!(value["result"]["abi_version"], ABI_VERSION);
}

#[test]
fn abi_contract_matches_engine_constants() {
    let contract: Value = serde_json::from_str(ABI_CONTRACT).unwrap();
    assert_eq!(contract["abi_version"], ABI_VERSION);
    assert_eq!(contract["request"]["format"], CALL_FORMAT);
    assert_eq!(contract["request"]["maximum_bytes"], MAX_CALL_BYTES);
    assert_eq!(contract["response"]["format"], RESPONSE_FORMAT);
    assert_eq!(
        contract["response"]["output_capacity_bytes"],
        MIN_RESPONSE_CAPACITY
    );
    assert_eq!(
        contract["error_behavior"]["json_error"]["maximum_bytes"],
        MAX_ERROR_RESPONSE_BYTES
    );
    assert_contract_limits(&contract);
    assert_eq!(contract["operations"], json!(OPERATIONS));
    assert_observation_contract(&contract);
    assert_native_failure_contract(&contract);
    assert_eq!(
        contract["symbols"]["abi_version"],
        "reproit_sdk_engine_abi_version"
    );
    assert_eq!(contract["symbols"]["call"], "reproit_sdk_engine_call");
}

#[test]
fn maximum_observation_read_success_envelope_fits_output_capacity() {
    let chunk = vec![u8::MAX; AutomaticManagedOperation::MAX_OBSERVATION_RESPONSE_READ_BYTES];
    let result = crate::observation::encode_observation_read_result(&chunk, false).unwrap();
    let response = EngineResponse {
        error_code: None,
        format: RESPONSE_FORMAT,
        ok: true,
        result,
    };
    let serialized = serialize_response(&response);

    assert_eq!(chunk.len(), 8_192);
    assert_eq!(response.result["chunk"].as_str().unwrap().len(), 10_923);
    assert_eq!(serialized.len(), 11_028);
    assert!(serialized.len() <= MIN_RESPONSE_CAPACITY);
}

fn assert_contract_limits(contract: &Value) {
    assert_eq!(contract["limits"]["engines"], MAX_ENGINES);
    assert_eq!(contract["limits"]["evidence_bytes"], MAX_EVIDENCE_BYTES);
    assert_eq!(
        contract["limits"]["observation_adapters"],
        AutomaticObservationClass::ALL.len()
    );
    assert_eq!(
        contract["limits"]["observation_chunk_bytes"],
        AutomaticManagedOperation::MAX_OBSERVATION_CHUNK_BYTES
    );
    assert_eq!(
        contract["limits"]["observation_response_read_bytes"],
        AutomaticManagedOperation::MAX_OBSERVATION_RESPONSE_READ_BYTES
    );
    assert_eq!(contract["limits"]["observation_response_read_bytes"], 8_192);
    assert_eq!(
        contract["limits"]["observation_sessions"],
        MAX_OBSERVATION_SESSIONS
    );
    assert_eq!(
        contract["limits"]["observation_sessions_per_operation"],
        AutomaticManagedOperation::MAX_OBSERVATION_SESSIONS
    );
    assert_eq!(contract["limits"]["operations"], MAX_OPERATIONS);
    assert_eq!(contract["limits"]["sink_wait_ms"], MAX_SINK_WAIT_MS);
    assert_eq!(contract["limits"]["sinks"], MAX_SINKS);
}

fn assert_observation_contract(contract: &Value) {
    assert_eq!(
        contract["observation_actions"],
        json!(["capture", "replay"])
    );
    assert_eq!(
        contract["observation_contract"],
        json!({
            "adapter_registration_fields": [
                "adapter_id",
                "adapter_version",
                "class",
                "implementation_digest",
            ],
            "finish_fields": ["observation_handle", "outcome", "session_position"],
                "open_fields": ["causal_parent_id", "class", "operation_handle"],
                "open_result_fields": ["observation_handle", "session_position"],
            "read_result_fields": ["chunk", "eof"],
            "write_fields": ["chunk", "observation_handle", "stream"],
        })
    );
}

fn assert_native_failure_contract(contract: &Value) {
    assert_eq!(
        contract["error_behavior"]["native_failures"],
        json!([
            {
                "code": RESULT_RESPONSE_LENGTH_OVERFLOW,
                "condition": "response-length-overflow",
                "output_written": false,
            },
            {
                "code": RESULT_OUTPUT_CAPACITY_EXCEEDED,
                "condition": "output-capacity-exceeded",
                "output_written": false,
            },
            {
                "code": RESULT_ENGINE_PANIC,
                "condition": "engine-panic",
                "output_written": false,
            },
            {
                "code": RESULT_INVALID_CALL_BOUNDARY,
                "condition": "invalid-call-boundary",
                "output_written": false,
            },
        ])
    );
}

#[test]
fn json_errors_stay_within_the_contract_bound() {
    let response = execute(b"not-json");
    assert!(response.len() <= MAX_ERROR_RESPONSE_BYTES);
}

#[test]
fn oversized_observation_chunk_stops_before_handle_lookup() {
    let chunk = encode_base64url(&vec![
        0_u8;
        AutomaticManagedOperation::MAX_OBSERVATION_CHUNK_BYTES
            + 1
    ]);
    let response = execute(
        json!({
            "chunk": chunk,
            "format": CALL_FORMAT,
            "observation_handle": 1,
            "operation": "observation-write",
            "stream": "request",
        })
        .to_string()
        .as_bytes(),
    );
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["error_code"], "RUNTIME_QUOTA");
    assert_eq!(value["ok"], false);
}

#[test]
fn one_over_global_observation_capacity_stops_before_operation_lookup() {
    let mut registry = Registry::new();
    for handle in 0..MAX_OBSERVATION_SESSIONS {
        registry.observations.insert(
            u64::try_from(handle).unwrap(),
            ObservationEntry {
                operation_handle: 1,
            },
        );
    }
    let error = registry
        .open_observation(1, AutomaticObservationClass::Database, None)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RuntimeQuota);
    assert_eq!(registry.observations.len(), MAX_OBSERVATION_SESSIONS);
}

#[test]
fn operation_cleanup_deletes_only_its_observation_sessions() {
    let mut observations = BTreeMap::from([
        (
            1,
            ObservationEntry {
                operation_handle: 10,
            },
        ),
        (
            2,
            ObservationEntry {
                operation_handle: 10,
            },
        ),
        (
            3,
            ObservationEntry {
                operation_handle: 20,
            },
        ),
    ]);
    remove_operation_observations(&mut observations, 10);
    assert_eq!(observations.len(), 1);
    assert!(observations.contains_key(&3));
}

#[test]
fn observation_read_call_is_present_before_replay_execution_exists() {
    let response = execute(
        json!({
            "format": CALL_FORMAT,
            "observation_handle": 1,
            "operation": "observation-read",
        })
        .to_string()
        .as_bytes(),
    );
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["error_code"], "NOT_FOUND");
    assert_eq!(value["ok"], false);
}

#[test]
fn engine_close_invalidates_only_its_owned_sink_handles() {
    let first = FailureTask::pending_for_test();
    let second = FailureTask::pending_for_test();
    let other = FailureTask::pending_for_test();
    let mut sinks = BTreeMap::from([
        (
            101,
            SinkEntry {
                engine_handle: 1,
                task: first.clone(),
            },
        ),
        (
            102,
            SinkEntry {
                engine_handle: 1,
                task: second.clone(),
            },
        ),
        (
            201,
            SinkEntry {
                engine_handle: 2,
                task: other.clone(),
            },
        ),
    ]);
    remove_engine_sinks(&mut sinks, 1);
    assert!(!sinks.contains_key(&101));
    assert!(!sinks.contains_key(&102));
    assert!(sinks.contains_key(&201));
    assert!(first.is_cancelled());
    assert!(second.is_cancelled());
    assert!(!other.is_cancelled());
}

#[test]
fn one_over_failure_capacity_removes_the_operation_without_a_sink() {
    let mut operations = BTreeMap::from([(17_u64, false)]);
    let sinks = (0..MAX_SINKS)
        .map(|handle| (u64::try_from(handle).unwrap(), false))
        .collect::<BTreeMap<_, _>>();
    let abandoned = Cell::new(false);

    let result = take_failure_operation(&mut operations, 17, sinks.len() >= MAX_SINKS, |_| {
        abandoned.set(true);
    });

    assert!(matches!(result, Err(error) if error.code == ErrorCode::RuntimeQuota));
    assert!(operations.is_empty());
    assert_eq!(sinks.len(), MAX_SINKS);
    assert!(!sinks.contains_key(&17));
    assert!(abandoned.get());
}

#[test]
fn malformed_failure_token_removes_and_abandons_the_operation() {
    let mut operations = BTreeMap::from([(23_u64, false)]);
    let sinks = BTreeMap::<u64, bool>::new();
    let abandoned = Cell::new(false);
    let operation = take_failure_operation(&mut operations, 23, false, |_| {
        panic!("the available failure operation must not be rejected");
    })
    .unwrap();

    let result = validate_failure_token(operation, "malformed project token".to_owned(), |_| {
        abandoned.set(true);
    });

    assert!(matches!(result, Err(error) if error.code == ErrorCode::SchemaInvalid));
    assert!(operations.is_empty());
    assert!(sinks.is_empty());
    assert!(abandoned.get());
}

#[test]
fn full_worker_queue_releases_the_moved_operation_and_sink_entry() {
    let registry = Mutex::new(Registry::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let task = FailureTask::pending_drop_probe(dropped.clone());
    registry.lock().unwrap().sinks.insert(
        29,
        SinkEntry {
            engine_handle: 3,
            task: task.clone(),
        },
    );

    reject_failure_enqueue(&registry, 29, &task);

    let registry = registry.lock().unwrap();
    assert!(registry.operations.is_empty());
    assert!(!registry.sinks.contains_key(&29));
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn blocked_sink_wait_does_not_block_contract_dispatch() {
    let registry = Arc::new(Mutex::new(Registry::new()));
    let task = FailureTask::pending_for_test();
    let (wait_started_sender, wait_started_receiver) = sync_channel(0);
    let release_wait = Arc::new((Mutex::new(false), Condvar::new()));
    let sink_release_wait = release_wait.clone();
    task.complete_for_test(Ok(ReadySink::new(move |_| {
        wait_started_sender.send(()).unwrap();
        let (released, changed) = &*sink_release_wait;
        let mut released = released.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        true
    })));
    registry.lock().unwrap().sinks.insert(
        7,
        SinkEntry {
            engine_handle: 1,
            task,
        },
    );

    let wait_registry = registry.clone();
    let waiter = thread::spawn(move || wait_for_sink(&wait_registry, 7, 1_000));
    wait_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let dispatch_registry = registry.clone();
    let (dispatch_sender, dispatch_receiver) = sync_channel(0);
    let dispatcher = thread::spawn(move || {
        let result = dispatch_call(
            &dispatch_registry,
            EngineCall::Contract {
                format: CALL_FORMAT.to_owned(),
            },
        );
        dispatch_sender.send(result).unwrap();
    });
    let dispatch = dispatch_receiver.recv_timeout(Duration::from_secs(1));
    let (released, changed) = &*release_wait;
    *released.lock().unwrap() = true;
    changed.notify_all();
    let wait_result = waiter.join().unwrap().unwrap();
    dispatcher.join().unwrap();

    assert!(dispatch.unwrap().unwrap().is_object());
    assert_eq!(wait_result["idle"], true);
}

#[test]
fn unknown_input_fails_without_echoing_input() {
    let secret = "do-not-return-this-value";
    let response = execute(
        format!(
            "{{\"format\":\"{CALL_FORMAT}\",\"operation\":\"unknown\",\"value\":\"{secret}\"}}"
        )
        .as_bytes(),
    );
    let text = String::from_utf8(response).unwrap();
    assert!(!text.contains(secret));
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["error_code"], "SCHEMA_INVALID");
    assert_eq!(value["ok"], false);
}

#[test]
fn exported_call_rejects_small_output_before_mutation() {
    let input = br#"{"format":"reproit.sdk-engine-call.v1","operation":"contract"}"#;
    let mut output = [0_u8; 32];
    // Safety: Both buffers are valid for the exact lengths supplied here.
    let result = unsafe {
        reproit_sdk_engine_call(
            input.as_ptr().cast(),
            input.len(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    assert_eq!(result, RESULT_INVALID_CALL_BOUNDARY);
}
