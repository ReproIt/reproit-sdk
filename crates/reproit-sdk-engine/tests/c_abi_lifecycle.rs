#![cfg(target_os = "linux")]

use reproit_core::{
    crypto::encode_base64url,
    identity::Digest,
    model::{
        InputChannel, OperationBeginFormat, OperationBeginPayload, OperationInputFormat,
        OperationInputPayload, OperationKind,
    },
};
use reproit_sdk_engine::reproit_sdk_engine_call;
use reproit_sdk_rust::package_running_rust_subject;
use serde_json::{Value, json};

const CALL_FORMAT: &str = "reproit.sdk-engine-call.v1";
const RESPONSE_CAPACITY: usize = 16_384;
const MAX_CALL_BYTES: usize = 1_048_576;
const MAX_OBSERVATION_CHUNK_BYTES: usize = 32 * 1_024;
const PROJECT: &str = r#"
format = 1
organization_id = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
profile = "backend"
profile_format = 1
processing_mode = "managed"
project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
repository_id = "source.example/acme/commerce"
sdk = "rust"
service_id = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
service_path = "services/orders"

[run]
arguments = ["serve"]
program = "orders"
working_directory = "services/orders"

[source]
remote = "origin"
"#;

#[test]
fn c_abi_runs_the_complete_local_non_failure_lifecycle() {
    if include_str!("../../reproit-sdk-rust/src/official_managed.rs")
        .contains("__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__")
    {
        return;
    }

    let package = package_running_rust_subject().unwrap();
    let adapter_implementation_digest = package
        .manifest
        .modules
        .iter()
        .find(|module| module.path == package.manifest.launch.executable)
        .expect("the running executable must be a frozen subject module")
        .module_digest;
    let subject_objects = package
        .objects
        .iter()
        .map(|object| {
            json!({
                "digest": object.digest,
                "path": object.path,
                "size": object.size,
            })
        })
        .collect::<Vec<_>>();
    let open = call(json!({
        "build_repository_id": "source.example/acme/commerce",
        "format": CALL_FORMAT,
        "observation_adapters": observation_adapters(adapter_implementation_digest),
        "operation": "engine-open",
        "project_toml": PROJECT,
        "sdk": "rust",
        "source_revision": "0123456789abcdef0123456789abcdef01234567",
        "subject_manifest": package.manifest,
        "subject_objects": subject_objects,
    }));
    assert_ok(&open);
    let engine_handle = open["result"]["engine_handle"].as_u64().unwrap();

    let operation_handle = begin(engine_handle);
    let input_bytes = br#"{"amount":10}"#;
    let input = OperationInputPayload {
        channel: InputChannel::Input,
        content_type: "application/json".to_owned(),
        format: OperationInputFormat::V1,
        input_index: 0,
        value: encode_base64url(input_bytes),
        value_digest: Digest::of(input_bytes),
    };
    assert_ok(&call(json!({
        "format": CALL_FORMAT,
        "input": input,
        "operation": "operation-input",
        "operation_handle": operation_handle,
    })));

    for class in ["clock", "environment", "filesystem", "randomness"] {
        capture_observation(operation_handle, class);
    }
    for class in ["database", "outbound-http", "queue"] {
        capture_dependency(operation_handle, class);
    }
    assert_ok(&call(json!({
        "format": CALL_FORMAT,
        "operation": "operation-succeed",
        "operation_handle": operation_handle,
    })));

    let abandoned = begin(engine_handle);
    assert_ok(&call(json!({
        "format": CALL_FORMAT,
        "operation": "operation-abandon",
        "operation_handle": abandoned,
    })));

    let oversized = call(json!({
        "chunk": encode_base64url(&vec![0_u8; MAX_OBSERVATION_CHUNK_BYTES + 1]),
        "format": CALL_FORMAT,
        "observation_handle": 1,
        "operation": "observation-write",
        "stream": "request",
    }));
    assert_eq!(oversized["error_code"], "RUNTIME_QUOTA");
    assert_eq!(oversized["ok"], false);

    assert_ok(&call(json!({
        "engine_handle": engine_handle,
        "format": CALL_FORMAT,
        "operation": "engine-close",
    })));
    bounded_native_errors_do_not_write_output();
    schema_errors_do_not_echo_input();
}

fn capture_observation(operation_handle: u64, class: &str) {
    let open = call(json!({
        "causal_parent_id": null,
        "class": class,
        "format": CALL_FORMAT,
        "operation": "observation-open",
        "operation_handle": operation_handle,
    }));
    assert_ok(&open);
    let observation_handle = open["result"]["observation_handle"].as_u64().unwrap();
    let session_position = open["result"]["session_position"].as_u64().unwrap();
    for (stream, chunk) in [("request", "request"), ("response", "response")] {
        if stream == "response" {
            let dispatch = call(json!({
                "format": CALL_FORMAT,
                "observation_handle": observation_handle,
                "operation": "observation-dispatch",
            }));
            assert_ok(&dispatch);
            assert_eq!(dispatch["result"]["action"], "capture");
        }
        assert_ok(&call(json!({
            "chunk": encode_base64url(format!("{class}-{chunk}").as_bytes()),
            "format": CALL_FORMAT,
            "observation_handle": observation_handle,
            "operation": "observation-write",
            "stream": stream,
        })));
    }
    assert_ok(&call(json!({
        "format": CALL_FORMAT,
        "observation_handle": observation_handle,
        "operation": "observation-finish",
        "outcome": "response",
        "session_position": session_position,
    })));
}

fn capture_dependency(operation_handle: u64, class: &str) {
    let (operation, method) = match class {
        "database" => ("database-execute", None),
        "outbound-http" => ("outbound-http-request", Some("POST")),
        "queue" => ("queue-publish", None),
        _ => panic!("unsupported dependency class"),
    };
    let open = call(json!({
        "causal_parent_id": null,
        "format": CALL_FORMAT,
        "operation": "dependency-open",
        "operation_handle": operation_handle,
        "request": {
            "encoding": "bytes",
            "metadata": [],
            "method": method,
            "observation_class": class,
            "operation": operation,
            "payload": encode_base64url(format!("{class}-request").as_bytes()),
            "protocol": "test-protocol",
            "target": encode_base64url(format!("{class}-target").as_bytes()),
        },
    }));
    assert_ok(&open);
    assert_eq!(open["result"]["action"], "capture");
    let dependency_handle = open["result"]["dependency_handle"].as_u64().unwrap();
    let response = call(json!({
        "dependency_handle": dependency_handle,
        "format": CALL_FORMAT,
        "operation": "dependency-finish",
        "response": {
            "error_code": null,
            "error_number": null,
            "metadata": [],
            "outcome": "response",
            "payload": encode_base64url(format!("{class}-response").as_bytes()),
            "status": null,
            "status_code": (class == "outbound-http").then_some(200),
        },
    }));
    assert_ok(&response);
    assert_eq!(response["result"]["outcome"], "response");
}

fn observation_adapters(implementation_digest: Digest) -> Vec<Value> {
    [
        "clock",
        "database",
        "environment",
        "filesystem",
        "outbound-http",
        "queue",
        "randomness",
    ]
    .into_iter()
    .map(|class| {
        json!({
            "adapter_id": "c-abi-semantic-hook",
            "adapter_version": "1.0.0",
            "class": class,
            "implementation_digest": implementation_digest,
        })
    })
    .collect()
}

fn begin(engine_handle: u64) -> u64 {
    let begin = OperationBeginPayload {
        adapter_id: "c-abi-test".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        campaign_context: None,
        causal_parent_ids: Vec::new(),
        format: OperationBeginFormat::V1,
        operation_kind: OperationKind::RequestResponse,
        operation_name: "orders.increment".to_owned(),
    };
    let response = call(json!({
        "begin": begin,
        "engine_handle": engine_handle,
        "format": CALL_FORMAT,
        "operation": "operation-begin",
    }));
    assert_ok(&response);
    response["result"]["operation_handle"].as_u64().unwrap()
}

fn call(request: Value) -> Value {
    let input = serde_json::to_vec(&request).unwrap();
    assert!(input.len() <= MAX_CALL_BYTES);
    let mut output = vec![0_u8; RESPONSE_CAPACITY];
    // Safety: Both buffers are valid for the exact lengths supplied here.
    let written = unsafe {
        reproit_sdk_engine_call(
            input.as_ptr().cast(),
            input.len(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    assert!(written > 0);
    serde_json::from_slice(&output[..written as usize]).unwrap()
}

fn assert_ok(response: &Value) {
    assert_eq!(response["format"], "reproit.sdk-engine-response.v1");
    assert_eq!(response["ok"], true);
}

fn bounded_native_errors_do_not_write_output() {
    let input = br#"{"format":"reproit.sdk-engine-call.v1","operation":"contract"}"#;
    let mut output = [0xA5_u8; 32];
    // Safety: Both buffers are valid for the exact lengths supplied here.
    let result = unsafe {
        reproit_sdk_engine_call(
            input.as_ptr().cast(),
            input.len(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(output, [0xA5_u8; 32]);
}

fn schema_errors_do_not_echo_input() {
    let secret = "do-not-echo-this-value";
    let response = call(json!({
        "format": CALL_FORMAT,
        "operation": "unknown",
        "value": secret,
    }));
    assert_eq!(response["error_code"], "SCHEMA_INVALID");
    assert_eq!(response["ok"], false);
    assert!(!response.to_string().contains(secret));
}
