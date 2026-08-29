use std::ffi::c_void;

use reproit_sdk_engine::{
    reproit_sdk_engine_abi_version, reproit_sdk_engine_call, reproit_sdk_engine_capture_probe,
};
use serde_json::{Value, json};

const ABI_CONTRACT: &str = include_str!("../sdk-engine-abi.json");
const OUTPUT_CAPACITY_BYTES: usize = 16_384;

#[test]
fn exported_engine_matches_the_canonical_abi_contract() {
    let contract: Value = serde_json::from_str(ABI_CONTRACT).unwrap();
    assert_eq!(
        reproit_sdk_engine_abi_version(),
        u32::try_from(contract["abi_version"].as_u64().unwrap()).unwrap()
    );

    let input = json!({
        "format": contract["request"]["format"],
        "operation": "contract",
    });
    let input = serde_json::to_vec(&input).unwrap();
    let mut output = vec![0_u8; OUTPUT_CAPACITY_BYTES];
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
    let response: Value = serde_json::from_slice(&output[..written as usize]).unwrap();
    assert_eq!(response["result"], contract);

    let _: extern "C" fn() -> u32 = reproit_sdk_engine_abi_version;
    let _: extern "C" fn() -> u32 = reproit_sdk_engine_capture_probe;
    let _: unsafe extern "C" fn(*const c_void, usize, *mut c_void, usize) -> isize =
        reproit_sdk_engine_call;
}

#[test]
fn canonical_lists_are_ordered_and_unique() {
    let contract: Value = serde_json::from_str(ABI_CONTRACT).unwrap();
    let operations = contract["operations"].as_array().unwrap();
    let names = operations
        .iter()
        .map(|operation| operation.as_str().unwrap())
        .collect::<Vec<_>>();
    let mut ordered = names.clone();
    ordered.sort_unstable();
    ordered.dedup();
    assert_eq!(names, ordered);

    let libraries = contract["libraries"].as_array().unwrap();
    let platforms = libraries
        .iter()
        .map(|library| library["platform"].as_str().unwrap())
        .collect::<Vec<_>>();
    let mut ordered = platforms.clone();
    ordered.sort_unstable();
    ordered.dedup();
    assert_eq!(platforms, ordered);
    assert_eq!(
        contract["libraries"],
        json!([
            {
                "name": "libreproit_sdk_engine.so",
                "platform": "linux-arm64",
            },
            {
                "name": "libreproit_sdk_engine.so",
                "platform": "linux-x86_64",
            },
            {
                "name": "libreproit_sdk_engine.dylib",
                "platform": "macos-arm64",
            },
            {
                "name": "reproit_sdk_engine.dll",
                "platform": "windows-x86_64",
            },
        ])
    );
}
