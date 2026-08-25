use reproit_core::{
    crypto::encode_base64url,
    identity::Digest,
    model::{
        Deployment, DeploymentFormat, ExceptionCategory, ExceptionFailureIdentity, FailureFrame,
        FailureIdentity, FailurePayload, FailurePayloadFormat, FailureReference, InputChannel,
        OperationBeginFormat, OperationBeginPayload, OperationInputFormat, OperationInputPayload,
        OperationKind, ProcessingMode, Subject, SubjectFormat,
    },
};
use reproit_sdk_rust::CandidateStart;

pub struct SdkFixture {
    pub begin: OperationBeginPayload,
    pub failure: FailurePayload,
    pub input: OperationInputPayload,
    pub start: CandidateStart,
}

pub fn fixture() -> SdkFixture {
    let identity = FailureIdentity::Exception(ExceptionFailureIdentity {
        category: ExceptionCategory::Exception,
        cause_types: Vec::new(),
        frames: vec![FailureFrame {
            function: "orders::increment".to_owned(),
            module: "orders".to_owned(),
            source: "src/orders.rs".to_owned(),
        }],
        operation_kind: OperationKind::RequestResponse,
        operation_name: "orders.increment".to_owned(),
        runtime_family: "rust".to_owned(),
        schema: "reproit.failure.v1".to_owned(),
        stable_code: None,
        type_name: "CounterInvariant".to_owned(),
    });
    let grouping = identity.grouping().expect("valid failure identity");
    let failure = FailurePayload {
        failure: FailureReference {
            category: grouping.category,
            identity: grouping.identity_digest,
            matcher: grouping.matcher,
            object_id: parse("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab7"),
            schema: "reproit.failure.v1".to_owned(),
        },
        format: FailurePayloadFormat::V1,
        identity,
    };
    let input_bytes = br#"{"amount":10}"#;
    SdkFixture {
        begin: OperationBeginPayload {
            adapter_id: "axum".to_owned(),
            adapter_version: "0.8.9".to_owned(),
            causal_parent_ids: Vec::new(),
            format: OperationBeginFormat::V1,
            operation_kind: OperationKind::RequestResponse,
            operation_name: "orders.increment".to_owned(),
        },
        failure,
        input: OperationInputPayload {
            channel: InputChannel::Input,
            content_type: "application/json".to_owned(),
            format: OperationInputFormat::V1,
            input_index: 0,
            value: encode_base64url(input_bytes),
            value_digest: Digest::of(input_bytes),
        },
        start: CandidateStart {
            capture_id: parse("cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"),
            deployment: deployment(),
            operation_id: parse("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1"),
            world_id: parse(
                "sha256:511ba2cbf45d169467aa44bc51b8f290f598f528df082fc2d6956666a2100084",
            ),
        },
    }
}

fn deployment() -> Deployment {
    Deployment {
        format: DeploymentFormat::V1,
        organization_id: parse("org_01890f3e-7b1c-7cc0-8a1b-123456789abd"),
        processing_mode: ProcessingMode::Private,
        project_id: parse("prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"),
        repository_id: "source.example/acme/commerce".to_owned(),
        runtime_capabilities: vec![
            "architecture.native".to_owned(),
            "operating-system.linux".to_owned(),
            "runtime.rust-native".to_owned(),
        ],
        runtime_endpoint: "https://runtime.customer.example".to_owned(),
        service_id: parse("svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"),
        service_path: "services/orders".to_owned(),
        signature: encode_base64url(&[0_u8; 64]),
        signed_at: parse("2026-01-01T00:00:00.000Z"),
        signer_key_id: "customer-deployment-test".to_owned(),
        source_revision: "0123456789abcdef".to_owned(),
        subject: Subject {
            architecture: "architecture.native".to_owned(),
            arguments: Vec::new(),
            artifact_digest: parse(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            ),
            artifact_media_type: "application/vnd.reproit.native-executable.v1".to_owned(),
            artifact_uri: concat!(
                "oci://customer.example/orders@sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111"
            )
            .to_owned(),
            environment_names: vec!["RUST_LOG".to_owned()],
            executable: "/reproit/subject/orders".to_owned(),
            format: SubjectFormat::V1,
            operating_system: "operating-system.linux".to_owned(),
            working_directory: "/reproit/subject".to_owned(),
        },
    }
}

fn parse<T: std::str::FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().expect("valid fixture value")
}
