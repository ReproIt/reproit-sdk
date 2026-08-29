use std::{collections::BTreeMap, str::FromStr};

use reproit_core::{
    canonical,
    crypto::{encode_base64url, secret_key, sign_bytes, verification_key},
    identity::{OperationId, ProjectId, Timestamp},
    model::{FuzzContext, FuzzContextFormat},
};
use reproit_sdk_rust::{
    FUZZ_CONTEXT_HTTP_HEADER, FUZZ_CONTEXT_QUEUE_METADATA, FUZZ_PARENT_HTTP_HEADER,
    FUZZ_PARENT_QUEUE_METADATA, FuzzCampaignContext, FuzzContextValidator,
    SignedFuzzContextValidator, inbound_queue_fuzz_context,
};

#[tokio::test]
async fn signed_context_is_active_and_propagates_over_http_and_queue() {
    let signing_key = secret_key([9_u8; 32]);
    let encoded = signed_context(&signing_key);
    let validator = SignedFuzzContextValidator::new(
        verification_key(&signing_key),
        ProjectId::from_str("prj_01890f3e-7b1e-7cc0-8a1b-123456789abc").expect("project ID"),
        || Timestamp::from_str("2026-08-29T00:00:00.000Z"),
    );
    let parent =
        OperationId::from_str("op_01890f3e-7b20-7cc0-8a1b-123456789abc").expect("operation ID");
    let context = validator
        .validate(&encoded)
        .expect("valid context")
        .with_parent(parent);

    context
        .scope(async {
            let current = FuzzCampaignContext::current().expect("active context");
            let http = current.outbound_http_fields();
            let queue = current.outbound_queue_metadata();
            assert_eq!(http[0], (FUZZ_CONTEXT_HTTP_HEADER, encoded.clone()));
            assert_eq!(http[1], (FUZZ_PARENT_HTTP_HEADER, parent.to_string()));
            assert_eq!(queue[0], (FUZZ_CONTEXT_QUEUE_METADATA, encoded.clone()));
            assert_eq!(queue[1], (FUZZ_PARENT_QUEUE_METADATA, parent.to_string()));
        })
        .await;
    assert!(FuzzCampaignContext::current().is_err());
}

#[test]
fn queue_inbound_extracts_context_and_rejects_an_orphan_parent() {
    let signing_key = secret_key([9_u8; 32]);
    let encoded = signed_context(&signing_key);
    let validator = SignedFuzzContextValidator::new(
        verification_key(&signing_key),
        ProjectId::from_str("prj_01890f3e-7b1e-7cc0-8a1b-123456789abc").expect("project ID"),
        || Timestamp::from_str("2026-08-29T00:00:00.000Z"),
    );
    let parent = "op_01890f3e-7b20-7cc0-8a1b-123456789abc";
    let mut metadata = BTreeMap::from([
        (FUZZ_CONTEXT_QUEUE_METADATA.to_owned(), encoded),
        (FUZZ_PARENT_QUEUE_METADATA.to_owned(), parent.to_owned()),
    ]);
    let context = inbound_queue_fuzz_context(&metadata, Some(&validator))
        .expect("valid queue context")
        .expect("present queue context");
    assert_eq!(
        context.parent_operation_id().expect("parent").to_string(),
        parent
    );

    metadata.remove(FUZZ_CONTEXT_QUEUE_METADATA);
    assert!(inbound_queue_fuzz_context(&metadata, Some(&validator)).is_err());
}

#[test]
fn invalid_signature_scope_and_expiry_never_activate() {
    let signing_key = secret_key([9_u8; 32]);
    let encoded = signed_context(&signing_key);
    let wrong_key = verification_key(&secret_key([8_u8; 32]));
    let validator = SignedFuzzContextValidator::new(
        wrong_key,
        ProjectId::from_str("prj_01890f3e-7b1e-7cc0-8a1b-123456789abc").expect("project ID"),
        || Timestamp::from_str("2026-08-31T00:00:00.000Z"),
    );
    assert!(validator.validate(&encoded).is_err());
    assert!(FuzzCampaignContext::current().is_err());
}

fn signed_context(signing_key: &reproit_core::crypto::SecretKey) -> String {
    let mut context = FuzzContext {
        campaign_id: "fc_01890f3e-7b1c-7cc0-8a1b-123456789abc"
            .parse()
            .expect("campaign ID"),
        case_id: "case_01890f3e-7b1d-7cc0-8a1b-123456789abc"
            .parse()
            .expect("case ID"),
        expires_at: Timestamp::from_str("2026-08-30T00:00:00.000Z").expect("timestamp"),
        format: FuzzContextFormat::V1,
        project_id: "prj_01890f3e-7b1e-7cc0-8a1b-123456789abc"
            .parse()
            .expect("project ID"),
        service_id: "svc_01890f3e-7b1f-7cc0-8a1b-123456789abc"
            .parse()
            .expect("service ID"),
        signature: String::new(),
    };
    context.signature = sign_bytes(
        &canonical::canonical_bytes(&context).expect("unsigned context"),
        signing_key,
    );
    encode_base64url(&canonical::canonical_bytes(&context).expect("signed context"))
}
