use std::sync::Arc;

use reproit_sdk_rust::{
    Error, ExactResponseFailureClassifier, OperationBeginPayload, RequestResponseFailureClassifier,
    RequestResponseHead, RequestResponseHeader, RequestResponseOperation,
    ResponseFailureClassification, RustOperation, RustOperationFactory,
};

fn accept_factory(_factory: &dyn RustOperationFactory) {}

fn accept_operation(_operation: Box<dyn RustOperation>) {}

fn start_request_response(
    factory: &dyn RustOperationFactory,
    begin: &OperationBeginPayload,
    classifier: Arc<dyn RequestResponseFailureClassifier>,
) -> Result<RequestResponseOperation, Error> {
    RequestResponseOperation::start(factory, begin, "application/octet-stream", classifier)
}

fn start_classification(
    classifier: &dyn RequestResponseFailureClassifier,
    response: &RequestResponseHead<'_>,
) -> Box<dyn ResponseFailureClassification> {
    classifier.start(response)
}

fn accept_header(_header: RequestResponseHeader) {}

fn assert_send<T: Send>() {}

#[test]
fn framework_adapter_spi_is_public_and_object_safe() {
    let _: fn(&dyn RustOperationFactory) = accept_factory;
    let _: fn(Box<dyn RustOperation>) = accept_operation;
    let _ = start_request_response;
    let _ = start_classification;
    let _: fn(RequestResponseHeader) = accept_header;
    assert_send::<ExactResponseFailureClassifier>();
    assert_send::<RequestResponseOperation>();
}
