use std::sync::Arc;

use reproit_core::{
    Error, ErrorCode,
    crypto::encode_base64url,
    identity::{Digest, OperationId},
    model::{
        FailureIdentity, InputChannel, OperationBeginPayload, OperationInputFormat,
        OperationInputPayload, OperationKind, TriggerCompletion,
    },
};

use crate::{AutomaticOperationContext, RustOperation, RustOperationFactory};

pub const MAX_REQUEST_INPUT_CHUNK_BYTES: usize = 32 * 1_024;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1_024;
pub const MAX_RESPONSE_HEADERS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestResponseHeader {
    pub name: String,
    pub value: Vec<u8>,
}

pub struct RequestResponseHead<'a> {
    headers: &'a [RequestResponseHeader],
    status: u16,
}

impl RequestResponseHead<'_> {
    #[must_use]
    pub const fn headers(&self) -> &[RequestResponseHeader] {
        self.headers
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
}

pub trait ResponseFailureClassification: Send {
    fn record_body_chunk(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn finish(self: Box<Self>) -> Option<FailureIdentity>;
}

pub trait RequestResponseFailureClassifier: Send + Sync + 'static {
    fn start(&self, response: &RequestResponseHead<'_>) -> Box<dyn ResponseFailureClassification>;
}

pub struct ExactResponseFailureClassifier {
    body: Arc<[u8]>,
    failure: FailureIdentity,
    status: u16,
}

impl ExactResponseFailureClassifier {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, failure: FailureIdentity) -> Self {
        Self {
            body: body.into(),
            failure,
            status,
        }
    }
}

impl RequestResponseFailureClassifier for ExactResponseFailureClassifier {
    fn start(&self, response: &RequestResponseHead<'_>) -> Box<dyn ResponseFailureClassification> {
        Box::new(ExactResponseFailureClassification {
            expected: self.body.clone(),
            failure: (response.status() == self.status).then(|| self.failure.clone()),
            matched_bytes: 0,
        })
    }
}

struct ExactResponseFailureClassification {
    expected: Arc<[u8]>,
    failure: Option<FailureIdentity>,
    matched_bytes: usize,
}

impl ResponseFailureClassification for ExactResponseFailureClassification {
    fn record_body_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let Some(end) = self.matched_bytes.checked_add(bytes.len()) else {
            self.failure = None;
            return Ok(());
        };
        if self
            .expected
            .get(self.matched_bytes..end)
            .is_none_or(|expected| expected != bytes)
        {
            self.failure = None;
        }
        self.matched_bytes = end;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Option<FailureIdentity> {
        if self.matched_bytes == self.expected.len() {
            self.failure
        } else {
            None
        }
    }
}

pub struct RequestResponseOperation {
    classification: Option<Box<dyn ResponseFailureClassification>>,
    classifier: Arc<dyn RequestResponseFailureClassifier>,
    content_type: String,
    input_complete: bool,
    input_count: u16,
    operation: Option<Box<dyn RustOperation>>,
}

impl RequestResponseOperation {
    pub fn start(
        factory: &dyn RustOperationFactory,
        begin: &OperationBeginPayload,
        content_type: &str,
        classifier: Arc<dyn RequestResponseFailureClassifier>,
    ) -> Result<Self, Error> {
        if begin.operation_kind != OperationKind::RequestResponse
            || content_type.is_empty()
            || content_type.len() > 128
        {
            return Err(Error::schema_invalid());
        }
        Ok(Self {
            classification: None,
            classifier,
            content_type: content_type.to_owned(),
            input_complete: false,
            input_count: 0,
            operation: Some(factory.start(begin)?),
        })
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<OperationId> {
        self.operation
            .as_ref()
            .map(|operation| operation.operation_id())
    }

    #[doc(hidden)]
    #[must_use]
    pub fn automatic_context(&self) -> Option<AutomaticOperationContext> {
        self.operation
            .as_ref()
            .and_then(|operation| operation.automatic_context())
    }

    pub fn record_input_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.input_complete || self.operation.is_none() {
            return Err(incomplete_operation());
        }
        for chunk in bytes.chunks(MAX_REQUEST_INPUT_CHUNK_BYTES) {
            self.record_input_record(chunk)?;
        }
        Ok(())
    }

    pub fn finish_input(&mut self) -> Result<(), Error> {
        if self.input_complete || self.operation.is_none() {
            self.abandon();
            return Err(incomplete_operation());
        }
        if self.input_count == 0 {
            self.record_input_record(&[])?;
        }
        self.input_complete = true;
        Ok(())
    }

    #[must_use]
    pub const fn input_complete(&self) -> bool {
        self.input_complete
    }

    pub fn begin_response(
        &mut self,
        status: u16,
        headers: impl IntoIterator<Item = RequestResponseHeader>,
    ) -> Result<(), Error> {
        if !self.input_complete || self.classification.is_some() || self.operation.is_none() {
            self.abandon();
            return Err(incomplete_operation());
        }
        let mut captured = Vec::new();
        let mut bytes = 0_usize;
        for header in headers {
            if captured.len() >= MAX_RESPONSE_HEADERS || header.name.is_empty() {
                self.abandon();
                return Err(capture_limit());
            }
            let Some(next_bytes) = bytes
                .checked_add(header.name.len())
                .and_then(|total| total.checked_add(header.value.len()))
            else {
                self.abandon();
                return Err(capture_limit());
            };
            bytes = next_bytes;
            if bytes > MAX_RESPONSE_HEADER_BYTES {
                self.abandon();
                return Err(capture_limit());
            }
            captured.push(header);
        }
        self.classification = Some(self.classifier.start(&RequestResponseHead {
            headers: &captured,
            status,
        }));
        Ok(())
    }

    pub fn record_response_chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let Some(classification) = self.classification.as_mut() else {
            return Err(incomplete_operation());
        };
        if let Err(error) = classification.record_body_chunk(bytes) {
            self.abandon();
            return Err(error);
        }
        Ok(())
    }

    pub fn finish_response(&mut self) -> Result<(), Error> {
        let classification = self
            .classification
            .take()
            .ok_or_else(incomplete_operation)?;
        let operation = self.operation.take().ok_or_else(incomplete_operation)?;
        if let Some(identity) = classification.finish() {
            operation.fail(identity, TriggerCompletion::Return)
        } else {
            operation.succeed();
            Ok(())
        }
    }

    pub fn abandon(&mut self) {
        self.classification = None;
        if let Some(operation) = self.operation.take() {
            operation.abandon_incomplete();
        }
    }

    fn record_input_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.input_count > 1_023 {
            self.abandon();
            return Err(capture_limit());
        }
        let payload = OperationInputPayload {
            channel: InputChannel::Input,
            content_type: self.content_type.clone(),
            format: OperationInputFormat::V1,
            input_index: self.input_count,
            value: encode_base64url(bytes),
            value_digest: Digest::of(bytes),
        };
        if let Err(error) = self
            .operation
            .as_ref()
            .ok_or_else(incomplete_operation)?
            .record_input(&payload)
        {
            self.abandon();
            return Err(error);
        }
        self.input_count += 1;
        Ok(())
    }
}

impl Drop for RequestResponseOperation {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn capture_limit() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The request-response capture limit was reached.",
    )
}

fn incomplete_operation() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The request-response capture is incomplete.",
    )
}
