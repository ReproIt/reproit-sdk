use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use reproit_core::{
    Error, canonical,
    crypto::decode_base64url_bytes,
    identity::{OperationId, ProjectId, Timestamp},
    model::{FuzzContext, FuzzContextIdentity, fuzz_context_digest, verify_fuzz_context},
};

pub const FUZZ_CONTEXT_HTTP_HEADER: &str = "ReproIt-Fuzz-Context";
pub const FUZZ_PARENT_HTTP_HEADER: &str = "ReproIt-Parent-Operation";
pub const FUZZ_CONTEXT_QUEUE_METADATA: &str = "reproit.fuzz.context";
pub const FUZZ_PARENT_QUEUE_METADATA: &str = "reproit.parent.operation";
const MAX_CONTEXT_BYTES: usize = 4_096;
const MAX_CONTEXT_DEPTH: usize = 16;

std::thread_local! {
    static ACTIVE_FUZZ_CONTEXT: RefCell<Vec<FuzzCampaignContext>> = const { RefCell::new(Vec::new()) };
}

pub trait FuzzContextValidator: Send + Sync {
    fn validate(&self, encoded: &str) -> Result<FuzzCampaignContext, Error>;
}

pub fn inbound_fuzz_context(
    encoded_context: Option<&str>,
    parent_operation: Option<&str>,
    validator: Option<&dyn FuzzContextValidator>,
) -> Result<Option<FuzzCampaignContext>, Error> {
    let Some(encoded_context) = encoded_context else {
        if parent_operation.is_some() {
            return Err(Error::schema_invalid());
        }
        return Ok(None);
    };
    let validator = validator.ok_or_else(Error::schema_invalid)?;
    let mut context = validator.validate(encoded_context)?;
    if let Some(parent_operation) = parent_operation {
        context = context.with_parent(parent_operation.parse()?);
    }
    Ok(Some(context))
}

pub fn inbound_queue_fuzz_context(
    metadata: &BTreeMap<String, String>,
    validator: Option<&dyn FuzzContextValidator>,
) -> Result<Option<FuzzCampaignContext>, Error> {
    inbound_fuzz_context(
        metadata
            .get(FUZZ_CONTEXT_QUEUE_METADATA)
            .map(String::as_str),
        metadata.get(FUZZ_PARENT_QUEUE_METADATA).map(String::as_str),
        validator,
    )
}

pub struct SignedFuzzContextValidator<C>
where
    C: Fn() -> Result<Timestamp, Error> + Send + Sync,
{
    clock: C,
    project_id: ProjectId,
    verification_key: [u8; 32],
}

impl<C> SignedFuzzContextValidator<C>
where
    C: Fn() -> Result<Timestamp, Error> + Send + Sync,
{
    pub const fn new(verification_key: [u8; 32], project_id: ProjectId, clock: C) -> Self {
        Self {
            clock,
            project_id,
            verification_key,
        }
    }
}

impl<C> FuzzContextValidator for SignedFuzzContextValidator<C>
where
    C: Fn() -> Result<Timestamp, Error> + Send + Sync,
{
    fn validate(&self, encoded: &str) -> Result<FuzzCampaignContext, Error> {
        let bytes = decode_base64url_bytes(encoded)?;
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(Error::schema_invalid());
        }
        let context: FuzzContext = canonical::parse_strict(&bytes)?;
        if canonical::canonical_bytes(&context)? != bytes {
            return Err(Error::schema_invalid());
        }
        verify_fuzz_context(
            &context,
            &self.verification_key,
            self.project_id,
            context.service_id,
            &(self.clock)()?,
        )?;
        FuzzCampaignContext::from_verified(encoded.to_owned(), &context, None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuzzCampaignContext {
    context: Arc<FuzzContext>,
    identity: FuzzContextIdentity,
    parent_operation_id: Option<OperationId>,
    signed_context: Arc<str>,
}

impl FuzzCampaignContext {
    pub fn from_verified(
        signed_context: String,
        context: &FuzzContext,
        parent_operation_id: Option<OperationId>,
    ) -> Result<Self, Error> {
        if signed_context.is_empty()
            || signed_context.len() > 5_462
            || signed_context
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        {
            return Err(Error::schema_invalid());
        }
        Ok(Self {
            context: Arc::new(context.clone()),
            identity: FuzzContextIdentity {
                campaign_id: context.campaign_id,
                case_id: context.case_id,
                context_digest: fuzz_context_digest(context)?,
            },
            parent_operation_id,
            signed_context: Arc::from(signed_context),
        })
    }

    pub const fn identity(&self) -> &FuzzContextIdentity {
        &self.identity
    }

    pub fn context(&self) -> &FuzzContext {
        &self.context
    }

    pub const fn parent_operation_id(&self) -> Option<OperationId> {
        self.parent_operation_id
    }

    #[must_use]
    pub fn with_parent(&self, parent_operation_id: OperationId) -> Self {
        let mut child = self.clone();
        child.parent_operation_id = Some(parent_operation_id);
        child
    }

    pub fn signed_context(&self) -> &str {
        &self.signed_context
    }

    pub fn current() -> Result<Self, Error> {
        ACTIVE_FUZZ_CONTEXT
            .try_with(|contexts| contexts.borrow().last().cloned())
            .ok()
            .flatten()
            .ok_or_else(Error::schema_invalid)
    }

    pub fn outbound_http_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![(FUZZ_CONTEXT_HTTP_HEADER, self.signed_context().to_owned())];
        if let Some(parent_operation_id) = self.parent_operation_id {
            fields.push((FUZZ_PARENT_HTTP_HEADER, parent_operation_id.to_string()));
        }
        fields
    }

    pub fn outbound_queue_metadata(&self) -> Vec<(&'static str, String)> {
        let mut metadata = vec![(
            FUZZ_CONTEXT_QUEUE_METADATA,
            self.signed_context().to_owned(),
        )];
        if let Some(parent_operation_id) = self.parent_operation_id {
            metadata.push((FUZZ_PARENT_QUEUE_METADATA, parent_operation_id.to_string()));
        }
        metadata
    }

    pub fn scope_sync<T>(&self, operation: impl FnOnce() -> T) -> T {
        let Some(_guard) = FuzzContextGuard::install(self.clone()) else {
            return operation();
        };
        operation()
    }

    #[must_use = "A scoped future does nothing until it is polled."]
    pub fn scope<F>(&self, future: F) -> FuzzContextScope<F>
    where
        F: Future,
    {
        FuzzContextScope {
            context: self.clone(),
            future: Box::pin(future),
        }
    }
}

pub struct FuzzContextScope<F>
where
    F: Future,
{
    context: FuzzCampaignContext,
    future: Pin<Box<F>>,
}

impl<F> Future for FuzzContextScope<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task_context: &mut Context<'_>) -> Poll<Self::Output> {
        let scope = self.get_mut();
        let Some(_guard) = FuzzContextGuard::install(scope.context.clone()) else {
            return scope.future.as_mut().poll(task_context);
        };
        scope.future.as_mut().poll(task_context)
    }
}

struct FuzzContextGuard;

impl FuzzContextGuard {
    fn install(context: FuzzCampaignContext) -> Option<Self> {
        ACTIVE_FUZZ_CONTEXT
            .try_with(|contexts| {
                let mut contexts = contexts.borrow_mut();
                if contexts.len() >= MAX_CONTEXT_DEPTH {
                    return false;
                }
                contexts.push(context);
                true
            })
            .ok()
            .filter(|installed| *installed)
            .map(|_| Self)
    }
}

impl Drop for FuzzContextGuard {
    fn drop(&mut self) {
        let _ = ACTIVE_FUZZ_CONTEXT.try_with(|contexts| contexts.borrow_mut().pop());
    }
}
