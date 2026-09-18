use std::{fs::File, io::Read as _, path::Path, sync::Arc};

use reproit_backend::automatic_replay::{AutomaticReplay, resolve_automatic_replay};
use reproit_core::{
    Error, ErrorCode, canonical,
    identity::OperationId,
    model::{LogicalObject, ReplayCapsule, resolve_replay_capsule},
};
use reproit_sdk_sentinel::{self as native_sentinel, OperationCoverage};
use uuid::Uuid;

use crate::{
    automatic_context::{AutomaticOperationContext, AutomaticOperationShared},
    automatic_engine::{NativeSentinelLease, next_native_operation_handle},
    automatic_world::AutomaticWorldCoordinator,
};

/// Replay one captured operation through the existing semantic observation APIs.
/// Finish the operation before reporting a reproduced Failure or a passing check.
pub struct AutomaticReplayOperation {
    operation_id: OperationId,
    shared: Arc<AutomaticOperationShared>,
    sentinel_handle: Option<u64>,
    _sentinel: Arc<NativeSentinelLease>,
}

impl AutomaticReplayOperation {
    /// Read `capsule.json` and verified payloads named by object ID.
    pub fn from_directory(directory: &Path) -> Result<Self, Error> {
        let bytes = read_bounded_file(&directory.join("capsule.json"), 32 * 1_024 * 1_024)?;
        let capsule: ReplayCapsule = canonical::parse_strict(&bytes)?;
        if canonical::canonical_bytes(&capsule)? != bytes {
            return Err(Error::schema_invalid());
        }
        Self::from_capsule(&capsule, &mut |object| {
            read_bounded_file(
                &directory.join(object.object_id.to_string()),
                object.plain_size,
            )
        })
    }

    pub fn from_capsule(
        capsule: &ReplayCapsule,
        read: &mut dyn FnMut(&LogicalObject) -> Result<Vec<u8>, Error>,
    ) -> Result<Self, Error> {
        let resolved = resolve_replay_capsule(capsule, read)?;
        let replay = resolve_automatic_replay(&resolved, read)?;
        Self::new(replay)
    }

    pub(crate) fn new(replay: AutomaticReplay) -> Result<Self, Error> {
        let sentinel = NativeSentinelLease::acquire();
        let _engine_call_guard = native_sentinel::engine_call_scope();
        let operation_id = format!("op_{}", Uuid::now_v7()).parse()?;
        let coordinator = AutomaticWorldCoordinator::new_replay(replay, operation_id)?;
        let shared = AutomaticOperationShared::new(operation_id, coordinator)?;
        let handle = next_native_operation_handle()?;
        native_sentinel::operation_started(handle);
        Ok(Self {
            operation_id,
            shared,
            sentinel_handle: Some(handle),
            _sentinel: sentinel,
        })
    }

    pub fn context(&self) -> AutomaticOperationContext {
        AutomaticOperationContext::new(self.operation_id, self.shared.clone())
    }

    pub fn finish(mut self) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        let handle = self.sentinel_handle.take().ok_or_else(incomplete_replay)?;
        if !matches!(
            native_sentinel::operation_finished(handle),
            OperationCoverage::CleanKernelTrace(_)
        ) {
            return Err(incomplete_replay());
        }
        self.shared.take_for_close()?.finish_replay()
    }
}

impl Drop for AutomaticReplayOperation {
    fn drop(&mut self) {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        if let Some(handle) = self.sentinel_handle.take() {
            native_sentinel::operation_removed(handle);
        }
        self.shared.deactivate();
    }
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let metadata = path.symlink_metadata().map_err(|_| incomplete_replay())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(incomplete_replay());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| incomplete_replay())?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| incomplete_replay())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(incomplete_replay());
    }
    Ok(bytes)
}

fn incomplete_replay() -> Error {
    Error::new(
        ErrorCode::WorldNotClosed,
        "The automatic replay did not consume a complete captured World.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_file_reader_enforces_the_limit_and_rejects_non_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("object");
        std::fs::write(&path, b"four").unwrap();
        assert_eq!(read_bounded_file(&path, 4).unwrap(), b"four");
        assert!(read_bounded_file(&path, 3).is_err());
        assert!(read_bounded_file(directory.path(), 4).is_err());
        assert!(read_bounded_file(&directory.path().join("missing"), 4).is_err());
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_bounded_file(&link, 4).is_err());
        }
    }
}
