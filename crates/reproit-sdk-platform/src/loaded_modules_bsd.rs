use std::{
    collections::BTreeSet, ffi::OsStr, fs, os::unix::ffi::OsStrExt as _, path::PathBuf, slice,
};

use crate::PlatformError;

const MAX_LOADED_MODULES: usize = 32_767;
const MAX_MODULE_PATH_BYTES: usize = 4_096;

struct SnapshotState {
    error: Option<PlatformError>,
    paths: BTreeSet<PathBuf>,
}

pub fn loaded_module_paths() -> Result<Vec<PathBuf>, PlatformError> {
    let before = module_snapshot()?;
    let after = module_snapshot()?;
    if before != after {
        return Err(PlatformError::Changing);
    }
    Ok(before.into_iter().collect())
}

fn module_snapshot() -> Result<BTreeSet<PathBuf>, PlatformError> {
    let executable =
        fs::canonicalize(std::env::current_exe().map_err(|_| PlatformError::Unreadable)?)
            .map_err(|_| PlatformError::Unreadable)?;
    let mut state = SnapshotState {
        error: None,
        paths: BTreeSet::from([executable]),
    };
    // Safety: The callback data remains valid for the synchronous traversal.
    let result = unsafe {
        libc::dl_iterate_phdr(
            Some(module_callback),
            (&raw mut state).cast::<libc::c_void>(),
        )
    };
    if let Some(error) = state.error {
        return Err(error);
    }
    if result != 0 || state.paths.is_empty() || state.paths.len() > MAX_LOADED_MODULES {
        return Err(PlatformError::Unreadable);
    }
    state
        .paths
        .into_iter()
        .map(|path| fs::canonicalize(path).map_err(|_| PlatformError::Unreadable))
        .collect()
}

#[forbid(unsafe_op_in_unsafe_fn)]
unsafe extern "C" fn module_callback(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut libc::c_void,
) -> libc::c_int {
    if info.is_null() || data.is_null() {
        return 1;
    }
    // Safety: dl_iterate_phdr supplies both pointers for this callback call.
    let state = unsafe { &mut *data.cast::<SnapshotState>() };
    // Safety: The non-null info pointer is valid for this callback call.
    let name = unsafe { (*info).dlpi_name };
    let path = match unsafe { bounded_path(name) } {
        Ok(Some(path)) => path,
        Ok(None) => return 0,
        Err(error) => {
            state.error = Some(error);
            return 1;
        }
    };
    if !path.is_absolute() {
        state.error = Some(PlatformError::Unsupported);
        return 1;
    }
    state.paths.insert(path);
    if state.paths.len() > MAX_LOADED_MODULES {
        state.error = Some(PlatformError::Unbounded);
        return 1;
    }
    0
}

#[forbid(unsafe_op_in_unsafe_fn)]
unsafe fn bounded_path(name: *const libc::c_char) -> Result<Option<PathBuf>, PlatformError> {
    if name.is_null() {
        return Ok(None);
    }
    let mut length = 0_usize;
    while length <= MAX_MODULE_PATH_BYTES {
        // Safety: dl_iterate_phdr supplies a null-terminated module name.
        if unsafe { *name.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length > MAX_MODULE_PATH_BYTES {
        return Err(PlatformError::Unbounded);
    }
    if length == 0 {
        return Ok(None);
    }
    // Safety: The bounded scan proved that these bytes precede the terminator.
    let bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), length) };
    Ok(Some(PathBuf::from(OsStr::from_bytes(bytes))))
}
