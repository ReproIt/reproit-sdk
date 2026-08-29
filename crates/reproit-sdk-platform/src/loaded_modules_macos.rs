use std::{
    collections::BTreeSet,
    ffi::{CStr, c_char},
    fs,
    os::unix::ffi::OsStrExt as _,
    path::PathBuf,
};

use crate::PlatformError;

const MAX_LOADED_MODULES: u32 = 32_767;

unsafe extern "C" {
    fn _dyld_get_image_name(image_index: u32) -> *const c_char;
    fn _dyld_image_count() -> u32;
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
    // Safety: dyld owns the immutable image-name pointers for each reported index.
    let count = unsafe { _dyld_image_count() };
    if count == 0 || count > MAX_LOADED_MODULES {
        return Err(PlatformError::Unbounded);
    }
    let mut paths = BTreeSet::new();
    for image_index in 0..count {
        // Safety: The index is below the count from this dyld snapshot.
        let name = unsafe { _dyld_get_image_name(image_index) };
        if name.is_null() {
            return Err(PlatformError::Unreadable);
        }
        // Safety: dyld returns a null-terminated path for a loaded image.
        let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
        if bytes.is_empty() {
            return Err(PlatformError::Unreadable);
        }
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
        if !path.is_absolute() {
            return Err(PlatformError::Unsupported);
        }
        let path = if macos_system_module(&path) {
            path
        } else {
            fs::canonicalize(path).map_err(|_| PlatformError::Unreadable)?
        };
        paths.insert(path);
        if paths.len() > MAX_LOADED_MODULES as usize {
            return Err(PlatformError::Unbounded);
        }
    }
    Ok(paths)
}

fn macos_system_module(path: &std::path::Path) -> bool {
    path.starts_with("/System/Library") || path.starts_with("/usr/lib")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_modules_include_the_running_executable() {
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(loaded_module_paths().unwrap().contains(&executable));
    }
}
