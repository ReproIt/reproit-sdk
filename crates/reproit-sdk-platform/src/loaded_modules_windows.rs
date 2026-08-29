use std::{
    collections::BTreeSet, ffi::OsString, fs, mem, os::windows::ffi::OsStringExt as _,
    path::PathBuf, ptr,
};

use windows_sys::Win32::{
    Foundation::HMODULE,
    System::{
        ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW},
        Threading::GetCurrentProcess,
    },
};

use crate::PlatformError;

const MAX_LOADED_MODULES: usize = 32_767;
const MAX_MODULE_PATH_CODE_UNITS: usize = 32_767;

pub fn loaded_module_paths() -> Result<Vec<PathBuf>, PlatformError> {
    let before = module_snapshot()?;
    let after = module_snapshot()?;
    if before != after {
        return Err(PlatformError::Changing);
    }
    Ok(before.into_iter().collect())
}

fn module_snapshot() -> Result<BTreeSet<PathBuf>, PlatformError> {
    let mut modules = vec![ptr::null_mut(); MAX_LOADED_MODULES];
    let buffer_bytes = modules
        .len()
        .checked_mul(mem::size_of::<HMODULE>())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(PlatformError::Unbounded)?;
    let mut needed_bytes = 0_u32;
    // Safety: The module buffer is writable for buffer_bytes bytes.
    let result = unsafe {
        K32EnumProcessModules(
            GetCurrentProcess(),
            modules.as_mut_ptr(),
            buffer_bytes,
            &raw mut needed_bytes,
        )
    };
    let module_bytes =
        u32::try_from(mem::size_of::<HMODULE>()).map_err(|_| PlatformError::Unbounded)?;
    if result == 0
        || needed_bytes == 0
        || needed_bytes > buffer_bytes
        || !needed_bytes.is_multiple_of(module_bytes)
    {
        return Err(if needed_bytes > buffer_bytes {
            PlatformError::Unbounded
        } else {
            PlatformError::Unreadable
        });
    }
    let module_count = needed_bytes as usize / mem::size_of::<HMODULE>();
    modules.truncate(module_count);
    let mut path_buffer = vec![0_u16; MAX_MODULE_PATH_CODE_UNITS];
    let path_buffer_code_units =
        u32::try_from(path_buffer.len()).map_err(|_| PlatformError::Unbounded)?;
    let mut paths = BTreeSet::new();
    for module in modules {
        // Safety: The path buffer is writable for its declared length.
        let length = unsafe {
            K32GetModuleFileNameExW(
                GetCurrentProcess(),
                module,
                path_buffer.as_mut_ptr(),
                path_buffer_code_units,
            )
        };
        if length == 0 || length as usize >= path_buffer.len() {
            return Err(PlatformError::Unreadable);
        }
        let path = PathBuf::from(OsString::from_wide(&path_buffer[..length as usize]));
        if !path.is_absolute() {
            return Err(PlatformError::Unsupported);
        }
        paths.insert(fs::canonicalize(path).map_err(|_| PlatformError::Unreadable)?);
    }
    Ok(paths)
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
