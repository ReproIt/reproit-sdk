use std::{fs::File, mem, os::windows::io::AsRawHandle as _};

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use crate::PlatformError;

pub fn same_file(left: &File, right: &File) -> Result<bool, PlatformError> {
    let left = file_identity(left)?;
    let right = file_identity(right)?;
    Ok(left == right)
}

fn file_identity(file: &File) -> Result<(u32, u64), PlatformError> {
    let mut information = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // Safety: The file owns a valid handle and information is writable.
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
    if result == 0 {
        return Err(PlatformError::Unreadable);
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_handles_for_the_executable_have_one_identity() {
        let path = std::env::current_exe().unwrap();
        let left = File::open(&path).unwrap();
        let right = File::open(path).unwrap();
        assert!(same_file(&left, &right).unwrap());
    }
}
