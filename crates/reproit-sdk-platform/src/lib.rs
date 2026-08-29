#![deny(clippy::all, clippy::pedantic)]
#![allow(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::{
    env,
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostPlatform {
    pub architecture: &'static str,
    pub operating_system: &'static str,
    pub runtime_abi: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Changing,
    Unbounded,
    Unreadable,
    Unsupported,
}

#[cfg(target_os = "macos")]
#[path = "loaded_modules_macos.rs"]
mod loaded_modules;

#[cfg(windows)]
#[path = "loaded_modules_windows.rs"]
mod loaded_modules;

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
#[path = "loaded_modules_bsd.rs"]
mod loaded_modules;

#[cfg(any(
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
pub use loaded_modules::loaded_module_paths;

#[cfg(windows)]
#[path = "file_identity_windows.rs"]
mod file_identity;

#[cfg(windows)]
pub use file_identity::same_file;

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
)))]
pub fn loaded_module_paths() -> Result<Vec<std::path::PathBuf>, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub fn host_platform() -> Result<HostPlatform, PlatformError> {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "architecture.arm64",
        "x86_64" => "architecture.x86-64",
        _ => return Err(PlatformError::Unsupported),
    };
    let operating_system = match std::env::consts::OS {
        "freebsd" => "operating-system.freebsd",
        "linux" => "operating-system.linux",
        "macos" => "operating-system.macos",
        "netbsd" => "operating-system.netbsd",
        "openbsd" => "operating-system.openbsd",
        "windows" => "operating-system.windows",
        _ => return Err(PlatformError::Unsupported),
    };
    Ok(HostPlatform {
        architecture,
        operating_system,
        runtime_abi: runtime_abi()?,
    })
}

pub fn managed_state_root() -> Result<PathBuf, PlatformError> {
    #[cfg(target_os = "macos")]
    return macos_state_root(
        env::var_os("XDG_STATE_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    );

    #[cfg(windows)]
    return windows_state_root(env::var_os("LOCALAPPDATA").as_deref());

    #[cfg(all(unix, not(target_os = "macos")))]
    return unix_state_root(
        env::var_os("XDG_STATE_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    );

    #[allow(unreachable_code)]
    Err(PlatformError::Unsupported)
}

pub fn validate_managed_state_root(path: &Path) -> Result<(), PlatformError> {
    validate_absolute_clean_path(path)?;
    #[cfg(windows)]
    {
        let local_application_data = windows_state_root(env::var_os("LOCALAPPDATA").as_deref())?;
        if !windows_path_within(path, &local_application_data) {
            return Err(PlatformError::Unsupported);
        }
    }
    Ok(())
}

#[cfg(all(unix, any(test, not(target_os = "macos"))))]
fn unix_state_root(
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, PlatformError> {
    if let Some(xdg_state_home) = xdg_state_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(xdg_state_home);
        validate_absolute_clean_path(&path)?;
        return Ok(path);
    }
    let home = home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(PlatformError::Unsupported)?;
    validate_absolute_clean_path(&home)?;
    Ok(home.join(".local/state"))
}

#[cfg(target_os = "macos")]
fn macos_state_root(
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, PlatformError> {
    if let Some(xdg_state_home) = xdg_state_home.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(xdg_state_home);
        validate_absolute_clean_path(&path)?;
        return Ok(path);
    }
    let home = home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(PlatformError::Unsupported)?;
    validate_absolute_clean_path(&home)?;
    Ok(home.join("Library/Application Support"))
}

#[cfg(windows)]
fn windows_state_root(local_application_data: Option<&OsStr>) -> Result<PathBuf, PlatformError> {
    let path = local_application_data
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(PlatformError::Unsupported)?;
    validate_absolute_clean_path(&path)?;
    Ok(path)
}

#[cfg(windows)]
fn windows_path_within(path: &Path, root: &Path) -> bool {
    let path = path.to_string_lossy();
    let root = root.to_string_lossy();
    path.get(..root.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&root))
        && path
            .as_bytes()
            .get(root.len())
            .is_none_or(|separator| matches!(*separator, b'\\' | b'/'))
}

fn validate_absolute_clean_path(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(PlatformError::Unsupported);
    }
    Ok(())
}

fn runtime_abi() -> Result<&'static str, PlatformError> {
    if cfg!(all(target_os = "linux", target_env = "gnu")) {
        return Ok("abi.gnu");
    }
    if cfg!(all(target_os = "linux", target_env = "musl")) {
        return Ok("abi.musl");
    }
    if cfg!(target_os = "macos") {
        return Ok("abi.apple-darwin");
    }
    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        return Ok("abi.windows-msvc");
    }
    if cfg!(target_os = "freebsd") {
        return Ok("abi.freebsd");
    }
    if cfg!(target_os = "netbsd") {
        return Ok("abi.netbsd");
    }
    if cfg!(target_os = "openbsd") {
        return Ok("abi.openbsd");
    }
    Err(PlatformError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_host_has_one_canonical_platform_descriptor() {
        let platform = host_platform().unwrap();
        assert!(platform.architecture.starts_with("architecture."));
        assert!(platform.operating_system.starts_with("operating-system."));
        assert!(platform.runtime_abi.starts_with("abi."));
    }

    #[test]
    fn current_managed_state_root_is_absolute_and_clean() {
        let path = managed_state_root().unwrap();
        validate_managed_state_root(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_state_root_prefers_absolute_xdg_and_falls_back_to_home() {
        assert_eq!(
            unix_state_root(
                Some(OsStr::new("/state")),
                Some(OsStr::new("/account/user"))
            )
            .unwrap(),
            PathBuf::from("/state")
        );
        assert_eq!(
            unix_state_root(None, Some(OsStr::new("/account/user"))).unwrap(),
            PathBuf::from("/account/user/.local/state")
        );
        assert!(
            unix_state_root(
                Some(OsStr::new("relative")),
                Some(OsStr::new("/account/user"))
            )
            .is_err()
        );
        assert!(unix_state_root(None, Some(OsStr::new("relative"))).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_state_root_uses_application_support_without_xdg() {
        assert_eq!(
            macos_state_root(None, Some(OsStr::new("/account/user"))).unwrap(),
            PathBuf::from("/account/user/Library/Application Support")
        );
    }

    #[cfg(windows)]
    #[test]
    fn state_root_must_stay_inside_local_application_data() {
        let root = Path::new(r"C:\Users\account\AppData\Local");
        assert!(windows_path_within(
            Path::new(r"c:\USERS\account\AppData\Local\state"),
            root,
        ));
        assert!(!windows_path_within(
            Path::new(r"C:\Users\account\AppData\Local.old\state"),
            root,
        ));
    }
}
