use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};

use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::{SecretKey, encode_base64url, secret_key},
    identity::{Digest, ServiceId, Timestamp},
};
use serde::{Deserialize, Serialize};

const WORKLOAD_KEY_BYTES: usize = 32;
const WORKLOAD_KEY_FILE: &str = "workload.key";
const DEPLOYMENT_METADATA_FILE: &str = "deployment.json";
const REGISTRATION_RECEIPT_FILE: &str = "registration.json";
pub const MAX_MANAGED_DEPLOYMENT_METADATA_BYTES: usize = 256;
pub const MAX_MANAGED_WORKLOAD_RECEIPT_BYTES: usize = 512;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDeploymentMetadata {
    binding_digest: Digest,
    format: u8,
    signed_at: Timestamp,
}

impl ManagedDeploymentMetadata {
    fn validate(&self) -> Result<(), Error> {
        if self.format != 1 {
            return Err(deployment_metadata_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorkloadRegistrationReceipt {
    pub deployment_digest: Digest,
    pub service_id: ServiceId,
    pub workload_key_id: String,
}

impl ManagedWorkloadRegistrationReceipt {
    fn validate(&self) -> Result<(), Error> {
        let digest = self
            .workload_key_id
            .strip_prefix("managed-workload-")
            .ok_or_else(receipt_invalid)?;
        let parsed: Digest = digest.parse().map_err(|_| receipt_invalid())?;
        if parsed.to_string() != digest {
            return Err(receipt_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManagedWorkloadIdentityState {
    directory: PathBuf,
}

impl ManagedWorkloadIdentityState {
    pub fn from_environment(binding_digest: Digest) -> Result<Self, Error> {
        let state_root =
            reproit_sdk_platform::managed_state_root().map_err(|_| state_root_invalid())?;
        Self::from_state_root(&state_root, binding_digest)
    }

    #[deprecated(note = "Use from_environment for portable managed identity state.")]
    pub fn from_linux_environment(binding_digest: Digest) -> Result<Self, Error> {
        Self::from_environment(binding_digest)
    }

    pub fn from_state_root(state_root: &Path, binding_digest: Digest) -> Result<Self, Error> {
        reproit_sdk_platform::validate_managed_state_root(state_root)
            .map_err(|_| state_root_invalid())?;
        ensure_state_root(state_root)?;
        let reproit = state_root.join("reproit");
        ensure_private_directory(&reproit)?;
        let workloads = reproit.join("workloads");
        ensure_private_directory(&workloads)?;
        let directory = workloads.join(binding_digest.to_string());
        ensure_private_directory(&directory)?;
        Ok(Self { directory })
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn load_or_create_key(&self) -> Result<SecretKey, Error> {
        validate_private_directory(&self.directory)?;
        load_or_create_managed_workload_key(&self.directory.join(WORKLOAD_KEY_FILE))
    }

    pub fn load_or_create_deployment_signed_at(
        &self,
        binding_digest: Digest,
        proposed_signed_at: &Timestamp,
    ) -> Result<Timestamp, Error> {
        validate_private_directory(&self.directory)?;
        let expected = ManagedDeploymentMetadata {
            binding_digest,
            format: 1,
            signed_at: proposed_signed_at.clone(),
        };
        let path = self.directory.join(DEPLOYMENT_METADATA_FILE);
        if let Some(stored) = read_deployment_metadata_if_present(&path)? {
            if stored.binding_digest != binding_digest {
                return Err(deployment_metadata_scope_mismatch());
            }
            return Ok(stored.signed_at);
        }
        let bytes = canonical::canonical_bytes(&expected)?;
        if bytes.is_empty() || bytes.len() > MAX_MANAGED_DEPLOYMENT_METADATA_BYTES {
            return Err(deployment_metadata_invalid());
        }
        match atomic_create(&path, &bytes)? {
            AtomicCreate::Created => Ok(expected.signed_at),
            AtomicCreate::AlreadyExists => {
                let stored = read_deployment_metadata(&path)?;
                if stored.binding_digest != binding_digest {
                    return Err(deployment_metadata_scope_mismatch());
                }
                Ok(stored.signed_at)
            }
        }
    }

    pub fn load_registration_receipt(
        &self,
        expected: &ManagedWorkloadRegistrationReceipt,
    ) -> Result<Option<ManagedWorkloadRegistrationReceipt>, Error> {
        expected.validate()?;
        validate_private_directory(&self.directory)?;
        let path = self.directory.join(REGISTRATION_RECEIPT_FILE);
        let Some(receipt) = read_receipt_if_present(&path)? else {
            return Ok(None);
        };
        if receipt != *expected {
            return Err(receipt_scope_mismatch());
        }
        Ok(Some(receipt))
    }

    pub fn persist_registration_receipt(
        &self,
        receipt: &ManagedWorkloadRegistrationReceipt,
    ) -> Result<(), Error> {
        receipt.validate()?;
        validate_private_directory(&self.directory)?;
        let bytes = canonical::canonical_bytes(receipt)?;
        if bytes.is_empty() || bytes.len() > MAX_MANAGED_WORKLOAD_RECEIPT_BYTES {
            return Err(receipt_invalid());
        }
        let path = self.directory.join(REGISTRATION_RECEIPT_FILE);
        if let Some(stored) = read_receipt_if_present(&path)? {
            return if stored == *receipt {
                Ok(())
            } else {
                Err(receipt_scope_mismatch())
            };
        }
        match atomic_create(&path, &bytes)? {
            AtomicCreate::Created => Ok(()),
            AtomicCreate::AlreadyExists => {
                let stored = read_receipt(&path)?;
                if stored == *receipt {
                    Ok(())
                } else {
                    Err(receipt_scope_mismatch())
                }
            }
        }
    }
}

pub fn load_or_create_managed_workload_key(path: &Path) -> Result<SecretKey, Error> {
    let parent = path.parent().ok_or_else(key_store_invalid)?;
    validate_parent(parent)?;
    match fs::symlink_metadata(path) {
        Ok(_) => read_key(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0_u8; WORKLOAD_KEY_BYTES];
            getrandom::fill(&mut key).map_err(|_| key_store_unavailable())?;
            match atomic_create(path, &key)? {
                AtomicCreate::Created => Ok(secret_key(key)),
                AtomicCreate::AlreadyExists => read_key(path),
            }
        }
        Err(_) => Err(key_store_unavailable()),
    }
}

fn ensure_state_root(path: &Path) -> Result<(), Error> {
    reproit_sdk_platform::validate_managed_state_root(path).map_err(|_| state_root_invalid())?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(state_root_invalid());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(&current)?;
            }
            Err(_) => return Err(state_root_unavailable()),
        }
    }
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| state_root_unavailable())?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(state_root_invalid());
        }
    }
    #[cfg(not(unix))]
    {
        fs::symlink_metadata(path).map_err(|_| state_root_unavailable())?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)?;
            validate_private_directory(path)
        }
        Err(_) => Err(state_root_unavailable()),
    }
}

fn create_private_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    #[cfg(not(unix))]
    let builder = DirBuilder::new();
    builder.create(path).map_err(|_| state_root_unavailable())
}

fn validate_private_directory(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| state_root_invalid())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(state_root_invalid());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(state_root_invalid());
    }
    Ok(())
}

enum AtomicCreate {
    AlreadyExists,
    Created,
}

fn atomic_create(path: &Path, bytes: &[u8]) -> Result<AtomicCreate, Error> {
    let parent = path.parent().ok_or_else(key_store_invalid)?;
    validate_parent(parent)?;
    let mut random = [0_u8; 12];
    getrandom::fill(&mut random).map_err(|_| key_store_unavailable())?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(key_store_invalid)?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.pending",
        encode_base64url(&random)
    ));
    let result = atomic_create_from_temporary(path, &temporary, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_create_from_temporary(
    path: &Path,
    temporary: &Path,
    bytes: &[u8],
) -> Result<AtomicCreate, Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(temporary)
        .map_err(|_| key_store_unavailable())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| key_store_unavailable())?;
    validate_open_file(temporary, &file, bytes.len())?;
    drop(file);
    let created = match fs::hard_link(temporary, path) {
        Ok(()) => AtomicCreate::Created,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            AtomicCreate::AlreadyExists
        }
        Err(_) => return Err(key_store_unavailable()),
    };
    fs::remove_file(temporary).map_err(|_| key_store_unavailable())?;
    sync_directory(path.parent().ok_or_else(key_store_invalid)?)?;
    Ok(created)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_: &Path) -> Result<(), Error> {
    // Windows has no supported equivalent of a Unix directory fsync. The file
    // data is flushed before the atomic hard link is created.
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| key_store_unavailable())
}

fn read_key(path: &Path) -> Result<SecretKey, Error> {
    let mut file = File::open(path).map_err(|_| key_store_unavailable())?;
    validate_open_file(path, &file, WORKLOAD_KEY_BYTES)?;
    let mut key = [0_u8; WORKLOAD_KEY_BYTES];
    file.read_exact(&mut key)
        .map_err(|_| key_store_unavailable())?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| key_store_unavailable())?
        != 0
    {
        return Err(key_store_invalid());
    }
    Ok(secret_key(key))
}

fn read_receipt_if_present(
    path: &Path,
) -> Result<Option<ManagedWorkloadRegistrationReceipt>, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_receipt(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(receipt_unavailable()),
    }
}

fn read_deployment_metadata_if_present(
    path: &Path,
) -> Result<Option<ManagedDeploymentMetadata>, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_deployment_metadata(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(deployment_metadata_unavailable()),
    }
}

fn read_deployment_metadata(path: &Path) -> Result<ManagedDeploymentMetadata, Error> {
    let file = File::open(path).map_err(|_| deployment_metadata_unavailable())?;
    let metadata = validate_open_file_range(path, &file, 1, MAX_MANAGED_DEPLOYMENT_METADATA_BYTES)?;
    let capacity: usize = metadata
        .len()
        .try_into()
        .map_err(|_| deployment_metadata_invalid())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_MANAGED_DEPLOYMENT_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| deployment_metadata_unavailable())?;
    if bytes.len() > MAX_MANAGED_DEPLOYMENT_METADATA_BYTES {
        return Err(deployment_metadata_invalid());
    }
    let metadata: ManagedDeploymentMetadata =
        canonical::parse_strict(&bytes).map_err(|_| deployment_metadata_invalid())?;
    metadata.validate()?;
    if canonical::canonical_bytes(&metadata).map_err(|_| deployment_metadata_invalid())? != bytes {
        return Err(deployment_metadata_invalid());
    }
    Ok(metadata)
}

fn read_receipt(path: &Path) -> Result<ManagedWorkloadRegistrationReceipt, Error> {
    let file = File::open(path).map_err(|_| receipt_unavailable())?;
    let metadata = validate_open_file_range(path, &file, 1, MAX_MANAGED_WORKLOAD_RECEIPT_BYTES)?;
    let capacity: usize = metadata.len().try_into().map_err(|_| receipt_invalid())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_MANAGED_WORKLOAD_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| receipt_unavailable())?;
    if bytes.len() > MAX_MANAGED_WORKLOAD_RECEIPT_BYTES {
        return Err(receipt_invalid());
    }
    let receipt: ManagedWorkloadRegistrationReceipt =
        canonical::parse_strict(&bytes).map_err(|_| receipt_invalid())?;
    receipt.validate()?;
    if canonical::canonical_bytes(&receipt).map_err(|_| receipt_invalid())? != bytes {
        return Err(receipt_invalid());
    }
    Ok(receipt)
}

fn validate_parent(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| key_store_invalid())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(key_store_invalid());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(key_store_invalid());
    }
    Ok(())
}

fn validate_open_file(
    path: &Path,
    file: &File,
    expected_len: usize,
) -> Result<fs::Metadata, Error> {
    validate_open_file_range(path, file, expected_len, expected_len)
}

fn validate_open_file_range(
    path: &Path,
    file: &File,
    minimum_len: usize,
    maximum_len: usize,
) -> Result<fs::Metadata, Error> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| key_store_invalid())?;
    let metadata = file.metadata().map_err(|_| key_store_invalid())?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !metadata.file_type().is_file()
        || metadata.len() < minimum_len as u64
        || metadata.len() > maximum_len as u64
    {
        return Err(key_store_invalid());
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .and_then(|parent| fs::metadata(parent).ok())
            .ok_or_else(key_store_invalid)?;
        if metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != parent.uid()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
        {
            return Err(key_store_invalid());
        }
    }
    Ok(metadata)
}

fn state_root_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed workload state directory is not private or valid.",
    )
}

fn state_root_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed workload state directory is unavailable.",
    )
}

fn key_store_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed workload key file is not private or valid.",
    )
}

fn key_store_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed workload key file is unavailable.",
    )
}

fn receipt_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed workload registration receipt is corrupt or invalid.",
    )
}

fn receipt_scope_mismatch() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed workload registration receipt belongs to a different deployment.",
    )
}

fn receipt_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed workload registration receipt is unavailable.",
    )
}

fn deployment_metadata_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed deployment metadata is corrupt or invalid.",
    )
}

fn deployment_metadata_scope_mismatch() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed deployment metadata belongs to a different build binding.",
    )
}

fn deployment_metadata_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed deployment metadata is unavailable.",
    )
}
