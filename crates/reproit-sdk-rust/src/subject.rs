use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::encode_base64url,
    identity::Digest,
    model::{
        DebugArtifactBinding, DebugArtifactKind, SubjectClosureFormat, SubjectClosureManifest,
        SubjectClosureObject, SubjectFile, SubjectLaunch, SubjectModule, SubjectObjectKind,
        SubjectRuntimeFamily, Validate as _,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const LINUX_RUNNING_EXECUTABLE: &str = "/proc/self/exe";
const MAX_LINUX_MAPS_BYTES: u64 = 1_048_576;
const MAX_SUBJECT_FILES: usize = 32_767;
const MAX_SUBJECT_OBJECT_BYTES: u64 = 274_878_824_448;
const MAX_SUBJECT_TOTAL_BYTES: u64 = 274_878_824_448;

pub struct RustSubjectPackage {
    pub manifest: SubjectClosureManifest,
    pub objects: Vec<PackagedSubjectObject>,
    _spool: TempDir,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PackagedSubjectObject {
    pub digest: Digest,
    pub path: PathBuf,
    pub size: u64,
}

pub fn package_running_rust_subject() -> Result<RustSubjectPackage, Error> {
    if cfg!(target_os = "linux") {
        package_linux_subject()
    } else {
        Err(unsupported_host())
    }
}

fn package_linux_subject() -> Result<RustSubjectPackage, Error> {
    let executable = std::env::current_exe().map_err(subject_unreadable)?;
    let paths = loaded_linux_modules(&executable)?;
    if paths.len().saturating_add(1) > MAX_SUBJECT_FILES {
        return Err(subject_unbounded());
    }
    let spool = tempfile::Builder::new()
        .prefix("reproit-rust-subject-")
        .tempdir()
        .map_err(subject_unreadable)?;
    let mut captured = Vec::with_capacity(paths.len().saturating_add(1));
    captured.push(capture_file(
        &executable,
        FileSource::RunningExecutable,
        spool.path(),
        SubjectObjectKind::Application,
    )?);
    for path in paths {
        captured.push(capture_file(
            &path,
            FileSource::Path(&path),
            spool.path(),
            SubjectObjectKind::NativeDependency,
        )?);
    }
    if !captured
        .iter()
        .find(|file| file.source_path == executable)
        .is_some_and(|file| file.has_dwarf)
    {
        return Err(debug_artifact_missing());
    }
    build_package(spool, &captured, &executable)
}

fn loaded_linux_modules(executable: &Path) -> Result<BTreeSet<PathBuf>, Error> {
    let bytes = fs::read("/proc/self/maps").map_err(subject_unreadable)?;
    if bytes.len() as u64 > MAX_LINUX_MAPS_BYTES {
        return Err(subject_unbounded());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| subject_unsupported())?;
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        let mapping = parse_linux_map_line(line).ok_or_else(subject_unsupported)?;
        if !mapping.permissions.contains('x') {
            continue;
        }
        let Some(path) = mapping.pathname else {
            continue;
        };
        if mapped_path_is_running_executable(path, executable) {
            continue;
        }
        if path.ends_with(" (deleted)") {
            return Err(subject_changing());
        }
        if !path.starts_with('/') {
            continue;
        }
        let path = fs::canonicalize(path).map_err(subject_unreadable)?;
        if path == executable {
            continue;
        }
        paths.insert(path);
        if paths.len() > MAX_SUBJECT_FILES {
            return Err(subject_unbounded());
        }
    }
    Ok(paths)
}

#[derive(Debug, Eq, PartialEq)]
struct LinuxMapLine<'a> {
    pathname: Option<&'a str>,
    permissions: &'a str,
}

fn parse_linux_map_line(line: &str) -> Option<LinuxMapLine<'_>> {
    let mut remaining = line;
    let address = next_linux_map_field(&mut remaining)?;
    let permissions = next_linux_map_field(&mut remaining)?;
    let offset = next_linux_map_field(&mut remaining)?;
    let device = next_linux_map_field(&mut remaining)?;
    let inode = next_linux_map_field(&mut remaining)?;
    if !valid_address_range(address)
        || !valid_permissions(permissions)
        || !valid_hex(offset)
        || !valid_device(device)
        || inode.is_empty()
        || !inode.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let pathname = remaining.trim_start_matches(char::is_whitespace);
    Some(LinuxMapLine {
        pathname: (!pathname.is_empty()).then_some(pathname),
        permissions,
    })
}

fn next_linux_map_field<'a>(remaining: &mut &'a str) -> Option<&'a str> {
    *remaining = remaining.trim_start_matches(char::is_whitespace);
    if remaining.is_empty() {
        return None;
    }
    let end = remaining
        .find(char::is_whitespace)
        .unwrap_or(remaining.len());
    let field = &remaining[..end];
    *remaining = &remaining[end..];
    Some(field)
}

fn valid_address_range(address: &str) -> bool {
    address
        .split_once('-')
        .is_some_and(|(start, end)| valid_hex(start) && valid_hex(end))
}

fn valid_permissions(permissions: &str) -> bool {
    let bytes = permissions.as_bytes();
    bytes.len() == 4
        && matches!(bytes[0], b'r' | b'-')
        && matches!(bytes[1], b'w' | b'-')
        && matches!(bytes[2], b'x' | b'-')
        && matches!(bytes[3], b'p' | b's')
}

fn valid_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_device(device: &str) -> bool {
    device
        .split_once(':')
        .is_some_and(|(major, minor)| valid_hex(major) && valid_hex(minor))
}

fn mapped_path_is_running_executable(mapped_path: &str, executable: &Path) -> bool {
    let mapped_path = mapped_path
        .strip_suffix(" (deleted)")
        .unwrap_or(mapped_path);
    Path::new(mapped_path) == executable
}

struct CapturedFile {
    digest: Digest,
    has_dwarf: bool,
    kind: SubjectObjectKind,
    size: u64,
    source_path: PathBuf,
    spool_path: PathBuf,
}

fn capture_file(
    source_path: &Path,
    source: FileSource<'_>,
    spool_root: &Path,
    kind: SubjectObjectKind,
) -> Result<CapturedFile, Error> {
    let mut source_file = source.open().map_err(subject_unreadable)?;
    let before = source.metadata(&source_file).map_err(subject_unreadable)?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_SUBJECT_OBJECT_BYTES {
        return Err(subject_unbounded());
    }
    let temporary_path = spool_root.join(format!("capture-{}", uuid_text()?));
    if !same_file_version(
        &before,
        &source_file.metadata().map_err(subject_unreadable)?,
    ) {
        return Err(subject_changing());
    }
    let mut target = File::create(&temporary_path).map_err(subject_unreadable)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut marker_tail = Vec::new();
    let mut has_dwarf = false;
    loop {
        let count = source_file.read(&mut buffer).map_err(subject_unreadable)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(count).map_err(|_| subject_unbounded())?)
            .ok_or_else(subject_unbounded)?;
        if copied > MAX_SUBJECT_OBJECT_BYTES || copied > before.len() {
            return Err(subject_changing());
        }
        hasher.update(&buffer[..count]);
        target
            .write_all(&buffer[..count])
            .map_err(subject_unreadable)?;
        marker_tail.extend_from_slice(&buffer[..count]);
        has_dwarf |= contains_dwarf_marker(&marker_tail);
        if marker_tail.len() > 32 {
            marker_tail.drain(..marker_tail.len() - 32);
        }
    }
    target.flush().map_err(subject_unreadable)?;
    let after = source.metadata(&source_file).map_err(subject_unreadable)?;
    if copied != before.len() || !same_file_version(&before, &after) {
        return Err(subject_changing());
    }
    let digest = Digest::from_bytes(hasher.finalize().into());
    let spool_path = spool_root.join(digest_name(digest));
    match fs::rename(&temporary_path, &spool_path) {
        Ok(()) => {}
        Err(_error) if spool_path.exists() => {
            fs::remove_file(&temporary_path).map_err(subject_unreadable)?;
            if fs::metadata(&spool_path).map_err(subject_unreadable)?.len() != copied {
                return Err(Error::object_digest_mismatch());
            }
        }
        Err(error) => return Err(subject_unreadable(error)),
    }
    Ok(CapturedFile {
        digest,
        has_dwarf,
        kind,
        size: copied,
        source_path: source_path.to_owned(),
        spool_path,
    })
}

#[derive(Clone, Copy)]
enum FileSource<'a> {
    Path(&'a Path),
    RunningExecutable,
}

impl<'a> FileSource<'a> {
    fn open(self) -> io::Result<File> {
        File::open(self.path())
    }

    fn metadata(self, opened_file: &File) -> io::Result<Metadata> {
        match self {
            Self::Path(path) => fs::metadata(path),
            Self::RunningExecutable => opened_file.metadata(),
        }
    }

    fn path(self) -> &'a Path {
        match self {
            Self::Path(path) => path,
            Self::RunningExecutable => Path::new(LINUX_RUNNING_EXECUTABLE),
        }
    }
}

fn build_package(
    spool: TempDir,
    captured: &[CapturedFile],
    executable: &Path,
) -> Result<RustSubjectPackage, Error> {
    let executable_digest = captured
        .iter()
        .find(|file| file.source_path == executable)
        .map(|file| file.digest)
        .ok_or_else(subject_unsupported)?;
    let mut assembly = assemble_files(captured, executable, executable_digest)?;
    let launch = SubjectLaunch {
        arguments: unicode_arguments()?,
        environment_names: environment_names()?,
        executable: subject_file_path(
            captured
                .iter()
                .find(|file| file.source_path == executable)
                .ok_or_else(subject_unsupported)?,
            executable_digest,
        ),
        working_directory: "/reproit/subject/work".to_owned(),
    };
    let launch_bytes = canonical::canonical_bytes(&launch)?;
    let launch_object = capture_bytes(
        spool.path(),
        &launch_bytes,
        SubjectObjectKind::LaunchData,
        &mut assembly.objects,
        &mut assembly.packaged,
    )?;
    assembly.files.push(SubjectFile {
        executable: false,
        object_digest: launch_object,
        path: "/reproit/subject/launch.json".to_owned(),
    });
    for module in &assembly.modules {
        let bytes = canonical::canonical_bytes(module)?;
        capture_bytes(
            spool.path(),
            &bytes,
            SubjectObjectKind::ModuleIdentity,
            &mut assembly.objects,
            &mut assembly.packaged,
        )?;
    }
    assembly
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    assembly
        .modules
        .sort_by(|left, right| left.path.cmp(&right.path));
    assembly
        .debug_artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    let objects = assembly
        .objects
        .into_iter()
        .map(|(digest, (kind, size))| SubjectClosureObject {
            digest,
            kind,
            media_type: object_media_type(kind).to_owned(),
            size,
        })
        .collect::<Vec<_>>();
    let total_bytes = objects.iter().try_fold(0_u64, |total, object| {
        total.checked_add(object.size).ok_or_else(subject_unbounded)
    })?;
    if total_bytes > MAX_SUBJECT_TOTAL_BYTES {
        return Err(subject_unbounded());
    }
    let manifest = SubjectClosureManifest {
        architecture: linux_architecture()?.to_owned(),
        debug_artifacts: assembly.debug_artifacts,
        files: assembly.files,
        format: SubjectClosureFormat::V1,
        launch,
        modules: assembly.modules,
        objects,
        operating_system: "operating-system.linux".to_owned(),
        runtime_family: SubjectRuntimeFamily::Rust,
        total_bytes,
    };
    manifest.validate()?;
    Ok(RustSubjectPackage {
        manifest,
        objects: assembly.packaged.into_values().collect(),
        _spool: spool,
    })
}

struct SubjectAssembly {
    debug_artifacts: Vec<DebugArtifactBinding>,
    files: Vec<SubjectFile>,
    modules: Vec<SubjectModule>,
    objects: BTreeMap<Digest, (SubjectObjectKind, u64)>,
    packaged: BTreeMap<Digest, PackagedSubjectObject>,
}

fn assemble_files(
    captured: &[CapturedFile],
    executable: &Path,
    executable_digest: Digest,
) -> Result<SubjectAssembly, Error> {
    let mut assembly = SubjectAssembly {
        debug_artifacts: Vec::new(),
        files: Vec::with_capacity(captured.len().saturating_add(1)),
        modules: Vec::with_capacity(captured.len()),
        objects: BTreeMap::new(),
        packaged: BTreeMap::new(),
    };
    for file in captured {
        let subject_path = subject_file_path(file, executable_digest);
        assembly.files.push(SubjectFile {
            executable: file.source_path == executable || is_dynamic_loader(&file.source_path),
            object_digest: file.digest,
            path: subject_path.clone(),
        });
        assembly.modules.push(SubjectModule {
            identity: file.digest.to_string(),
            module_digest: file.digest,
            path: subject_path.clone(),
        });
        if file.source_path == executable && file.has_dwarf {
            assembly.debug_artifacts.push(DebugArtifactBinding {
                artifact_digest: file.digest,
                kind: DebugArtifactKind::Dwarf,
                module_digest: file.digest,
                path: subject_path,
            });
        }
        insert_object(&mut assembly.objects, file.digest, file.kind, file.size)?;
        assembly
            .packaged
            .entry(file.digest)
            .or_insert_with(|| PackagedSubjectObject {
                digest: file.digest,
                path: file.spool_path.clone(),
                size: file.size,
            });
    }
    Ok(assembly)
}

fn is_dynamic_loader(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("ld-linux-") || name.starts_with("ld-musl-"))
}

fn capture_bytes(
    spool_root: &Path,
    bytes: &[u8],
    kind: SubjectObjectKind,
    objects: &mut BTreeMap<Digest, (SubjectObjectKind, u64)>,
    packaged: &mut BTreeMap<Digest, PackagedSubjectObject>,
) -> Result<Digest, Error> {
    if bytes.is_empty() {
        return Err(subject_unsupported());
    }
    let digest = Digest::of(bytes);
    let path = spool_root.join(digest_name(digest));
    if !path.exists() {
        fs::write(&path, bytes).map_err(subject_unreadable)?;
    }
    let size = u64::try_from(bytes.len()).map_err(|_| subject_unbounded())?;
    insert_object(objects, digest, kind, size)?;
    packaged
        .entry(digest)
        .or_insert(PackagedSubjectObject { digest, path, size });
    Ok(digest)
}

fn insert_object(
    objects: &mut BTreeMap<Digest, (SubjectObjectKind, u64)>,
    digest: Digest,
    kind: SubjectObjectKind,
    size: u64,
) -> Result<(), Error> {
    if let Some(existing) = objects.get(&digest) {
        if *existing != (kind, size) {
            return Err(subject_unsupported());
        }
    } else {
        objects.insert(digest, (kind, size));
    }
    Ok(())
}

fn subject_file_path(file: &CapturedFile, executable_digest: Digest) -> String {
    let name = file
        .source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("module");
    let category = if file.digest == executable_digest {
        "application"
    } else {
        "native"
    };
    format!(
        "/reproit/subject/{category}/{}/{name}",
        digest_name(file.digest)
    )
}

fn unicode_arguments() -> Result<Vec<String>, Error> {
    std::env::args_os()
        .skip(1)
        .map(|value| value.into_string().map_err(|_| subject_unsupported()))
        .collect()
}

fn environment_names() -> Result<Vec<String>, Error> {
    let mut names = std::env::vars_os()
        .map(|(name, _)| name.into_string().map_err(|_| subject_unsupported()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(unix)]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.len() == after.len()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn contains_dwarf_marker(bytes: &[u8]) -> bool {
    [b".debug_info".as_slice(), b".zdebug_info".as_slice()]
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn object_media_type(kind: SubjectObjectKind) -> &'static str {
    match kind {
        SubjectObjectKind::Application | SubjectObjectKind::NativeDependency => {
            "application/vnd.reproit.subject-file.v1"
        }
        SubjectObjectKind::LaunchData => "application/vnd.reproit.subject-launch.v1+json",
        SubjectObjectKind::ModuleIdentity => {
            "application/vnd.reproit.subject-module-identity.v1+json"
        }
        _ => "application/octet-stream",
    }
}

fn linux_architecture() -> Result<&'static str, Error> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("architecture.x86-64"),
        "aarch64" => Ok("architecture.arm64"),
        _ => Err(unsupported_host()),
    }
}

fn digest_name(digest: Digest) -> String {
    digest
        .to_string()
        .strip_prefix("sha256:")
        .expect("Digest display always has the sha256 prefix")
        .to_owned()
}

fn uuid_text() -> Result<String, Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| subject_unreadable("random source"))?;
    Ok(encode_base64url(&bytes))
}

fn unsupported_host() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "This host cannot package a Backend v1 Rust production subject.",
    )
}

fn subject_unreadable<T>(_: T) -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The running Rust subject is not completely readable.",
    )
}

fn subject_changing() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The running Rust subject changed during local packaging.",
    )
}

fn subject_unbounded() -> Error {
    Error::new(
        ErrorCode::UploadLimitExceeded,
        "The running Rust subject exceeds a Backend v1 bound.",
    )
}

fn subject_unsupported() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "The running Rust subject has an unsupported file or launch identity.",
    )
}

fn debug_artifact_missing() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "The running Rust subject does not contain the required DWARF artifact.",
    )
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn linux_map_parser_preserves_a_spaced_executable_path() {
        let line = "00400000-00452000 r-xp 00000000 08:02 173521 /srv/Repro It/bin/service";
        assert_eq!(
            parse_linux_map_line(line),
            Some(LinuxMapLine {
                pathname: Some("/srv/Repro It/bin/service"),
                permissions: "r-xp",
            })
        );
    }

    #[test]
    fn linux_map_parser_preserves_a_spaced_deleted_path() {
        let line =
            "00400000-00452000 r-xp 00000000 08:02 173521 /srv/Repro It/bin/service (deleted)";
        assert_eq!(
            parse_linux_map_line(line),
            Some(LinuxMapLine {
                pathname: Some("/srv/Repro It/bin/service (deleted)"),
                permissions: "r-xp",
            })
        );
    }

    #[test]
    fn linux_map_parser_accepts_a_missing_pathname() {
        let line = "7f000000-7f001000 rw-p 00000000 00:00 0";
        assert_eq!(
            parse_linux_map_line(line),
            Some(LinuxMapLine {
                pathname: None,
                permissions: "rw-p",
            })
        );
    }

    #[test]
    fn linux_map_parser_rejects_malformed_mandatory_fields() {
        let malformed = [
            "invalid r-xp 00000000 08:02 173521 /srv/service",
            "00400000-00452000 rwxq 00000000 08:02 173521 /srv/service",
            "00400000-00452000 r-xp invalid 08:02 173521 /srv/service",
            "00400000-00452000 r-xp 00000000 invalid 173521 /srv/service",
            "00400000-00452000 r-xp 00000000 08:02 invalid /srv/service",
            "00400000-00452000 r-xp 00000000 08:02",
        ];
        for line in malformed {
            assert_eq!(parse_linux_map_line(line), None);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::{Mutex, PoisonError};

    use super::*;

    static SUBJECT_CAPTURE: Mutex<()> = Mutex::new(());

    #[test]
    fn running_subject_is_complete_and_content_addressed() {
        let _capture = SUBJECT_CAPTURE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let package = package_running_rust_subject().unwrap();
        package.manifest.validate().unwrap();
        assert_eq!(package.manifest.runtime_family, SubjectRuntimeFamily::Rust);
        assert_eq!(
            package.manifest.launch.arguments,
            std::env::args().skip(1).collect::<Vec<_>>()
        );
        assert!(package.manifest.modules.len() >= 2);
        assert_eq!(package.manifest.debug_artifacts.len(), 1);
        let running_bytes = fs::read(LINUX_RUNNING_EXECUTABLE).unwrap();
        let application = package
            .manifest
            .files
            .iter()
            .find(|file| file.path == package.manifest.launch.executable)
            .unwrap();
        assert_eq!(application.object_digest, Digest::of(&running_bytes));
        assert!(package.manifest.files.iter().all(|file| {
            let name = Path::new(&file.path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap();
            (!name.starts_with("ld-linux-") && !name.starts_with("ld-musl-")) || file.executable
        }));
        for object in package.objects {
            let bytes = fs::read(object.path).unwrap();
            assert_eq!(Digest::of(&bytes), object.digest);
            assert_eq!(bytes.len() as u64, object.size);
        }
    }

    #[test]
    fn running_executable_capture_does_not_read_the_reported_path() {
        let _capture = SUBJECT_CAPTURE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let spool = tempfile::tempdir().unwrap();
        let reported_path = spool.path().join("unreadable/running-subject");
        let captured = capture_file(
            &reported_path,
            FileSource::RunningExecutable,
            spool.path(),
            SubjectObjectKind::Application,
        )
        .unwrap();
        let running_bytes = fs::read(LINUX_RUNNING_EXECUTABLE).unwrap();
        assert_eq!(captured.source_path, reported_path);
        assert_eq!(captured.digest, Digest::of(&running_bytes));
        assert_eq!(captured.size, running_bytes.len() as u64);
        assert_eq!(fs::read(captured.spool_path).unwrap(), running_bytes);
    }

    #[test]
    fn deleted_running_executable_mapping_is_not_a_dependency() {
        let executable = Path::new("/srv/reproit/bin/service");
        assert!(mapped_path_is_running_executable(
            "/srv/reproit/bin/service (deleted)",
            executable,
        ));
        assert!(!mapped_path_is_running_executable(
            "/srv/reproit/lib/libservice.so (deleted)",
            executable,
        ));
    }
}
