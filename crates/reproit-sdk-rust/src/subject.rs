use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

#[cfg(windows)]
use reproit_core::model::classify_pdb_prefix;
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
#[cfg(target_os = "linux")]
const LINUX_RUNNING_EXECUTABLE: &str = "/proc/self/exe";
#[cfg(target_os = "linux")]
const MAX_LINUX_MAPS_BYTES: u64 = 1_048_576;
const MAX_SUBJECT_FILES: usize = 32_767;

pub struct SubjectPackage {
    pub manifest: SubjectClosureManifest,
    pub objects: Vec<PackagedSubjectObject>,
    _reservation: crate::resources::LogicalByteReservation,
    _spool: TempDir,
}

pub type RustSubjectPackage = SubjectPackage;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PackagedSubjectObject {
    pub digest: Digest,
    pub path: PathBuf,
    pub size: u64,
}

impl SubjectPackage {
    pub fn freeze(
        manifest: SubjectClosureManifest,
        objects: &[PackagedSubjectObject],
    ) -> Result<Self, Error> {
        manifest.validate()?;
        if objects.len() != manifest.objects.len() || objects.len() > MAX_SUBJECT_FILES {
            return Err(subject_unsupported());
        }
        let declared = manifest
            .objects
            .iter()
            .map(|object| (object.digest, (object.kind, object.size)))
            .collect::<BTreeMap<_, _>>();
        if declared.len() != objects.len() {
            return Err(subject_unsupported());
        }
        let spool = tempfile::Builder::new()
            .prefix("reproit-subject-")
            .tempdir()
            .map_err(subject_unreadable)?;
        let mut reservation = crate::resources::LogicalByteReservation::new();
        let mut frozen = Vec::with_capacity(objects.len());
        for object in objects {
            let (kind, declared_size) = declared
                .get(&object.digest)
                .copied()
                .ok_or_else(subject_unsupported)?;
            if declared_size != object.size || object.size > crate::MAX_SUBJECT_FILE_BYTES {
                return Err(subject_unsupported());
            }
            let captured = capture_file(
                &object.path,
                FileSource::Path(&object.path),
                spool.path(),
                kind,
                EmptyFilePolicy::Allowed,
                &mut reservation,
            )?;
            if captured.digest != object.digest || captured.size != object.size {
                return Err(subject_changing());
            }
            frozen.push(PackagedSubjectObject {
                digest: captured.digest,
                path: captured.spool_path,
                size: captured.size,
            });
        }
        Ok(Self {
            manifest,
            objects: frozen,
            _reservation: reservation,
            _spool: spool,
        })
    }
}

pub fn package_running_rust_subject() -> Result<RustSubjectPackage, Error> {
    #[cfg(target_os = "linux")]
    return package_linux_subject();

    #[cfg(target_os = "macos")]
    return package_macos_subject();

    #[cfg(windows)]
    return package_windows_subject();

    #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    return package_bsd_subject();

    #[allow(unreachable_code)]
    Err(unsupported_host())
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
fn package_bsd_subject() -> Result<RustSubjectPackage, Error> {
    let executable = fs::canonicalize(std::env::current_exe().map_err(subject_unreadable)?)
        .map_err(subject_unreadable)?;
    let paths = reproit_sdk_platform::loaded_module_paths()
        .map_err(platform_module_error)?
        .into_iter()
        .filter(|path| path != &executable)
        .collect::<BTreeSet<_>>();
    package_native_subject(
        &executable,
        paths,
        path_file_source,
        &NativeDebugArtifact::EmbeddedDwarf,
    )
}

#[cfg(target_os = "linux")]
fn package_linux_subject() -> Result<RustSubjectPackage, Error> {
    let executable = std::env::current_exe().map_err(subject_unreadable)?;
    let paths = loaded_linux_modules(&executable)?;
    package_native_subject(
        &executable,
        paths,
        running_executable_source,
        &NativeDebugArtifact::EmbeddedDwarf,
    )
}

#[cfg(target_os = "macos")]
fn package_macos_subject() -> Result<RustSubjectPackage, Error> {
    let executable = fs::canonicalize(std::env::current_exe().map_err(subject_unreadable)?)
        .map_err(subject_unreadable)?;
    let paths = reproit_sdk_platform::loaded_module_paths()
        .map_err(platform_module_error)?
        .into_iter()
        .filter(|path| path != &executable && !macos_system_module(path))
        .collect::<BTreeSet<_>>();
    package_native_subject(
        &executable,
        paths,
        path_file_source,
        &NativeDebugArtifact::EmbeddedDwarf,
    )
}

#[cfg(windows)]
fn package_windows_subject() -> Result<RustSubjectPackage, Error> {
    let executable = fs::canonicalize(std::env::current_exe().map_err(subject_unreadable)?)
        .map_err(subject_unreadable)?;
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or_else(subject_unsupported)?;
    let system_root = fs::canonicalize(system_root).map_err(subject_unreadable)?;
    let paths = reproit_sdk_platform::loaded_module_paths()
        .map_err(platform_module_error)?
        .into_iter()
        .filter(|path| path != &executable && !windows_system_module(path, &system_root))
        .collect::<BTreeSet<_>>();
    let pdb = adjacent_native_pdb(&executable)?;
    package_native_subject(
        &executable,
        paths,
        path_file_source,
        &NativeDebugArtifact::AdjacentNativePdb(pdb),
    )
}

enum NativeDebugArtifact {
    #[cfg(not(windows))]
    EmbeddedDwarf,
    #[cfg(windows)]
    AdjacentNativePdb(PathBuf),
}

impl NativeDebugArtifact {
    const fn file_count(&self) -> usize {
        match self {
            #[cfg(not(windows))]
            Self::EmbeddedDwarf => 0,
            #[cfg(windows)]
            Self::AdjacentNativePdb(_) => 1,
        }
    }
}

fn package_native_subject(
    executable: &Path,
    paths: BTreeSet<PathBuf>,
    executable_source: for<'a> fn(&'a Path) -> FileSource<'a>,
    debug_artifact: &NativeDebugArtifact,
) -> Result<RustSubjectPackage, Error> {
    let debug_artifact_files = debug_artifact.file_count();
    if paths
        .len()
        .saturating_add(1)
        .saturating_add(debug_artifact_files)
        > MAX_SUBJECT_FILES
    {
        return Err(subject_unbounded());
    }
    let spool = tempfile::Builder::new()
        .prefix("reproit-rust-subject-")
        .tempdir()
        .map_err(subject_unreadable)?;
    let mut reservation = crate::resources::LogicalByteReservation::new();
    let mut captured = Vec::with_capacity(
        paths
            .len()
            .saturating_add(1)
            .saturating_add(debug_artifact_files),
    );
    captured.push(capture_file(
        executable,
        executable_source(executable),
        spool.path(),
        SubjectObjectKind::Application,
        EmptyFilePolicy::Rejected,
        &mut reservation,
    )?);
    for path in paths {
        captured.push(capture_file(
            &path,
            FileSource::Path(&path),
            spool.path(),
            SubjectObjectKind::NativeDependency,
            EmptyFilePolicy::Rejected,
            &mut reservation,
        )?);
    }
    match debug_artifact {
        #[cfg(not(windows))]
        NativeDebugArtifact::EmbeddedDwarf => {
            if !captured
                .iter()
                .find(|file| file.source_path == executable)
                .is_some_and(|file| file.has_dwarf)
            {
                return Err(debug_artifact_missing());
            }
        }
        #[cfg(windows)]
        NativeDebugArtifact::AdjacentNativePdb(path) => {
            let mut artifact = capture_file(
                path,
                FileSource::Path(path),
                spool.path(),
                SubjectObjectKind::DebugArtifact,
                EmptyFilePolicy::Rejected,
                &mut reservation,
            )?;
            let prefix = pdb_prefix(&artifact.spool_path)?;
            if classify_pdb_prefix(&prefix) != Some(DebugArtifactKind::NativePdb) {
                return Err(debug_artifact_missing());
            }
            artifact.debug_artifact_kind = Some(DebugArtifactKind::NativePdb);
            captured.push(artifact);
        }
    }
    build_package(spool, &captured, executable, reservation)
}

#[cfg(windows)]
fn adjacent_native_pdb(executable: &Path) -> Result<PathBuf, Error> {
    let path = executable.with_extension("pdb");
    let metadata = fs::symlink_metadata(&path).map_err(|_| debug_artifact_missing())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(debug_artifact_missing());
    }
    fs::canonicalize(path).map_err(subject_unreadable)
}

#[cfg(windows)]
fn pdb_prefix(path: &Path) -> Result<[u8; 32], Error> {
    let mut file = File::open(path).map_err(subject_unreadable)?;
    let mut prefix = [0_u8; 32];
    file.read_exact(&mut prefix)
        .map_err(|_| debug_artifact_missing())?;
    Ok(prefix)
}

#[cfg(target_os = "macos")]
fn macos_system_module(path: &Path) -> bool {
    path.starts_with("/System/Library") || path.starts_with("/usr/lib")
}

#[cfg(windows)]
fn windows_system_module(path: &Path, system_root: &Path) -> bool {
    let path = path.to_string_lossy();
    let system_root = system_root.to_string_lossy();
    path.get(..system_root.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&system_root))
        && path
            .as_bytes()
            .get(system_root.len())
            .is_none_or(|separator| matches!(*separator, b'\\' | b'/'))
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
fn platform_module_error(error: reproit_sdk_platform::PlatformError) -> Error {
    match error {
        reproit_sdk_platform::PlatformError::Changing => subject_changing(),
        reproit_sdk_platform::PlatformError::Unbounded => subject_unbounded(),
        reproit_sdk_platform::PlatformError::Unreadable => subject_unreadable(error),
        reproit_sdk_platform::PlatformError::Unsupported => subject_unsupported(),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Eq, PartialEq)]
struct LinuxMapLine<'a> {
    pathname: Option<&'a str>,
    permissions: &'a str,
}

#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
fn valid_address_range(address: &str) -> bool {
    address
        .split_once('-')
        .is_some_and(|(start, end)| valid_hex(start) && valid_hex(end))
}

#[cfg(any(target_os = "linux", test))]
fn valid_permissions(permissions: &str) -> bool {
    let bytes = permissions.as_bytes();
    bytes.len() == 4
        && matches!(bytes[0], b'r' | b'-')
        && matches!(bytes[1], b'w' | b'-')
        && matches!(bytes[2], b'x' | b'-')
        && matches!(bytes[3], b'p' | b's')
}

#[cfg(any(target_os = "linux", test))]
fn valid_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(any(target_os = "linux", test))]
fn valid_device(device: &str) -> bool {
    device
        .split_once(':')
        .is_some_and(|(major, minor)| valid_hex(major) && valid_hex(minor))
}

#[cfg(target_os = "linux")]
fn mapped_path_is_running_executable(mapped_path: &str, executable: &Path) -> bool {
    let mapped_path = mapped_path
        .strip_suffix(" (deleted)")
        .unwrap_or(mapped_path);
    Path::new(mapped_path) == executable
}

struct CapturedFile {
    debug_artifact_kind: Option<DebugArtifactKind>,
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
    empty_file_policy: EmptyFilePolicy,
    reservation: &mut crate::resources::LogicalByteReservation,
) -> Result<CapturedFile, Error> {
    let mut source_file = source.open().map_err(subject_unreadable)?;
    let before = source.metadata(&source_file).map_err(subject_unreadable)?;
    if !before.is_file()
        || empty_file_policy == EmptyFilePolicy::Rejected && before.len() == 0
        || before.len() > crate::MAX_SUBJECT_FILE_BYTES
    {
        return Err(subject_unbounded());
    }
    reserve_subject_bytes(reservation, before.len())?;
    let temporary_path = spool_root.join(format!("capture-{}", uuid_text()?));
    if !same_file_version(
        &before,
        &source_file.metadata().map_err(subject_unreadable)?,
    ) || !source_path_matches_open_file(source, &source_file)?
    {
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
        if copied > crate::MAX_SUBJECT_FILE_BYTES || copied > before.len() {
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
    if copied != before.len()
        || !same_file_version(&before, &after)
        || !source_path_matches_open_file(source, &source_file)?
    {
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
            reservation.release(copied);
        }
        Err(error) => return Err(subject_unreadable(error)),
    }
    Ok(CapturedFile {
        debug_artifact_kind: None,
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
    #[cfg(target_os = "linux")]
    RunningExecutable,
}

#[cfg(target_os = "linux")]
fn running_executable_source(_: &Path) -> FileSource<'_> {
    FileSource::RunningExecutable
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
fn path_file_source(path: &Path) -> FileSource<'_> {
    FileSource::Path(path)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EmptyFilePolicy {
    Allowed,
    Rejected,
}

impl<'a> FileSource<'a> {
    fn open(self) -> io::Result<File> {
        File::open(self.path())
    }

    #[cfg(windows)]
    fn metadata(self, opened_file: &File) -> io::Result<Metadata> {
        match self {
            Self::Path(_) => opened_file.metadata(),
        }
    }

    #[cfg(target_os = "linux")]
    fn metadata(self, opened_file: &File) -> io::Result<Metadata> {
        match self {
            Self::Path(path) => fs::metadata(path),
            Self::RunningExecutable => opened_file.metadata(),
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn metadata(self, _opened_file: &File) -> io::Result<Metadata> {
        match self {
            Self::Path(path) => fs::metadata(path),
        }
    }

    fn path(self) -> &'a Path {
        match self {
            Self::Path(path) => path,
            #[cfg(target_os = "linux")]
            Self::RunningExecutable => Path::new(LINUX_RUNNING_EXECUTABLE),
        }
    }
}

#[cfg(windows)]
fn source_path_matches_open_file(source: FileSource<'_>, opened: &File) -> Result<bool, Error> {
    let current = File::open(source.path()).map_err(subject_unreadable)?;
    reproit_sdk_platform::same_file(opened, &current).map_err(platform_module_error)
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn source_path_matches_open_file(_: FileSource<'_>, _: &File) -> Result<bool, Error> {
    Ok(true)
}

fn build_package(
    spool: TempDir,
    captured: &[CapturedFile],
    executable: &Path,
    mut reservation: crate::resources::LogicalByteReservation,
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
        &mut reservation,
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
            &mut reservation,
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
        .map(
            |(digest, (kind, size, debug_artifact_kind))| SubjectClosureObject {
                digest,
                kind,
                media_type: object_media_type(kind, debug_artifact_kind).to_owned(),
                size,
            },
        )
        .collect::<Vec<_>>();
    let total_bytes = objects.iter().try_fold(0_u64, |total, object| {
        total.checked_add(object.size).ok_or_else(subject_unbounded)
    })?;
    if total_bytes > crate::MAX_SUBJECT_BYTES {
        return Err(subject_unbounded());
    }
    let manifest = SubjectClosureManifest {
        architecture: reproit_sdk_platform::host_platform()
            .map_err(|_| unsupported_host())?
            .architecture
            .to_owned(),
        debug_artifacts: assembly.debug_artifacts,
        files: assembly.files,
        format: SubjectClosureFormat::V1,
        launch,
        modules: assembly.modules,
        objects,
        operating_system: reproit_sdk_platform::host_platform()
            .map_err(|_| unsupported_host())?
            .operating_system
            .to_owned(),
        runtime_family: SubjectRuntimeFamily::Rust,
        total_bytes,
    };
    manifest.validate()?;
    Ok(RustSubjectPackage {
        manifest,
        objects: assembly.packaged.into_values().collect(),
        _reservation: reservation,
        _spool: spool,
    })
}

struct SubjectAssembly {
    debug_artifacts: Vec<DebugArtifactBinding>,
    files: Vec<SubjectFile>,
    modules: Vec<SubjectModule>,
    objects: BTreeMap<Digest, (SubjectObjectKind, u64, Option<DebugArtifactKind>)>,
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
        if file.kind != SubjectObjectKind::DebugArtifact {
            assembly.modules.push(SubjectModule {
                identity: file.digest.to_string(),
                module_digest: file.digest,
                path: subject_path.clone(),
            });
        }
        if file.source_path == executable && file.has_dwarf {
            assembly.debug_artifacts.push(DebugArtifactBinding {
                artifact_digest: file.digest,
                kind: DebugArtifactKind::Dwarf,
                module_digest: file.digest,
                path: subject_path.clone(),
            });
        }
        if let Some(kind) = file.debug_artifact_kind {
            assembly.debug_artifacts.push(DebugArtifactBinding {
                artifact_digest: file.digest,
                kind,
                module_digest: executable_digest,
                path: subject_path,
            });
        }
        insert_object(
            &mut assembly.objects,
            file.digest,
            file.kind,
            file.size,
            file.debug_artifact_kind,
        )?;
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
    objects: &mut BTreeMap<Digest, (SubjectObjectKind, u64, Option<DebugArtifactKind>)>,
    packaged: &mut BTreeMap<Digest, PackagedSubjectObject>,
    reservation: &mut crate::resources::LogicalByteReservation,
) -> Result<Digest, Error> {
    if bytes.is_empty() {
        return Err(subject_unsupported());
    }
    let digest = Digest::of(bytes);
    let path = spool_root.join(digest_name(digest));
    let size = u64::try_from(bytes.len()).map_err(|_| subject_unbounded())?;
    if !packaged.contains_key(&digest) {
        reserve_subject_bytes(reservation, size)?;
    }
    if !path.exists() {
        fs::write(&path, bytes).map_err(subject_unreadable)?;
    }
    insert_object(objects, digest, kind, size, None)?;
    packaged
        .entry(digest)
        .or_insert(PackagedSubjectObject { digest, path, size });
    Ok(digest)
}

fn reserve_subject_bytes(
    reservation: &mut crate::resources::LogicalByteReservation,
    bytes: u64,
) -> Result<(), Error> {
    if reservation
        .bytes()
        .checked_add(bytes)
        .is_none_or(|total| total > crate::MAX_SUBJECT_BYTES)
        || !reservation.reserve(bytes)
    {
        return Err(subject_unbounded());
    }
    Ok(())
}

fn insert_object(
    objects: &mut BTreeMap<Digest, (SubjectObjectKind, u64, Option<DebugArtifactKind>)>,
    digest: Digest,
    kind: SubjectObjectKind,
    size: u64,
    debug_artifact_kind: Option<DebugArtifactKind>,
) -> Result<(), Error> {
    if let Some(existing) = objects.get(&digest) {
        if *existing != (kind, size, debug_artifact_kind) {
            return Err(subject_unsupported());
        }
    } else {
        objects.insert(digest, (kind, size, debug_artifact_kind));
    }
    Ok(())
}

fn subject_file_path(file: &CapturedFile, executable_digest: Digest) -> String {
    let name = file
        .source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("module");
    let category = match file.kind {
        SubjectObjectKind::DebugArtifact => "debug",
        _ if file.digest == executable_digest => "application",
        _ => "native",
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

#[cfg(windows)]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    before.file_size() == after.file_size()
        && before.creation_time() == after.creation_time()
        && before.last_write_time() == after.last_write_time()
        && before.file_attributes() == after.file_attributes()
}

#[cfg(not(any(unix, windows)))]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn contains_dwarf_marker(bytes: &[u8]) -> bool {
    [
        b"__DWARF".as_slice(),
        b".debug_info".as_slice(),
        b".zdebug_info".as_slice(),
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn object_media_type(
    kind: SubjectObjectKind,
    debug_artifact_kind: Option<DebugArtifactKind>,
) -> &'static str {
    match (kind, debug_artifact_kind) {
        (SubjectObjectKind::DebugArtifact, Some(DebugArtifactKind::NativePdb)) => {
            "application/vnd.reproit.native-pdb.v1"
        }
        (SubjectObjectKind::DebugArtifact, Some(DebugArtifactKind::PortablePdb)) => {
            "application/vnd.reproit.portable-pdb.v1"
        }
        (SubjectObjectKind::Application | SubjectObjectKind::NativeDependency, _) => {
            "application/vnd.reproit.subject-file.v1"
        }
        (SubjectObjectKind::LaunchData, _) => "application/vnd.reproit.subject-launch.v1+json",
        (SubjectObjectKind::ModuleIdentity, _) => {
            "application/vnd.reproit.subject-module-identity.v1+json"
        }
        _ => "application/octet-stream",
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
        "The running Rust subject does not contain the required native debug artifact.",
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

#[cfg(all(
    test,
    any(
        target_os = "freebsd",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        windows
    )
))]
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
        assert!(!package.manifest.modules.is_empty());
        assert_eq!(package.manifest.debug_artifacts.len(), 1);
        let running_bytes = fs::read(running_executable_path()).unwrap();
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

    #[cfg(target_os = "linux")]
    #[test]
    fn running_executable_capture_does_not_read_the_reported_path() {
        let _capture = SUBJECT_CAPTURE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let spool = tempfile::tempdir().unwrap();
        let reported_path = spool.path().join("unreadable/running-subject");
        let mut reservation = crate::resources::LogicalByteReservation::new();
        let captured = capture_file(
            &reported_path,
            FileSource::RunningExecutable,
            spool.path(),
            SubjectObjectKind::Application,
            EmptyFilePolicy::Rejected,
            &mut reservation,
        )
        .unwrap();
        let running_bytes = fs::read(LINUX_RUNNING_EXECUTABLE).unwrap();
        assert_eq!(captured.source_path, reported_path);
        assert_eq!(captured.digest, Digest::of(&running_bytes));
        assert_eq!(captured.size, running_bytes.len() as u64);
        assert_eq!(fs::read(captured.spool_path).unwrap(), running_bytes);
    }

    #[test]
    #[cfg(target_os = "linux")]
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

    fn running_executable_path() -> PathBuf {
        #[cfg(target_os = "linux")]
        return PathBuf::from(LINUX_RUNNING_EXECUTABLE);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            windows
        ))]
        return std::env::current_exe().unwrap();

        #[allow(unreachable_code)]
        PathBuf::new()
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn system_module_filter_is_case_insensitive_and_component_bounded() {
        let root = Path::new(r"C:\Windows");
        assert!(windows_system_module(
            Path::new(r"c:\WINDOWS\System32\kernel32.dll"),
            root,
        ));
        assert!(!windows_system_module(
            Path::new(r"C:\Windows.old\System32\kernel32.dll"),
            root,
        ));
    }
}
