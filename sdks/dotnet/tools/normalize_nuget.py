#!/usr/bin/env python3
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path

FIXED_TIME = (1980, 1, 1, 0, 0, 0)
CORE_DIRECTORY = "package/services/metadata/core-properties"
CORE_NAME = f"{CORE_DIRECTORY}/core-properties.psmdcp"
RELATIONSHIP = re.compile(
    r'<Relationship Type="([^"]+)" Target="([^"]+)" Id="([^"]+)" />'
)


def normalized_relationships(value: bytes) -> bytes:
    text = value.decode("utf-8")
    relationships = RELATIONSHIP.findall(text)
    if len(relationships) != 2:
        raise ValueError("The NuGet package has an unexpected relationship set.")

    def replace(match: re.Match[str]) -> str:
        relationship_type, target, _ = match.groups()
        if relationship_type.endswith("/manifest"):
            identity = "RManifest"
        elif relationship_type.endswith("/metadata/core-properties"):
            identity = "RCoreProperties"
            target = f"/{CORE_NAME}"
        else:
            raise ValueError("The NuGet package has an unsupported relationship.")
        return (
            f'<Relationship Type="{relationship_type}" Target="{target}" '
            f'Id="{identity}" />'
        )

    return RELATIONSHIP.sub(replace, text).encode("utf-8")


def normalized_entries(package: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("The NuGet package contains a duplicate archive path.")
        core_names = [name for name in names if name.startswith(f"{CORE_DIRECTORY}/")]
        if len(core_names) != 1 or not core_names[0].endswith(".psmdcp"):
            raise ValueError("The NuGet package has an invalid core-properties record.")
        entries = {
            name: archive.read(name)
            for name in names
            if name not in {"_rels/.rels", core_names[0]}
        }
        entries["_rels/.rels"] = normalized_relationships(archive.read("_rels/.rels"))
        entries[CORE_NAME] = archive.read(core_names[0])
        return entries


def write_normalized(package: Path, entries: dict[str, bytes]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{package.name}.", dir=package.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in sorted(entries):
                info = zipfile.ZipInfo(name, FIXED_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, entries[name])
        os.replace(temporary, package)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_nuget.py PACKAGE", file=sys.stderr)
        return 2
    package = Path(sys.argv[1])
    if not package.is_file() or package.suffix != ".nupkg":
        print("The NuGet package path is invalid.", file=sys.stderr)
        return 2
    try:
        write_normalized(package, normalized_entries(package))
    except (OSError, UnicodeDecodeError, ValueError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
