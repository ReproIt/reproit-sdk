"""Run one Python application with automatic Repro It adapters installed."""

from __future__ import annotations

import os
import runpy
import sys
import unicodedata
from dataclasses import dataclass

from .automatic_adapters import _acquire_automatic_adapters
from .observation_adapters import _installed_observation_adapters

_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_CHARACTERS = 4_096
_MAX_TOTAL_ARGUMENT_BYTES = 64 * 1_024
_CAPTURE_PROBE_ENVIRONMENT = "REPROIT_INTERNAL_CAPTURE_PROBE"
_CAPTURE_PROBE_FORMAT = "reproit.capture-probe.v1"
_CAPTURE_PROBE_NONCE_CHARACTERS = 64
_CAPTURE_PROBE_CLASSES = {
    "clock",
    "database",
    "environment",
    "filesystem",
    "outbound-http",
    "queue",
    "randomness",
}
_USAGE_ERROR = (
    "The Python launch arguments are invalid. Run: "
    "python -m reproit_sdk.register -- SCRIPT [ARGUMENT ...], or use "
    "-- -m MODULE [ARGUMENT ...]."
)
_PROCESS_LEASE_ACQUIRED = False


@dataclass(frozen=True)
class _Launch:
    arguments: tuple[str, ...]
    module: str | None
    script: str | None


def _main(arguments: list[str] | None = None) -> int:
    """Validate one bounded launch and run it with a process lease."""
    selected = sys.argv[1:] if arguments is None else arguments
    try:
        launch = _parse_launch(selected)
    except ValueError:
        sys.stderr.write(f"{_USAGE_ERROR}\n")
        return 2
    if not _acquire_process_lease():
        sys.stderr.write("Repro It could not install the Python capture hooks.\n")
        return 1
    probe = os.environ.get(_CAPTURE_PROBE_ENVIRONMENT)
    if probe is not None:
        return _run_capture_probe(probe)
    if launch.module is not None:
        _run_module(launch.module, launch.arguments)
    else:
        assert launch.script is not None
        _run_script(launch.script, launch.arguments)
    return 0


def _run_capture_probe(nonce: str) -> int:
    if not _valid_capture_probe_nonce(nonce):
        return 1
    installed = _installed_observation_adapters()
    classes = {value.get("class") for value in installed}
    if len(installed) != len(_CAPTURE_PROBE_CLASSES) or classes != _CAPTURE_PROBE_CLASSES:
        return 1
    sys.stdout.write(f"{_CAPTURE_PROBE_FORMAT}:python:{nonce}\n")
    return 0


def _valid_capture_probe_nonce(value: str) -> bool:
    return len(value) == _CAPTURE_PROBE_NONCE_CHARACTERS and all(
        character in "0123456789abcdef" for character in value
    )


def _parse_launch(arguments: list[str]) -> _Launch:
    if not _arguments_are_bounded(arguments) or not arguments:
        raise ValueError(_USAGE_ERROR)
    if arguments[0] != "--" or len(arguments) < 2:
        raise ValueError(_USAGE_ERROR)
    target = arguments[1]
    if target == "-m":
        if len(arguments) < 3 or not _valid_module_name(arguments[2]):
            raise ValueError(_USAGE_ERROR)
        return _Launch(tuple(arguments[3:]), arguments[2], None)
    if (
        not target
        or target.startswith("-")
        or any(unicodedata.category(character) == "Cc" for character in target)
    ):
        raise ValueError(_USAGE_ERROR)
    return _Launch(tuple(arguments[2:]), None, target)


def _arguments_are_bounded(arguments: list[str]) -> bool:
    if len(arguments) > _MAX_ARGUMENTS:
        return False
    total_bytes = 0
    for argument in arguments:
        if not isinstance(argument, str) or len(argument) > _MAX_ARGUMENT_CHARACTERS:
            return False
        try:
            total_bytes += len(argument.encode("utf-8", "strict"))
        except UnicodeError:
            return False
        if total_bytes > _MAX_TOTAL_ARGUMENT_BYTES:
            return False
    return True


def _valid_module_name(value: str) -> bool:
    if not value or value.startswith("-"):
        return False
    for component in value.split("."):
        if not component:
            return False
        first, *remaining = component
        if not (first.isascii() and (first.isalpha() or first == "_")):
            return False
        if any(
            not (character.isascii() and (character.isalnum() or character == "_"))
            for character in remaining
        ):
            return False
    return True


def _acquire_process_lease() -> bool:
    global _PROCESS_LEASE_ACQUIRED
    if _PROCESS_LEASE_ACQUIRED:
        return True
    _PROCESS_LEASE_ACQUIRED = _acquire_automatic_adapters()
    return _PROCESS_LEASE_ACQUIRED


def _run_script(script: str, arguments: tuple[str, ...]) -> None:
    sys.argv = [script, *arguments]
    sys.orig_argv = [*_interpreter_prefix(), script, *arguments]
    sys.path[0] = os.path.dirname(os.path.abspath(script))
    runpy.run_path(script, run_name="__main__")


def _run_module(module: str, arguments: tuple[str, ...]) -> None:
    sys.argv = [module, *arguments]
    sys.orig_argv = [*_interpreter_prefix(), "-m", module, *arguments]
    runpy.run_module(module, run_name="__main__", alter_sys=True)


def _interpreter_prefix() -> list[str]:
    original = getattr(sys, "orig_argv", None)
    if not isinstance(original, list) or not original:
        return [sys.executable]
    for index in range(1, len(original) - 1):
        if original[index : index + 2] == ["-m", "reproit_sdk.register"]:
            return original[:index]
    return [sys.executable]


if __name__ == "__main__":
    raise SystemExit(_main())
