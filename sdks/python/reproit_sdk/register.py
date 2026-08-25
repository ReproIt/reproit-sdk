"""Run one Python application with automatic Repro It adapters installed."""

from __future__ import annotations

import os
import runpy
import sys
from dataclasses import dataclass

from .automatic_adapters import _acquire_automatic_adapters

_MAX_ARGUMENTS = 128
_MAX_ARGUMENT_CHARACTERS = 4_096
_MAX_TOTAL_ARGUMENT_BYTES = 64 * 1_024
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
    if launch.module is not None:
        _run_module(launch.module, launch.arguments)
    else:
        assert launch.script is not None
        _run_script(launch.script, launch.arguments)
    return 0


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
    if not target or target.startswith("-"):
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
    return (
        bool(value)
        and not value.startswith("-")
        and all(part.isidentifier() for part in value.split("."))
    )


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
