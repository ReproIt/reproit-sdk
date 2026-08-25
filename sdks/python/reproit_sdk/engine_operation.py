"""Framework-neutral operation capture through the shared SDK engine."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from .managed_subject import package_running_python_subject
from .native_engine import (
    MAX_SINK_WAITERS,
    MAX_SINK_WAIT_MS,
    NativeEngineBridge,
    NativeEngineHandle,
    NativeObservation,
    NativeObservationAction,
    NativeObservationClass,
    NativeObservationOutcome,
    NativeObservationStream,
    NativeOperation,
    NativeTriggerCompletion,
)

_Result = TypeVar("_Result")
_ACTIVE_OPERATION: contextvars.ContextVar[OperationContext | None] = (
    contextvars.ContextVar("reproit_active_operation", default=None)
)
_PROJECT_CONSTRUCTOR = object()


@dataclass(frozen=True)
class OperationPreparation:
    """The Core begin, ordered inputs, and exact Trigger completion."""

    begin: Mapping[str, Any]
    inputs: Sequence[Mapping[str, Any]]
    completion: NativeTriggerCompletion


class ManagedEngineProject:
    """Own one packaged shared engine and its bounded delivery waiters."""

    def __init__(
        self,
        constructor: object,
        bridge: NativeEngineBridge,
        engine_handle: NativeEngineHandle,
        project_token_provider: Callable[[], str],
        automatic_adapters: bool,
    ) -> None:
        if constructor is not _PROJECT_CONSTRUCTOR:
            raise TypeError("Use ManagedEngineProject.open().")
        self._bridge = bridge
        self._engine_handle = engine_handle
        self._project_token_provider = project_token_provider
        self._lock = threading.Lock()
        self._sink_handles: set[int] = set()
        self._automatic_adapters = automatic_adapters
        self._closed = False

    @classmethod
    def open(
        cls,
        *,
        project_toml: str,
        build_repository_id: str,
        source_revision: str,
        project_token_provider: Callable[[], str],
        entry_script: str | None = None,
        application_root: str | None = None,
    ) -> ManagedEngineProject:
        """Package the running program and open its shared SDK engine."""
        selected_bridge = NativeEngineBridge.load()
        return cls._open_with(
            project_toml=project_toml,
            build_repository_id=build_repository_id,
            source_revision=source_revision,
            project_token_provider=project_token_provider,
            entry_script=entry_script,
            application_root=application_root,
            bridge=selected_bridge,
        )

    @classmethod
    def _open_with(
        cls,
        *,
        project_toml: str,
        build_repository_id: str,
        source_revision: str,
        project_token_provider: Callable[[], str],
        entry_script: str | None,
        application_root: str | None,
        bridge: NativeEngineBridge,
    ) -> ManagedEngineProject:
        """Open a project through the package-owned bridge seam."""
        from .automatic_adapters import _acquire_automatic_adapters

        selected_bridge = bridge
        automatic_adapters = _acquire_automatic_adapters()
        try:
            selected_bridge.contract()
            subject = package_running_python_subject(entry_script, application_root)
            try:
                engine_handle = selected_bridge.engine_open(
                    build_repository_id=build_repository_id,
                    project_toml=project_toml,
                    source_revision=source_revision,
                    subject_manifest=subject.manifest,
                    subject_objects=[
                        {
                            "digest": value.digest,
                            "path": value.path,
                            "size": value.size,
                        }
                        for value in subject.objects
                    ],
                )
            finally:
                subject.close()
        except BaseException:
            if automatic_adapters:
                from .automatic_adapters import _release_automatic_adapters

                _release_automatic_adapters()
            raise
        return cls(
            _PROJECT_CONSTRUCTOR,
            selected_bridge,
            engine_handle,
            project_token_provider,
            automatic_adapters,
        )

    def close(self) -> None:
        """Close the engine and invalidate its operation and sink handles."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._sink_handles.clear()
        try:
            self._bridge.engine_close(self._engine_handle)
        finally:
            if self._automatic_adapters:
                from .automatic_adapters import _release_automatic_adapters

                _release_automatic_adapters()

    def _begin(self, begin: Mapping[str, Any]) -> OperationContext:
        with self._lock:
            if self._closed:
                return OperationContext(None, None)
        try:
            native = self._bridge.operation_begin(self._engine_handle, begin)
        except Exception:
            return OperationContext(None, None)
        return OperationContext(self, native)

    def _project_token(self) -> str:
        return self._project_token_provider()

    def _wait_for_sink(self, sink_handle: int) -> None:
        with self._lock:
            if self._closed or len(self._sink_handles) >= MAX_SINK_WAITERS:
                return
            self._sink_handles.add(sink_handle)
        waiter = threading.Thread(
            target=self._poll_sink,
            args=(sink_handle,),
            daemon=True,
            name="reproit-sink-waiter",
        )
        waiter.start()

    def _poll_sink(self, sink_handle: int) -> None:
        try:
            with self._lock:
                if self._closed or sink_handle not in self._sink_handles:
                    return
            self._bridge.sink_wait(sink_handle, MAX_SINK_WAIT_MS)
        except Exception:
            pass
        finally:
            with self._lock:
                self._sink_handles.discard(sink_handle)


class OperationContext:
    """Translate semantic observations into one shared engine operation."""

    def __init__(
        self,
        project: ManagedEngineProject | None,
        native: NativeOperation | None,
    ) -> None:
        self._project = project
        self._native = native

    @property
    def operation_id(self) -> str | None:
        """Return the stable operation identity when capture is active."""
        return None if self._native is None else self._native.operation_id

    def record_input(self, value: Mapping[str, Any]) -> None:
        """Record the next ordered Trigger input."""
        self._call("operation_input", value)

    def _open_observation(
        self,
        observation_class: NativeObservationClass,
        causal_parent_id: str | None = None,
    ) -> _ObservationSession | None:
        """Open one session for a package-owned semantic adapter."""
        project = self._project
        native = self._native
        if project is None or native is None:
            return None
        try:
            observation = project._bridge.observation_open(
                native.handle,
                observation_class,
                causal_parent_id,
            )
        except Exception:
            self._abandon()
            return None
        return _ObservationSession(self, project, observation)

    def _mark_unowned(
        self,
        observation_class: NativeObservationClass,
        evidence: bytes,
        causal_parent_id: str | None = None,
    ) -> None:
        """Mark an observation that no supported semantic adapter owns."""
        self._call(
            "operation_unowned",
            observation_class,
            evidence,
            causal_parent_id,
        )

    def _call(self, name: str, *arguments: Any) -> None:
        project = self._project
        native = self._native
        if project is None or native is None:
            return
        try:
            getattr(project._bridge, name)(native.handle, *arguments)
        except Exception:
            self._abandon()

    def _close_success(self, completion: NativeTriggerCompletion) -> None:
        project = self._project
        native = self._native
        if project is None or native is None:
            return
        self._native = None
        try:
            project._bridge.operation_succeed(native.handle)
        except Exception:
            _safe_abandon(project, native)

    def _close_failure(
        self,
        completion: NativeTriggerCompletion,
        failure: Mapping[str, Any] | None,
    ) -> None:
        project = self._project
        native = self._native
        if project is None or native is None:
            return
        self._native = None
        if failure is None:
            _safe_abandon(project, native)
            return
        try:
            project._bridge.operation_close_world(native.handle, completion)
            sink = project._bridge.operation_fail(
                native.handle,
                failure,
                project._project_token(),
            )
        except Exception:
            _safe_abandon(project, native)
            return
        project._wait_for_sink(int(sink))

    def _abandon(self) -> None:
        project = self._project
        native = self._native
        self._native = None
        if project is not None and native is not None:
            _safe_abandon(project, native)


class _ObservationSession:
    """Keep one package-owned observation session fail-open and bounded."""

    def __init__(
        self,
        context: OperationContext,
        project: ManagedEngineProject,
        native: NativeObservation,
    ) -> None:
        self._context = context
        self._project = project
        self._native: NativeObservation | None = native

    def _write_request(self, chunk: bytes) -> bool:
        return self._write("request", chunk)

    def _write_response(self, chunk: bytes) -> bool:
        return self._write("response", chunk)

    def _dispatch(self) -> NativeObservationAction | None:
        native = self._native
        if native is None:
            return None
        try:
            return self._project._bridge.observation_dispatch(native.handle)
        except Exception:
            self._fail()
            return None

    def _read_response(self) -> tuple[bytes, bool] | None:
        native = self._native
        if native is None:
            return None
        try:
            return self._project._bridge.observation_read(native.handle)
        except Exception:
            self._fail()
            return None

    def _finish(self, outcome: NativeObservationOutcome) -> bool:
        native = self._native
        if native is None:
            return False
        try:
            self._project._bridge.observation_finish(
                native.handle,
                outcome,
                native.session_position,
            )
        except Exception:
            self._fail()
            return False
        self._native = None
        return True

    def _abandon(self) -> None:
        native = self._take()
        if native is not None:
            try:
                self._project._bridge.observation_abandon(native.handle)
            except Exception:
                pass
        self._context._abandon()

    def _write(self, stream: NativeObservationStream, chunk: bytes) -> bool:
        native = self._native
        if native is None:
            return False
        try:
            self._project._bridge.observation_write(
                native.handle,
                stream,
                chunk,
            )
        except Exception:
            self._fail()
            return False
        return True

    def _fail(self) -> None:
        native = self._take()
        if native is not None:
            try:
                self._project._bridge.observation_abandon(native.handle)
            except Exception:
                pass
        self._context._abandon()

    def _take(self) -> NativeObservation | None:
        native = self._native
        self._native = None
        return native


def _current_operation_context() -> OperationContext | None:
    """Return the operation owned by the current package execution context."""
    context = _ACTIVE_OPERATION.get()
    if context is None or context._native is None:
        return None
    return context


def run_operation(
    project: ManagedEngineProject,
    preparation: OperationPreparation,
    operation: Callable[[OperationContext], _Result | Awaitable[_Result]],
    failure: Callable[[BaseException], Mapping[str, Any] | None],
) -> _Result | Awaitable[_Result]:
    """Run one framework-neutral boundary without changing its outcome."""
    context = project._begin(preparation.begin)
    for value in preparation.inputs:
        context.record_input(value)
    token = _ACTIVE_OPERATION.set(context)
    try:
        result = operation(context)
    except BaseException as original:
        _finish_failure(context, preparation.completion, original, failure)
        raise
    finally:
        _ACTIVE_OPERATION.reset(token)
    if inspect.isawaitable(result):
        return _finish_awaitable(
            result,
            context,
            preparation.completion,
            failure,
        )
    context._close_success(preparation.completion)
    return result


async def _finish_awaitable(
    result: Awaitable[_Result],
    context: OperationContext,
    completion: NativeTriggerCompletion,
    failure: Callable[[BaseException], Mapping[str, Any] | None],
) -> _Result:
    token = _ACTIVE_OPERATION.set(context)
    try:
        value = await result
    except BaseException as original:
        _finish_failure(context, completion, original, failure)
        raise
    else:
        context._close_success(completion)
        return value
    finally:
        _ACTIVE_OPERATION.reset(token)


def _finish_failure(
    context: OperationContext,
    completion: NativeTriggerCompletion,
    original: BaseException,
    failure: Callable[[BaseException], Mapping[str, Any] | None],
) -> None:
    if isinstance(original, asyncio.CancelledError) or not isinstance(
        original, Exception
    ):
        context._abandon()
        return
    try:
        translated = failure(original)
    except Exception:
        context._abandon()
        return
    context._close_failure(completion, translated)


def _safe_abandon(project: ManagedEngineProject, native: NativeOperation) -> None:
    try:
        project._bridge.operation_abandon(native.handle)
    except Exception:
        pass
