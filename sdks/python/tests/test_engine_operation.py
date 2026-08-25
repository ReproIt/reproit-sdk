from __future__ import annotations

import asyncio
import threading
import unittest

from reproit_sdk import (
    ManagedEngineProject,
    OperationPreparation,
    run_operation,
)
from reproit_sdk.engine_operation import (
    _PROJECT_CONSTRUCTOR,
    _current_operation_context,
)
from reproit_sdk.native_engine import (
    NativeEngineHandle,
    NativeObservation,
    NativeObservationHandle,
    NativeOperation,
    NativeOperationHandle,
)


class FakeBridge:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.sink_idle = threading.Event()

    def operation_begin(self, engine_handle, begin):
        self.calls.append(("begin", engine_handle, begin))
        return NativeOperation(NativeOperationHandle(2), "op_fixture")

    def operation_input(self, operation_handle, value):
        self.calls.append(("input", operation_handle, value))

    def observation_open(self, operation_handle, kind, parent):
        self.calls.append(("observation-open", operation_handle, kind, parent))
        return NativeObservation(NativeObservationHandle(4), 7)

    def observation_write(self, observation_handle, stream, chunk):
        self.calls.append(("observation-write", observation_handle, stream, chunk))

    def observation_dispatch(self, observation_handle):
        self.calls.append(("observation-dispatch", observation_handle))
        return "capture"

    def observation_read(self, observation_handle):
        self.calls.append(("observation-read", observation_handle))
        return b"", True

    def observation_finish(self, observation_handle, outcome, position):
        self.calls.append(
            ("observation-finish", observation_handle, outcome, position)
        )

    def observation_abandon(self, observation_handle):
        self.calls.append(("observation-abandon", observation_handle))

    def operation_unowned(self, operation_handle, kind, evidence, parent):
        self.calls.append(("unowned", operation_handle, kind, evidence, parent))

    def operation_close_world(self, operation_handle, completion):
        self.calls.append(("close-world", operation_handle, completion))

    def operation_succeed(self, operation_handle):
        self.calls.append(("succeed", operation_handle))

    def operation_abandon(self, operation_handle):
        self.calls.append(("abandon", operation_handle))

    def operation_fail(self, operation_handle, failure, project_token):
        self.calls.append(("fail", operation_handle, failure, project_token))
        return 3

    def sink_wait(self, sink_handle, timeout_ms):
        self.calls.append(("sink-wait", sink_handle, timeout_ms))
        self.sink_idle.set()
        return True

    def engine_close(self, engine_handle):
        self.calls.append(("engine-close", engine_handle))


def fixture_project(bridge):
    return ManagedEngineProject(
        _PROJECT_CONSTRUCTOR,
        bridge,
        NativeEngineHandle(1),
        lambda: "fixture-project-token",
    )


class EngineOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = FakeBridge()
        self.project = fixture_project(self.bridge)

    def test_all_backend_operation_completions_use_one_boundary(self) -> None:
        for completion in ("return", "stream-end", "acknowledgment", "task-end"):
            self.bridge.calls.clear()
            preparation = OperationPreparation(
                {"operation_kind": "request-response"},
                ({"input_index": 0}, {"input_index": 1}),
                completion,
            )
            result = run_operation(
                self.project,
                preparation,
                lambda context: context.operation_id,
                lambda error: None,
            )
            self.assertEqual(result, "op_fixture")
            self.assertEqual(
                [call[0] for call in self.bridge.calls],
                ["begin", "input", "input", "succeed"],
            )
            self.assertNotIn("close-world", [call[0] for call in self.bridge.calls])
            self.assertNotIn("fail", [call[0] for call in self.bridge.calls])

    def test_observation_session_preserves_order_bytes_and_parent(self) -> None:
        preparation = OperationPreparation({}, (), "return")

        def operation(context):
            session = context._open_observation("database", "op_parent")
            self.assertIsNotNone(session)
            assert session is not None
            self.assertTrue(session._write_request(b"request"))
            self.assertEqual(session._dispatch(), "capture")
            self.assertTrue(session._write_response(b"response"))
            self.assertTrue(session._finish("response"))
            context._mark_unowned("filesystem", b"unowned", None)
            return "result"

        self.assertEqual(
            run_operation(self.project, preparation, operation, lambda error: None),
            "result",
        )
        self.assertIn(
            ("observation-open", 2, "database", "op_parent"),
            self.bridge.calls,
        )
        self.assertIn(
            ("observation-write", 4, "request", b"request"),
            self.bridge.calls,
        )
        self.assertIn(("observation-dispatch", 4), self.bridge.calls)
        self.assertIn(
            ("observation-write", 4, "response", b"response"),
            self.bridge.calls,
        )
        self.assertIn(("observation-finish", 4, "response", 7), self.bridge.calls)
        self.assertIn(("unowned", 2, "filesystem", b"unowned", None), self.bridge.calls)

    def test_invalid_observation_transition_abandons_capture_only(self) -> None:
        class InvalidTransition(FakeBridge):
            def observation_dispatch(self, observation_handle):
                self.calls.append(("observation-dispatch", observation_handle))
                raise RuntimeError("private engine detail")

        bridge = InvalidTransition()
        project = fixture_project(bridge)

        def operation(context):
            session = context._open_observation("database")
            assert session is not None
            self.assertTrue(session._write_request(b"request"))
            self.assertIsNone(session._dispatch())
            return "application-result"

        self.assertEqual(
            run_operation(
                project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: None,
            ),
            "application-result",
        )
        self.assertIn(("observation-abandon", 4), bridge.calls)
        self.assertIn(("abandon", 2), bridge.calls)
        self.assertNotIn(("succeed", 2), bridge.calls)

    def test_failure_is_rethrown_and_delivery_wait_is_background(self) -> None:
        original = RuntimeError("application failure")
        failure = {"format": "reproit.failure-identity.v1"}

        def operation(context):
            del context
            raise original

        with self.assertRaises(RuntimeError) as raised:
            run_operation(
                self.project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: failure,
            )
        self.assertIs(raised.exception, original)
        self.assertTrue(self.bridge.sink_idle.wait(1))
        self.assertIn(("fail", 2, failure, "fixture-project-token"), self.bridge.calls)
        self.assertIn(("sink-wait", 3, 1_800_000), self.bridge.calls)

    def test_capture_failure_and_async_cancellation_do_not_replace_outcome(self) -> None:
        class BeginFailure(FakeBridge):
            def operation_begin(self, engine_handle, begin):
                raise RuntimeError("local capture unavailable")

        project = fixture_project(BeginFailure())
        self.assertEqual(
            run_operation(
                project,
                OperationPreparation({}, (), "return"),
                lambda context: "application-result",
                lambda error: None,
            ),
            "application-result",
        )

        async def cancelled(context):
            del context
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(
                run_operation(
                    self.project,
                    OperationPreparation({}, (), "return"),
                    cancelled,
                    lambda error: self.fail("Cancellation was translated."),
                )
            )
        self.assertIn(("abandon", 2), self.bridge.calls)
        self.assertIsNone(_current_operation_context())

    def test_sync_nested_operation_restores_its_parent_and_caller(self) -> None:
        class SequencedBridge(FakeBridge):
            def __init__(self) -> None:
                super().__init__()
                self.sequence = 0

            def operation_begin(self, engine_handle, begin):
                self.sequence += 1
                operation_id = f"op_{self.sequence}"
                self.calls.append(("begin", engine_handle, begin))
                return NativeOperation(
                    NativeOperationHandle(self.sequence + 1),
                    operation_id,
                )

        project = fixture_project(SequencedBridge())

        def outer(outer_context):
            self.assertIs(_current_operation_context(), outer_context)

            def inner(inner_context):
                self.assertIs(_current_operation_context(), inner_context)
                self.assertIsNot(inner_context, outer_context)
                return inner_context.operation_id

            inner_id = run_operation(
                project,
                OperationPreparation({}, (), "return"),
                inner,
                lambda error: None,
            )
            self.assertIs(_current_operation_context(), outer_context)
            return outer_context.operation_id, inner_id

        self.assertIsNone(_current_operation_context())
        self.assertEqual(
            run_operation(
                project,
                OperationPreparation({}, (), "return"),
                outer,
                lambda error: None,
            ),
            ("op_1", "op_2"),
        )
        self.assertIsNone(_current_operation_context())

    def test_concurrent_async_operations_keep_distinct_contexts(self) -> None:
        class SequencedBridge(FakeBridge):
            def __init__(self) -> None:
                super().__init__()
                self.sequence = 0

            def operation_begin(self, engine_handle, begin):
                self.sequence += 1
                return NativeOperation(
                    NativeOperationHandle(self.sequence + 1),
                    f"op_{self.sequence}",
                )

        project = fixture_project(SequencedBridge())

        async def scenario():
            ready = 0
            both_ready = asyncio.Event()

            async def operation(context):
                nonlocal ready
                self.assertIs(_current_operation_context(), context)
                ready += 1
                if ready == 2:
                    both_ready.set()
                await both_ready.wait()
                await asyncio.sleep(0)
                self.assertIs(_current_operation_context(), context)
                return context.operation_id

            first = run_operation(
                project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: None,
            )
            second = run_operation(
                project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: None,
            )
            return await asyncio.gather(first, second)

        self.assertEqual(asyncio.run(scenario()), ["op_1", "op_2"])
        self.assertIsNone(_current_operation_context())

    def test_exception_restores_the_callers_context(self) -> None:
        original = RuntimeError("application failure")

        def operation(context):
            self.assertIs(_current_operation_context(), context)
            raise original

        with self.assertRaises(RuntimeError) as raised:
            run_operation(
                self.project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: None,
            )
        self.assertIs(raised.exception, original)
        self.assertIsNone(_current_operation_context())

    def test_detached_task_cannot_retain_a_closed_operation(self) -> None:
        async def scenario():
            release = asyncio.Event()
            detached_task = None

            async def detached():
                await release.wait()
                return _current_operation_context()

            async def operation(context):
                nonlocal detached_task
                self.assertIs(_current_operation_context(), context)
                detached_task = asyncio.create_task(detached())
                return "application-result"

            result = await run_operation(
                self.project,
                OperationPreparation({}, (), "return"),
                operation,
                lambda error: None,
            )
            release.set()
            return result, await detached_task

        self.assertEqual(
            asyncio.run(scenario()),
            ("application-result", None),
        )


if __name__ == "__main__":
    unittest.main()
