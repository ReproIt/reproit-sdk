from __future__ import annotations

import _sqlite3 as sqlite_native
import base64
import json
import sqlite3
import sqlite3.dbapi2 as sqlite_dbapi2
import unittest
from contextlib import contextmanager
from itertools import count
from unittest import mock

from reproit_sdk import automatic_adapters, sqlite_adapter
from reproit_sdk.engine_operation import (
    _PROJECT_CONSTRUCTOR,
    ManagedEngineProject,
    OperationPreparation,
    run_operation,
)

_BRIDGE_IDS = count(1)


class SqliteBridge:
    def __init__(
        self,
        action: str,
        replay_responses: list[dict[str, object]] | None = None,
    ) -> None:
        self.abandoned = 0
        self.action = action
        self.bridge_id = next(_BRIDGE_IDS)
        self.current_response: dict[str, object] | None = None
        self.next_handle = 4
        self.offset = 0
        self.operation_count = 0
        self.replay_responses = list(replay_responses or [])
        self.requests: list[dict[str, object]] = []
        self.responses: list[dict[str, object]] = []
        self.unowned: list[tuple[str, bytes]] = []

    def operation_begin(self, _engine: int, _begin: object) -> object:
        self.operation_count += 1
        operation_id = f"op_sqlite_{self.bridge_id}_{self.operation_count}"
        return type("Native", (), {"handle": 2, "operation_id": operation_id})()

    def operation_input(self, *_arguments: object) -> None:
        pass

    def dependency_open(
        self,
        _handle: int,
        request: dict[str, object],
        _parent: str | None,
    ) -> object:
        self.requests.append(request)
        handle = self.next_handle
        self.next_handle += 1
        if self.action == "replay":
            self.current_response = (
                self.replay_responses.pop(0) if self.replay_responses else None
            )
            self.offset = 0
        return type("Dependency", (), {"handle": handle, "action": self.action})()

    def observation_read(self, _handle: int) -> tuple[bytes, bool]:
        data = _response_record(self.current_response)
        end = min(self.offset + 97, len(data))
        chunk = data[self.offset : end]
        self.offset = end
        return chunk, end == len(data)

    def dependency_finish(
        self,
        _handle: int,
        response: dict[str, object] | None,
    ) -> str | None:
        if response is not None:
            self.responses.append(response)
            return str(response["outcome"])
        if self.current_response is None:
            return None
        return str(self.current_response["outcome"])

    def operation_unowned(
        self,
        _handle: int,
        observation_class: str,
        evidence: bytes,
        _parent: str | None,
    ) -> None:
        self.unowned.append((observation_class, bytes(evidence)))

    def operation_succeed(self, *_arguments: object) -> None:
        pass

    def operation_abandon(self, _handle: int) -> None:
        self.abandoned += 1

    def engine_close(self, _handle: int) -> None:
        pass


class SqliteAdapterTests(unittest.TestCase):
    def tearDown(self) -> None:
        while automatic_adapters._OPEN_PROJECTS:
            automatic_adapters._release_automatic_adapters()
        with sqlite_adapter._LOCK:
            sqlite_adapter._UNSUPPORTED_PROCESS_BOUNDARY = False

    def test_install_is_shared_and_the_last_release_restores_connect(self) -> None:
        original = sqlite3.connect
        original_connection = sqlite3.Connection
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        installed = sqlite3.connect
        self.assertIsNot(installed, original)
        self.assertIs(sqlite_dbapi2.connect, installed)
        self.assertIs(sqlite_native.connect, installed)
        self.assertIsNot(sqlite3.Connection, original_connection)
        direct = sqlite3.Connection(":memory:")
        try:
            self.assertIsInstance(direct, original_connection)
            self.assertEqual(direct.execute("SELECT 1").fetchone(), (1,))
        finally:
            direct.close()
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        self.assertIs(sqlite3.connect, installed)
        automatic_adapters._release_automatic_adapters()
        self.assertIs(sqlite3.connect, installed)
        automatic_adapters._release_automatic_adapters()
        self.assertIs(sqlite3.connect, original)
        self.assertIs(sqlite_dbapi2.connect, original)
        self.assertIs(sqlite_native.connect, original)
        self.assertIs(sqlite3.Connection, original_connection)

    def test_failed_sqlite_install_restores_all_hooks_and_skips_registration(self) -> None:
        original_connect = sqlite3.connect
        original_time_ns = automatic_adapters._ORIGINAL_TIME_NS
        with mock.patch.object(
            automatic_adapters,
            "_install_sqlite_adapter",
            side_effect=RuntimeError("hook unavailable"),
        ):
            self.assertFalse(automatic_adapters._acquire_automatic_adapters())
        self.assertIs(sqlite3.connect, original_connect)
        self.assertIs(automatic_adapters.time.time_ns, original_time_ns)
        self.assertEqual(automatic_adapters._OPEN_PROJECTS, 0)

    def test_execute_and_fetch_replay_without_live_sqlite(self) -> None:
        with _adapters():
            connection = sqlite3.connect(":memory:")
            bridge = SqliteBridge("capture")
            try:
                value = _run(
                    bridge,
                    lambda: self._database_sequence(connection),
                )
            finally:
                connection.close()
        self.assertEqual(len(bridge.requests), 7)
        self.assertEqual(
            [_request_payload(request)[1] for request in bridge.requests],
            [
                "execute",
                "execute",
                "execute",
                "execute",
                "fetchone",
                "execute",
                "fetchall",
            ],
        )
        self.assertEqual(value["one"], (7, b"one"))
        self.assertEqual(value["all"], [(7, b"one"), (8, b"two")])

        with _adapters():
            replay_connection = sqlite3.connect(":memory:")
            replay_connection.close()
            replay = SqliteBridge("replay", bridge.responses)
            replay_value = _run(
                replay,
                lambda: self._database_sequence(replay_connection),
            )
        self.assertEqual(replay_value, value)
        self.assertEqual(
            [_request_payload(request) for request in replay.requests],
            [_request_payload(request) for request in bridge.requests],
        )

    def test_ordered_named_and_scalar_values_have_canonical_shapes(self) -> None:
        with _adapters():
            connection = sqlite3.connect(":memory:")
            bridge = SqliteBridge("capture")
            try:
                ordered = _run(
                    bridge,
                    lambda: connection.execute(
                        "SELECT ?, ?, ?, ?, ?",
                        (None, -0.0, "text", b"\x00\xff", 9),
                    ).fetchone(),
                )
                named = _run(
                    bridge,
                    lambda: connection.execute(
                        "SELECT :second, :first",
                        {"second": 2, "first": 1},
                    ).fetchone(),
                )
            finally:
                connection.close()
        self.assertEqual(ordered, (None, -0.0, "text", b"\x00\xff", 9))
        self.assertEqual(named, (2, 1))
        ordered_request = _request_payload(bridge.requests[0])
        self.assertEqual(
            ordered_request[5],
            [
                "ordered",
                [
                    ["null"],
                    ["float", "-0.0"],
                    ["string", "text"],
                    ["bytes", "AP8"],
                    ["integer", 9],
                ],
            ],
        )
        named_request = _request_payload(bridge.requests[2])
        self.assertEqual(
            [field[0] for field in named_request[5][1]],
            ["second", "first"],
        )

    def test_explicit_cursor_replays_as_a_sqlite_cursor_surrogate(self) -> None:
        with _adapters():
            connection = sqlite3.connect(":memory:")
            bridge = SqliteBridge("capture")
            try:
                value = _run(bridge, lambda: self._explicit_cursor(connection))
            finally:
                connection.close()
        self.assertEqual(value, (3,))
        self.assertEqual(
            [_request_payload(request)[1] for request in bridge.requests],
            ["cursor", "execute", "fetchone"],
        )

        with _adapters():
            replay_connection = sqlite3.connect(":memory:")
            replay_connection.close()
            replay = SqliteBridge("replay", bridge.responses)
            replay_value = _run(
                replay,
                lambda: self._explicit_cursor(replay_connection),
            )
        self.assertEqual(replay_value, value)

    def test_capture_preserves_exact_result_and_exception(self) -> None:
        sentinel_row = (41,)
        sentinel_error = RuntimeError("application sentinel")

        class FakeCursor:
            @staticmethod
            def fetchone(_cursor: object) -> tuple[int]:
                return sentinel_row

            @staticmethod
            def execute(
                _cursor: object,
                *_arguments: object,
                **_keywords: object,
            ) -> object:
                raise sentinel_error

        with _adapters():
            connection = sqlite3.connect(":memory:")
            cursor = connection.cursor()
            try:
                with mock.patch.object(sqlite_adapter, "_ORIGINAL_CURSOR", FakeCursor):
                    result_bridge = SqliteBridge("capture")
                    self.assertIs(_run(result_bridge, cursor.fetchone), sentinel_row)
                    error_bridge = SqliteBridge("capture")
                    with self.assertRaises(RuntimeError) as raised:
                        _run(error_bridge, lambda: connection.execute("SELECT 1"))
                    self.assertIs(raised.exception, sentinel_error)
                    self.assertEqual(error_bridge.abandoned, 1)
            finally:
                connection.close()

    def test_unsupported_and_over_limit_calls_are_unowned(self) -> None:
        with _adapters():
            open_bridge = SqliteBridge("capture")
            opened = _run(open_bridge, lambda: sqlite3.connect(":memory:"))
            opened.close()
            self.assertEqual(
                [item[0] for item in open_bridge.unowned],
                ["database"],
            )

            connection = sqlite3.connect(":memory:")
            connection.execute("CREATE TABLE records (value INTEGER)")
            try:
                limit_bridge = SqliteBridge("capture")
                value = _run(
                    limit_bridge,
                    lambda: connection.execute(
                        "SELECT length(?)",
                        ("x" * (16 * 1_024 + 1),),
                    ).fetchone(),
                )
                self.assertEqual(value, (16 * 1_024 + 1,))
                self.assertEqual(limit_bridge.requests, [])
                self.assertEqual(
                    [item[0] for item in limit_bridge.unowned],
                    ["database"],
                )

                unsupported = SqliteBridge("capture")
                _run(
                    unsupported,
                    lambda: connection.executemany(
                        "INSERT INTO records VALUES (?)",
                        [(1,), (2,)],
                    ),
                )
                cursor = connection.execute("SELECT value FROM records")
                _run(unsupported, lambda: list(cursor))
                _run(unsupported, lambda: connection.serialize())
                self.assertGreaterEqual(len(unsupported.unowned), 3)
                self.assertTrue(
                    all(item[0] == "database" for item in unsupported.unowned)
                )
            finally:
                connection.close()

    def test_database_and_cursor_identity_limits_stop_before_engine_open(self) -> None:
        with _adapters():
            with mock.patch.object(
                sqlite_adapter,
                "_NEXT_DATABASE_ID",
                sqlite_adapter._MAX_DATABASES + 1,
            ):
                connection = sqlite3.connect(":memory:")
            database_bridge = SqliteBridge("capture")
            try:
                self.assertEqual(
                    _run(
                        database_bridge,
                        lambda: connection.execute("SELECT 1").fetchone(),
                    ),
                    (1,),
                )
            finally:
                connection.close()
            self.assertEqual(database_bridge.requests, [])
            self.assertEqual(len(database_bridge.unowned), 1)

            connection = sqlite3.connect(":memory:")
            state = sqlite_adapter._connection_state(connection)
            assert state is not None
            state.next_cursor_id = sqlite_adapter._MAX_CURSORS_PER_DATABASE + 1
            cursor_bridge = SqliteBridge("capture")
            try:
                self.assertEqual(
                    _run(
                        cursor_bridge,
                        lambda: connection.execute("SELECT 2").fetchone(),
                    ),
                    (2,),
                )
            finally:
                connection.close()
            self.assertEqual(cursor_bridge.requests, [])
            self.assertGreaterEqual(len(cursor_bridge.unowned), 1)
            self.assertTrue(
                all(item[0] == "database" for item in cursor_bridge.unowned)
            )

    def test_noncanonical_replay_payload_stops_without_live_sqlite(self) -> None:
        with _adapters():
            connection = sqlite3.connect(":memory:")
            capture = SqliteBridge("capture")
            try:
                _run(capture, lambda: connection.execute("SELECT 1"))
            finally:
                connection.close()
        response = dict(capture.responses[0])
        encoded = response["payload"]
        assert isinstance(encoded, str)
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
        response["payload"] = base64.urlsafe_b64encode(b" " + payload).rstrip(b"=").decode()

        with _adapters():
            replay_connection = sqlite3.connect(":memory:")
            replay_connection.close()
            replay = SqliteBridge("replay", [response])
            with self.assertRaisesRegex(RuntimeError, "recorded SQLite dependency"):
                _run(replay, lambda: replay_connection.execute("SELECT 1"))

    def test_retained_original_factory_is_not_replaced(self) -> None:
        with _adapters():
            bridge = SqliteBridge("capture")
            connection = _run(
                bridge,
                lambda: sqlite3.connect(
                    ":memory:",
                    factory=sqlite_adapter._ORIGINAL_CONNECTION,
                ),
            )
            try:
                self.assertIs(type(connection), sqlite_adapter._ORIGINAL_CONNECTION)
            finally:
                connection.close()
        self.assertEqual([item[0] for item in bridge.unowned], ["database"])

    def test_custom_connection_factory_poison_marks_later_operations(self) -> None:
        class CustomConnection(sqlite_adapter._ORIGINAL_CONNECTION):
            pass

        with _adapters():
            connection = sqlite3.connect(":memory:", factory=CustomConnection)
            bridge = SqliteBridge("capture")
            try:
                self.assertEqual(_run(bridge, lambda: 7), 7)
            finally:
                connection.close()
        self.assertEqual(
            [item[0] for item in bridge.unowned],
            ["database"],
        )

    @staticmethod
    def _database_sequence(connection: sqlite3.Connection) -> dict[str, object]:
        connection.execute("CREATE TABLE records (id INTEGER, body BLOB)")
        connection.execute("INSERT INTO records VALUES (?, ?)", (7, b"one"))
        connection.execute("INSERT INTO records VALUES (?, ?)", (8, b"two"))
        one = connection.execute(
            "SELECT id, body FROM records WHERE id = ?",
            (7,),
        ).fetchone()
        all_rows = connection.execute(
            "SELECT id, body FROM records ORDER BY id",
        ).fetchall()
        return {"all": all_rows, "one": one}

    @staticmethod
    def _explicit_cursor(connection: sqlite3.Connection) -> tuple[object, ...] | None:
        cursor = connection.cursor()
        if not isinstance(cursor, sqlite_adapter._ORIGINAL_CURSOR):
            raise AssertionError("The managed cursor changed SQLite identity.")
        if cursor.connection is not connection:
            raise AssertionError("The managed cursor changed its connection.")
        cursor.execute("SELECT ?", (3,))
        return cursor.fetchone()


def _response_record(response: dict[str, object] | None) -> bytes:
    if response is None:
        return b"null"
    return json.dumps(response, separators=(",", ":")).encode("utf-8")


def _request_payload(request: dict[str, object]) -> object:
    value = request["payload"]
    assert isinstance(value, str)
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    return json.loads(decoded)


def _run(bridge: SqliteBridge, operation: object) -> object:
    project = ManagedEngineProject(
        _PROJECT_CONSTRUCTOR,
        bridge,
        1,
        lambda: "unused",
        False,
    )
    preparation = OperationPreparation({}, (), "return")
    return run_operation(
        project,
        preparation,
        lambda _context: operation(),
        lambda _error: None,
    )


@contextmanager
def _adapters() -> object:
    if not automatic_adapters._acquire_automatic_adapters():
        raise RuntimeError("The automatic adapters did not install.")
    try:
        yield
    finally:
        automatic_adapters._release_automatic_adapters()


if __name__ == "__main__":
    unittest.main()
