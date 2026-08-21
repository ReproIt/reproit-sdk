"""Test-only candidate storage for SDK conformance checks."""


class MemorySink:
    """Store candidate bytes without external I/O."""

    def __init__(self) -> None:
        self.candidates: list[bytes] = []

    @property
    def processing_modes(self) -> frozenset[str]:
        return frozenset(("managed", "private"))

    @property
    def queued_bytes(self) -> int:
        return 0

    def try_send(self, capture_id: str, candidate: bytes) -> bool:
        del capture_id
        self.candidates.append(candidate)
        return True
