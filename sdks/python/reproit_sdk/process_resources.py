"""One bounded process reservation for subject-discovery bytes."""

from __future__ import annotations

import threading

MAX_PROCESS_LOGICAL_BYTES = 4 * 1024 * 1024 * 1024


class ProcessResources:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._logical_bytes = 0

    def reserve_logical(self, size: int) -> bool:
        with self._lock:
            if size < 0 or self._logical_bytes > MAX_PROCESS_LOGICAL_BYTES - size:
                return False
            self._logical_bytes += size
            return True

    def release_logical(self, size: int) -> None:
        with self._lock:
            self._logical_bytes = max(0, self._logical_bytes - size)


PROCESS_RESOURCES = ProcessResources()
