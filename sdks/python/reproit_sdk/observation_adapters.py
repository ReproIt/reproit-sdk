"""Package-owned registry for installed semantic observation adapters."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .native_engine import MAX_OBSERVATION_ADAPTERS, NativeObservationClass


@dataclass(frozen=True)
class _ObservationAdapterRegistration:
    adapter_id: str
    adapter_version: str
    observation_class: NativeObservationClass
    implementation_digest: str

    def engine_input(self) -> dict[str, str]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "class": self.observation_class,
            "implementation_digest": self.implementation_digest,
        }


_LOCK = threading.Lock()
_INSTALLED: dict[NativeObservationClass, _ObservationAdapterRegistration] = {}


def _install_observation_adapter(
    registration: _ObservationAdapterRegistration,
) -> None:
    """Install one real package-owned adapter before an engine opens."""
    if not isinstance(registration, _ObservationAdapterRegistration):
        raise TypeError("The observation adapter registration is invalid.")
    with _LOCK:
        if registration.observation_class in _INSTALLED:
            raise ValueError("The observation adapter is already installed.")
        if len(_INSTALLED) >= MAX_OBSERVATION_ADAPTERS:
            raise ValueError("The observation adapter limit was reached.")
        _INSTALLED[registration.observation_class] = registration


def _installed_observation_adapters() -> list[dict[str, str]]:
    """Return a stable copy of the package-owned installed adapters."""
    with _LOCK:
        return [
            _INSTALLED[observation_class].engine_input()
            for observation_class in sorted(_INSTALLED)
        ]
