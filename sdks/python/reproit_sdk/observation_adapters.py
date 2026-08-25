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
_ACTIVE: dict[NativeObservationClass, _ObservationAdapterRegistration] = {}


def _activate_observation_adapters(
    registrations: tuple[_ObservationAdapterRegistration, ...],
) -> None:
    """Publish one complete set of active package-owned adapters."""
    if not registrations or not all(
        isinstance(value, _ObservationAdapterRegistration)
        for value in registrations
    ):
        raise TypeError("The observation adapter registration is invalid.")
    classes = [value.observation_class for value in registrations]
    if len(classes) != len(set(classes)):
        raise ValueError("The observation adapter class is duplicated.")
    if len(registrations) > MAX_OBSERVATION_ADAPTERS:
        raise ValueError("The observation adapter limit was reached.")
    with _LOCK:
        if _ACTIVE:
            raise ValueError("Observation adapters are already active.")
        _ACTIVE.update(
            (value.observation_class, value) for value in registrations
        )


def _deactivate_observation_adapters(
    registrations: tuple[_ObservationAdapterRegistration, ...],
) -> None:
    """Remove only the active package-owned adapter set."""
    with _LOCK:
        if any(
            _ACTIVE.get(value.observation_class) != value
            for value in registrations
        ):
            _ACTIVE.clear()
            return
        for value in registrations:
            _ACTIVE.pop(value.observation_class, None)


def _installed_observation_adapters() -> list[dict[str, str]]:
    """Return a stable copy of the package-owned installed adapters."""
    with _LOCK:
        return [
            _ACTIVE[observation_class].engine_input()
            for observation_class in sorted(_ACTIVE)
        ]
