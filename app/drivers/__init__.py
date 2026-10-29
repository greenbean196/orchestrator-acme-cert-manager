"""Deploy-target drivers. ``get(name)`` returns the singleton for a driver name."""
from __future__ import annotations

from .base import CertBundle, Driver, Field  # noqa: F401  (re-exported)

_REGISTRY: dict[str, Driver] = {}


def register(driver: Driver) -> Driver:
    _REGISTRY[driver.name] = driver
    return driver


def get(name: str) -> Driver:
    _load_builtin()
    try:
        return _REGISTRY[name]
    except KeyError:
        from .. import config
        raise config.ConfigError(f"unknown target driver {name!r}; known: {', '.join(sorted(_REGISTRY))}") from None


def names() -> list[str]:
    _load_builtin()
    return sorted(_REGISTRY)


def all_drivers() -> list[Driver]:
    _load_builtin()
    return [_REGISTRY[n] for n in sorted(_REGISTRY, key=lambda n: (n != "orchestrator", n))]


def choices() -> list[tuple[str, str]]:
    return [(d.name, d.label) for d in all_drivers()]


_loaded = False


def _load_builtin() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import clearpass, edgeconnect, orchestrator, ssh  # noqa: F401  (register on import)
