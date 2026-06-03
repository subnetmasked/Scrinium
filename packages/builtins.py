"""Built-in NavApp entries for Documentation and Dashboard."""
from __future__ import annotations

from packages.registry import NavApp, register_nav_app


def _always(user) -> bool:
    return user is not None


def register_builtin_nav_apps() -> None:
    register_nav_app(
        NavApp(
            id="documentation",
            name="Documentation",
            icon="folder",
            endpoint="index",
            accessible=_always,
        )
    )
    register_nav_app(
        NavApp(
            id="dashboard",
            name="Dashboard",
            icon="globe",
            endpoint="dash",
            accessible=_always,
        )
    )
