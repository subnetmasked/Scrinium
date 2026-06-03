"""Package / module / nav-app registry for the Scrinium platform."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from flask import Blueprint


@dataclass(frozen=True)
class Role:
    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    icon: str
    blueprint: Blueprint
    migrate: Callable[[Any], None]
    summary_card: Callable[[Any, Optional[str]], dict]
    default_config: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Package:
    id: str
    name: str
    icon: str
    roles: tuple[Role, ...]
    modules: tuple[Module, ...]
    admin_view: Callable[..., Any]
    landing_view: Callable[..., Any]


@dataclass(frozen=True)
class NavApp:
    id: str
    name: str
    icon: str
    endpoint: str
    accessible: Callable[[Any], bool]


_packages: dict[str, Package] = {}
_nav_apps: list[NavApp] = []
_RESERVED_IDS = frozenset({"security", "itsm"})


def register_package(pkg: Package) -> None:
    if pkg.id in _packages:
        raise ValueError(f"Package already registered: {pkg.id!r}")
    _packages[pkg.id] = pkg


def register_nav_app(app: NavApp) -> None:
    _nav_apps.append(app)


def get_package(package_id: str) -> Optional[Package]:
    return _packages.get(package_id)


def iter_packages() -> list[Package]:
    return list(_packages.values())


def iter_nav_apps() -> list[NavApp]:
    return list(_nav_apps)


def reserved_package_ids() -> frozenset[str]:
    return _RESERVED_IDS | frozenset(_packages.keys())


def get_module(package_id: str, module_id: str) -> Optional[Module]:
    pkg = _packages.get(package_id)
    if pkg is None:
        return None
    for mod in pkg.modules:
        if mod.id == module_id:
            return mod
    return None
