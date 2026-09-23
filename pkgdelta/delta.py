"""Structural difference between two versions of the same package."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .source import Package

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
             "prepublish", "preuninstall", "uninstall", "postuninstall")


@dataclass
class Delta:
    old: Package
    new: Package
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    same: list[str] = field(default_factory=list)
    pack: dict | None = None  # registry record for the package, when known

    @property
    def touched(self) -> list[str]:
        return self.added + self.changed


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def compute(old: Package, new: Package, pack: dict | None = None) -> Delta:
    d = Delta(old, new, pack=pack)
    oh = {p: _h(b) for p, b in old.files.items()}
    for p, b in new.files.items():
        if p not in oh:
            d.added.append(p)
        elif oh[p] != _h(b):
            d.changed.append(p)
        else:
            d.same.append(p)
    d.removed = [p for p in old.files if p not in new.files]
    d.added.sort(); d.changed.sort(); d.removed.sort()
    return d


def lifecycle_scripts(man: dict) -> dict[str, str]:
    s = man.get("scripts") or {}
    if not isinstance(s, dict):
        return {}
    return {k: str(v) for k, v in s.items() if k in LIFECYCLE}


def deps(man: dict) -> dict[str, str]:
    out = {}
    for k in ("dependencies", "optionalDependencies", "peerDependencies"):
        v = man.get(k) or {}
        if isinstance(v, dict):
            out.update({n: str(r) for n, r in v.items()})
    return out
