"""Read resolved (name, version) pairs from npm and pnpm lockfiles."""
from __future__ import annotations

import json
import pathlib
import re


def _npm(text: str) -> set[tuple[str, str]]:
    data = json.loads(text)
    out = set()
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            ver = meta.get("version")
            name = meta.get("name") or path.split("node_modules/")[-1]
            res = meta.get("resolved", "")
            if ver and (not res or "registry" in res or res.endswith(".tgz")):
                out.add((name, ver))
        return out

    def walk(deps):  # lockfile v1
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version") and not str(meta["version"]).startswith(("file:", "git")):
                out.add((name, meta["version"]))
                walk(meta.get("dependencies"))
    walk(data.get("dependencies"))
    return out


_PNPM_KEY = re.compile(r"^\s{2}'?/?((?:@[^/@\s]+/)?[^@\s/']+)[@/](\d[^()'\s:]*)")


def _pnpm(text: str) -> set[tuple[str, str]]:
    out = set()
    section = None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.rstrip(":")
            continue
        if section in ("packages", "snapshots"):
            m = _PNPM_KEY.match(line)
            if m:
                out.add((m.group(1), m.group(2)))
    return out


def _yarn(text: str) -> set[tuple[str, str]]:
    out = set()
    name = None
    for line in text.splitlines():
        if line and not line.startswith(" ") and line.rstrip().endswith(":"):
            key = line.strip().rstrip(":").strip('"').split(",")[0].strip().strip('"')
            at = key.rfind("@")
            name = key[:at] if at > 0 else key
            name = name.split("@npm:")[0]
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and name:
            out.add((name, m.group(1)))
            name = None
    return out


def read(path: str | pathlib.Path) -> set[tuple[str, str]]:
    p = pathlib.Path(path)
    text = p.read_text(encoding="utf-8")
    if p.name.endswith(".json") or text.lstrip().startswith("{"):
        return _npm(text)
    if "lockfileVersion" in text and ("packages:" in text or "importers:" in text):
        return _pnpm(text)
    return _yarn(text)


def changes(old: set[tuple[str, str]], new: set[tuple[str, str]]) -> list[tuple[str, str, str | None]]:
    """(name, new_version, version it replaced or None) for every version that is new in the tree."""
    old_by_name: dict[str, set[str]] = {}
    for n, v in old:
        old_by_name.setdefault(n, set()).add(v)
    out = []
    for n, v in sorted(new - old):
        prev = old_by_name.get(n)
        out.append((n, v, max(prev, key=_skey) if prev else None))
    return out


def _skey(v: str):
    from .semver import key
    return key(v)
