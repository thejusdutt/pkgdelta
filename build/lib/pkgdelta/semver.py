"""Just enough semver to order npm versions. Not a range parser."""
import re

_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse(v: str):
    m = _RE.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    pre_key = ()
    if pre:
        parts = []
        for p in pre.split("."):
            parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
        pre_key = tuple(parts)
    return int(major), int(minor), int(patch), pre_key


def key(v: str):
    """Sort key. Invalid versions sort first. A release sorts after its prereleases."""
    p = parse(v)
    if p is None:
        return (-1, -1, -1, 0, ())
    major, minor, patch, pre = p
    return (major, minor, patch, 0 if pre else 1, pre)


def is_prerelease(v: str) -> bool:
    p = parse(v)
    return bool(p and p[3])


def bump_kind(old: str, new: str) -> str:
    a, b = parse(old), parse(new)
    if not a or not b:
        return "unknown"
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    if b[2] != a[2]:
        return "patch"
    return "prerelease"
