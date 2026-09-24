"""pkgdelta: check npm updates against the package's own previous release.

  pkgdelta check <name> <new-version> [--against <old-version>]
  pkgdelta diff  <old-lockfile> <new-lockfile>
  pkgdelta audit <lockfile> [--since 30d]

Exit code 1 when any version is blocked, 0 otherwise, 2 on usage errors.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import sys

from . import delta, lockfile, rules, semver, source

SEV_MARK = {"high": "HIGH", "medium": "MED ", "low": "low "}


def predecessor(pack: dict, version: str) -> str | None:
    """Newest release below `version` that was published before it."""
    times = pack.get("time") or {}
    t = times.get(version)
    stable_only = not semver.is_prerelease(version)
    cands = []
    for v in pack.get("versions") or {}:
        if semver.parse(v) is None or "security" in v or semver.key(v) >= semver.key(version):
            continue
        if t and times.get(v) and times[v] >= t:
            continue
        cands.append(v)
    stable = [v for v in cands if not semver.is_prerelease(v)]
    if stable_only and stable:
        cands = stable
    return max(cands, key=semver.key) if cands else None


def dep_lookup(name: str, published: str | None):
    try:
        pack = source.packument(name)
    except Exception:
        return None
    created = (pack.get("time") or {}).get("created")
    if not created or not published:
        return None
    a = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
    b = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
    hooks = any(k in (m.get("scripts") or {}) for m in (pack.get("versions") or {}).values() for k in rules.INSTALL_HOOKS)
    return (b - a).total_seconds() / 86400, hooks, rules._maintainers(pack)


def check_one(name: str, version: str, against: str | None = None) -> dict:
    try:
        pack = source.packument(name)
        if version not in (pack.get("versions") or {}):
            return {"name": name, "new": version, "error": "version not on the registry (unpublished?)"}
        base = against or predecessor(pack, version)
        if not base:
            return {"name": name, "new": version, "skipped": "first release, nothing to compare with"}
        old = source.from_registry(name, base, pack)
        new = source.from_registry(name, version, pack)
        return rules.evaluate(delta.compute(old, new, pack), dep_lookup).as_dict()
    except Exception as e:
        return {"name": name, "new": version, "error": f"{type(e).__name__}: {e}"}


def run_many(items: list[tuple[str, str, str | None]], workers: int) -> list[dict]:
    with cf.ThreadPoolExecutor(workers) as ex:
        return list(ex.map(lambda it: check_one(*it), items))


def show(results: list[dict], verbose: bool) -> None:
    blocked = [r for r in results if r.get("blocked")]
    for r in results:
        if "error" in r:
            print(f"  ?  {r['name']}@{r['new']}: {r['error']}")
            continue
        if "skipped" in r:
            if verbose:
                print(f"  -  {r['name']}@{r['new']}: {r['skipped']}")
            continue
        if not r["findings"] and not verbose:
            continue
        mark = "BLOCK" if r["blocked"] else ("warn " if r["findings"] else "ok   ")
        print(f"{mark} {r['name']} {r['old']} -> {r['new']}  (score {r['score']})")
        for f in r["findings"]:
            loc = f" [{f['file']}]" if f.get("file") else ""
            print(f"        {SEV_MARK[f['severity']]} {f['rule']}: {f['message']}{loc}")
            if f.get("evidence"):
                print(f"             {f['evidence']}")
    ok = sum(1 for r in results if "findings" in r)
    print(f"\n{len(results)} versions checked ({ok} compared), {len(blocked)} blocked.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pkgdelta", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check one package version")
    c.add_argument("name")
    c.add_argument("version")
    c.add_argument("--against", help="compare with this version instead of the previous release")
    d = sub.add_parser("diff", help="check every version a lockfile change brings in")
    d.add_argument("old")
    d.add_argument("new")
    a = sub.add_parser("audit", help="check every version in a lockfile against its previous release")
    a.add_argument("lock")
    for p in (c, d, a):
        p.add_argument("--json", action="store_true", help="print JSON")
        p.add_argument("-v", "--verbose", action="store_true")
        p.add_argument("-j", "--jobs", type=int, default=8)
    args = ap.parse_args(argv)

    if args.cmd == "check":
        items = [(args.name, args.version, args.against)]
    elif args.cmd == "diff":
        items = [(n, v, None) for n, v, _ in lockfile.changes(lockfile.read(args.old), lockfile.read(args.new))]
    else:
        items = [(n, v, None) for n, v in sorted(lockfile.read(args.lock))]
    if not items:
        print("nothing to check")
        return 0
    results = run_many(items, args.jobs)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        show(results, args.verbose)
    return 1 if any(r.get("blocked") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
