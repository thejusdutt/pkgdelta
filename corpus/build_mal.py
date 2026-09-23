"""Build (clean baseline, malicious version) pairs from the DataDog compromised_lib samples.

Baseline = highest semver version below the malicious one that
  - is not known-malicious (DataDog manifest + OSV MAL- entries),
  - was published before the malicious version,
  - is still downloadable from the registry,
  - is not npm's "0.0.1-security" placeholder.
That models a user who had the last good version and took the update.
"""
import concurrent.futures as cf
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pkgdelta import semver, source  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"
ZIPS = DATA / "dd_zips"


def name_from_dir(d: str) -> str:
    if d.startswith("@") and "@" in d[1:]:
        i = d.index("@", 1)
        return d[:i] + "/" + d[i + 1:]
    return d


def osv_mal_versions(name: str) -> set[str]:
    path = source.CACHE / "osv" / (name.replace("/", "__") + ".json")
    if path.exists():
        d = json.loads(path.read_text())
    else:
        body = json.dumps({"package": {"name": name, "ecosystem": "npm"}}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                     headers={"Content-Type": "application/json"})
        d = json.load(urllib.request.urlopen(req, timeout=60))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(d))
    out = set()
    for v in d.get("vulns", []):
        if v["id"].startswith("MAL-"):
            for a in v.get("affected", []):
                out.update(a.get("versions", []))
    return out


def ts(s: str | None):
    if not s:
        return None
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def build_one(args):
    zpath, dd_man = args
    rel = zpath.relative_to(ZIPS).as_posix()
    pkgdir, ver, fname = rel.split("/")[-3:]
    name = name_from_dir(pkgdir)
    m = re.match(r"(\d{4}-\d{2}-\d{2})-", fname)
    found = m.group(1) if m else None
    rec = {"name": name, "mal_version": ver, "discovered": found, "zip": rel}
    try:
        bad = set(dd_man.get(name) or []) | osv_mal_versions(name)
        bad.add(ver)
        try:
            pack = source.packument(name, max_age=10 ** 9)
        except urllib.error.HTTPError as e:
            rec["drop"] = f"packument {e.code}"
            return rec
        times = pack.get("time", {})
        live = set(pack.get("versions", {}))
        mal_t = ts(times.get(ver)) or (ts(found + "T23:59:59+00:00") if found else None)
        rec["mal_published"] = times.get(ver)
        cands = []
        for v in live:
            if v in bad or "security" in v or semver.parse(v) is None:
                continue
            if semver.key(v) >= semver.key(ver):
                continue
            vt = ts(times.get(v))
            if mal_t and vt and vt >= mal_t:
                continue
            cands.append(v)
        if not cands:
            rec["drop"] = "no clean earlier version"
            return rec
        # users on a stable line get stable updates: prefer a stable baseline
        stable = [v for v in cands if not semver.is_prerelease(v)]
        if stable and not semver.is_prerelease(ver):
            cands = stable
        base = max(cands, key=semver.key)
        rec["base_version"] = base
        rec["base_published"] = times.get(base)
        rec["bump"] = semver.bump_kind(base, ver)
        # make sure the baseline tarball is fetchable now, so eval runs offline
        source.tarball_bytes(name, base, pack["versions"][base].get("dist", {}).get("tarball"))
    except Exception as e:
        rec["drop"] = f"error {type(e).__name__}: {e}"
    return rec


def main():
    dd_man = json.loads((DATA / "dd_manifest.json").read_text())
    zips = sorted(ZIPS.rglob("*.zip"))
    with cf.ThreadPoolExecutor(12) as ex:
        recs = list(ex.map(build_one, [(z, dd_man) for z in zips]))
    out = DATA / "mal_pairs.jsonl"
    with out.open("w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    kept = [r for r in recs if "drop" not in r]
    print(f"{len(recs)} samples, {len(kept)} pairs, {len(recs) - len(kept)} dropped")
    from collections import Counter
    print(Counter(r["drop"].split(":")[0] for r in recs if "drop" in r).most_common(10))
    print(Counter(r["bump"] for r in kept))


if __name__ == "__main__":
    main()
