"""Build benign (previous, next) pairs from real updates of top npm packages.

Same baseline rule as the malicious pairs, so the two sets are comparable:
the newest stable version below the target that was published before it.
Targets are the last N stable releases of each package. Known-malicious
versions (OSV MAL-) are excluded as targets and as baselines.
"""
import concurrent.futures as cf
import json
import pathlib
import sys
import urllib.request
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pkgdelta import semver, source  # noqa: E402
from corpus.build_mal import osv_mal_versions, ts  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"
TOP_N = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
PER_PKG = int(sys.argv[2]) if len(sys.argv) > 2 else 6


def top_packages() -> list[str]:
    path = DATA / "top.js"
    if not path.exists():
        path.write_bytes(urllib.request.urlopen("https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top.js", timeout=60).read())
    names = []
    for line in path.read_text().splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("'") and line.endswith("'"):
            names.append(line[1:-1])
    return names


def pairs_for(name: str) -> list[dict]:
    try:
        pack = source.packument(name, max_age=10 ** 9)
    except Exception as e:
        return [{"name": name, "drop": f"packument {e}"}]
    bad = osv_mal_versions(name)
    times = pack.get("time", {})
    live = [v for v in pack.get("versions", {}) if v not in bad and semver.parse(v)
            and not semver.is_prerelease(v) and times.get(v)]
    live.sort(key=lambda v: times[v])
    out = []
    for tgt in reversed(live):
        if len(out) >= PER_PKG:
            break
        t = ts(times[tgt])
        cands = [v for v in live if semver.key(v) < semver.key(tgt) and ts(times[v]) < t]
        if not cands:
            continue
        base = max(cands, key=semver.key)
        rec = {"name": name, "base_version": base, "new_version": tgt, "bump": semver.bump_kind(base, tgt),
               "base_published": times[base], "new_published": times[tgt],
               "split": "train" if zlib.crc32(name.encode()) % 2 == 0 else "test"}
        try:
            for v in (base, tgt):
                source.tarball_bytes(name, v, pack["versions"][v].get("dist", {}).get("tarball"))
        except Exception as e:
            rec["drop"] = f"tarball {e}"
        out.append(rec)
    return out


def main():
    names = top_packages()[:TOP_N]
    with cf.ThreadPoolExecutor(16) as ex:
        res = list(ex.map(pairs_for, names))
    recs = [r for rs in res for r in rs]
    with (DATA / "benign_pairs.jsonl").open("w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    kept = [r for r in recs if "drop" not in r]
    print(f"{len(names)} packages, {len(kept)} pairs kept, {len(recs) - len(kept)} dropped")


if __name__ == "__main__":
    main()
