"""Second holdout: takeovers published after the DataDog dataset ends (2026-06-25).

Walks OSV MAL-2026-* ids, keeps npm entries published after the cutoff whose
package has earlier clean versions on the registry (a takeover, not a new
malicious package), and recovers the malicious tarball from jsDelivr's cache
when it still has it. Tarballs are stored as .tgz, never extracted to disk.
"""
import concurrent.futures as cf
import io
import json
import pathlib
import sys
import tarfile
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pkgdelta import semver, source  # noqa: E402

DATA = ROOT / "data"
CUTOFF = "2026-06-26"
ID_RANGE = range(int(sys.argv[1]) if len(sys.argv) > 1 else 5000, int(sys.argv[2]) if len(sys.argv) > 2 else 16000)


def osv(i):
    vid = f"MAL-2026-{i}"
    path = source.CACHE / "osv_ids" / f"{vid}.json"
    if path.exists():
        t = path.read_text()
        return json.loads(t) if t else None
    try:
        d = urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=60).read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        return None
    except Exception:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(d)
    return json.loads(d)


def jsdelivr_tgz(name, version):
    """Rebuild a tarball from jsDelivr's per-file cache (only if the version is really there)."""
    base = f"https://cdn.jsdelivr.net/npm/{name}@{version}"
    try:
        man = json.loads(urllib.request.urlopen(base + "/package.json", timeout=60).read())
        if man.get("version") != version:
            return None
        listing = json.loads(urllib.request.urlopen(
            f"https://data.jsdelivr.com/v1/packages/npm/{name}@{version}?structure=flat", timeout=60).read())
    except Exception:
        return None
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in listing.get("files", []):
            p = f["name"].lstrip("/")
            if f.get("size", 0) > 64 * 1024 * 1024:
                continue
            try:
                b = urllib.request.urlopen(base + "/" + urllib.parse.quote(p), timeout=120).read()
            except Exception:
                return None  # incomplete copy is worse than none
            ti = tarfile.TarInfo("package/" + p)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def main():
    with cf.ThreadPoolExecutor(24) as ex:
        entries = [e for e in ex.map(osv, ID_RANGE) if e]
    cands = []
    for e in entries:
        if e.get("published", "") < CUTOFF:
            continue
        for a in e.get("affected", []):
            if a.get("package", {}).get("ecosystem") != "npm":
                continue
            for v in a.get("versions", []):
                cands.append((a["package"]["name"], v, e["id"], e.get("published", "")[:10]))
    print(f"{len(entries)} OSV entries, {len(cands)} npm versions published after {CUTOFF}")

    def one(c):
        name, ver, vid, pub = c
        try:
            pack = source.packument(name, max_age=10 ** 9)
        except Exception:
            return None
        times = pack.get("time", {})
        mal_t = times.get(ver)
        clean = [v for v in pack.get("versions", {}) if semver.parse(v) and "security" not in v
                 and semver.key(v) < semver.key(ver) and (not mal_t or times.get(v, "") < mal_t)]
        if not clean:
            return None  # new package, not a takeover
        stable = [v for v in clean if not semver.is_prerelease(v)]
        base = max(stable or clean, key=semver.key)
        out = DATA / "extra" / f"{name.replace('/', '__')}@{ver}.tgz"
        if not out.exists():
            b = jsdelivr_tgz(name, ver)
            if not b:
                return {"name": name, "mal_version": ver, "osv": vid, "drop": "tarball gone"}
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b)
        source.tarball_bytes(name, base, pack["versions"][base].get("dist", {}).get("tarball"))
        return {"name": name, "mal_version": ver, "base_version": base, "osv": vid, "discovered": pub,
                "mal_published": mal_t, "tgz": str(out.relative_to(DATA)).replace("\\", "/")}

    with cf.ThreadPoolExecutor(12) as ex:
        recs = [r for r in ex.map(one, cands) if r]
    with open(DATA / "extra_pairs.jsonl", "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    kept = [r for r in recs if "drop" not in r]
    print(f"{len(recs)} takeover versions, {len(kept)} recoverable")
    for r in kept:
        print("  ", r["discovered"], r["name"], r["base_version"], "->", r["mal_version"])


if __name__ == "__main__":
    main()
