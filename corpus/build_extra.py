"""Second holdout: takeovers published after the DataDog dataset ends (2026-06-25).

Walks OSV MAL-2026-* ids, keeps npm entries published after the cutoff whose
package has earlier clean versions on the registry (a takeover, not a new
malicious package), and recovers the malicious tarball from jsDelivr's cache
when it still has it. Tarballs are stored as .tgz, never extracted to disk.
"""
import concurrent.futures as cf
import io
import json
import re
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
        t = path.read_text(encoding="utf-8")
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
    missing = []
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in listing.get("files", []):
            p = f["name"].lstrip("/")
            if f.get("size", 0) > 64 * 1024 * 1024:
                continue
            try:
                b = urllib.request.urlopen(base + "/" + urllib.parse.quote(p), timeout=120).read()
            except Exception:
                missing.append(p)  # a missing file shows up as "removed", which no rule looks at
                continue
            ti = tarfile.TarInfo("package/" + p)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    return buf.getvalue(), missing


# Phrases that describe a hijacked release. GitHub's generic malware notice
# ("should be considered fully compromised") is removed first; it says nothing
# about how the package came to be malicious.
COMPROMISE = re.compile(r"btrojaniz|bhijack|\bworm\b|account takeover|maintainer(?:'s)? (?:npm |github )?account|shai-hulud|chaindrop|miasma|"
                        r"self-propagat|compromised (?:npm |github )?(?:maintainer|account|token|publish|release|version|package|credentials)|"
                        r"compromise of the|legitimate package")
BOILERPLATE = re.compile(r"any computer that has this package installed.*?(?:installing it|$)", re.S)


def label_kind(vid: str) -> str:
    """'compromise' when the advisory text describes a hijacked release,
    otherwise 'automated' (usually one scanner judging the package on its own)."""
    t = (source.CACHE / "osv_ids" / f"{vid}.json").read_text(encoding="utf-8")
    e = json.loads(t) if t else {}
    text = BOILERPLATE.sub("", ((e.get("summary") or "") + " " + (e.get("details") or "")).lower())
    return "compromise" if COMPROMISE.search(text) else "automated"


def main():
    with cf.ThreadPoolExecutor(24) as ex:
        entries = [e for e in ex.map(osv, ID_RANGE) if e]
    from corpus.build_mal import osv_mal_versions
    import datetime as dt
    by_pkg: dict[str, list] = {}
    for e in entries:
        if e.get("published", "") < CUTOFF:
            continue
        for a in e.get("affected", []):
            if a.get("package", {}).get("ecosystem") != "npm":
                continue
            for v in a.get("versions", []):
                by_pkg.setdefault(a["package"]["name"], []).append((v, e["id"], e.get("published", "")[:10]))
    print(f"{len(entries)} OSV entries, {len(by_pkg)} npm packages with entries after {CUTOFF}", flush=True)

    def one_pkg(name):
        """A takeover: an established clean release (30+ days older, not in any
        MAL entry for the package) followed by a malicious one. At most 3
        malicious versions per package so one package can't dominate."""
        try:
            pack = source.packument(name, max_age=10 ** 9)
            bad = osv_mal_versions(name) | {v for v, _, _ in by_pkg[name]}
        except Exception:
            return []
        times = pack.get("time", {})
        out = []
        for ver, vid, pub in sorted(by_pkg[name], key=lambda x: semver.key(x[0]))[:3]:
            mal_t = times.get(ver)
            if not mal_t:
                continue
            cutoff = (dt.datetime.fromisoformat(mal_t.replace("Z", "+00:00")) - dt.timedelta(days=30)).isoformat()
            clean = [v for v in pack.get("versions", {}) if semver.parse(v) and "security" not in v and v not in bad
                     and semver.key(v) < semver.key(ver) and times.get(v, "9") < mal_t]
            if not clean or min(times[v] for v in clean) > cutoff.replace("+00:00", "Z"):
                continue  # new package or a one-day-old decoy, not a takeover
            r = one((name, ver, vid, pub, pack, clean))
            if r:
                out.append(r)
        return out

    def one(c):
        name, ver, vid, pub, pack, clean = c
        times = pack.get("time", {})
        mal_t = times.get(ver)
        stable = [v for v in clean if not semver.is_prerelease(v)]
        base = max(stable or clean, key=semver.key)
        out = DATA / "extra" / f"{name.replace('/', '__')}@{ver}.tgz"
        missing = []
        if not out.exists():
            got = jsdelivr_tgz(name, ver)
            if not got:
                return {"name": name, "mal_version": ver, "osv": vid, "drop": "tarball gone"}
            b, missing = got
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b)
        source.tarball_bytes(name, base, pack["versions"][base].get("dist", {}).get("tarball"))
        return {"name": name, "mal_version": ver, "base_version": base, "osv": vid, "discovered": pub,
                "mal_published": mal_t, "tgz": str(out.relative_to(DATA)).replace("\\", "/"),
                "missing_files": len(missing), "label": label_kind(vid)}

    with cf.ThreadPoolExecutor(12) as ex:
        recs = [r for rs in ex.map(one_pkg, sorted(by_pkg)) for r in rs]
    with open(DATA / "extra_pairs.jsonl", "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    kept = [r for r in recs if "drop" not in r]
    print(f"{len(recs)} takeover versions, {len(kept)} recoverable")
    for r in kept:
        print("  ", r["discovered"], r["name"], r["base_version"], "->", r["mal_version"])


if __name__ == "__main__":
    main()
