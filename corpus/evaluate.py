"""Run pkgdelta over the malicious and benign pairs and print the tables.

usage: python corpus/evaluate.py [--split train|test|all] [--limit N]
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import pathlib
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pkgdelta import delta, rules, source  # noqa: E402
from corpus.campaigns import assign  # noqa: E402

DATA = ROOT / "data"


def dep_lookup(name, published):
    try:
        pack = source.packument(name, max_age=10 ** 9)
    except Exception:
        return None
    created = (pack.get("time") or {}).get("created")
    if not created or not published:
        return None
    a = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
    b = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
    # hooks in any version published before the dependent release
    hooks = False
    for v, meta in (pack.get("versions") or {}).items():
        t = (pack.get("time") or {}).get(v)
        if t and t <= published and any(k in (meta.get("scripts") or {}) for k in rules.INSTALL_HOOKS):
            hooks = True
    from pkgdelta.rules import _maintainers
    return (b - a).total_seconds() / 86400, hooks, _maintainers(pack)


def run_one(job):
    kind, r = job
    try:
        pack = source.packument(r["name"], max_age=10 ** 9)
        old = source.from_registry(r["name"], r["base_version"], pack)
        if kind == "mal":
            new, info = source.from_dd_zip(DATA / "dd_zips" / r["zip"])
            if not new.published:
                new.published = (info.get("time") or {}).get(r["mal_version"]) or r.get("mal_published")
            if not new.meta:
                new.meta = (pack.get("versions") or {}).get(r["mal_version"], {})
        elif kind == "extra":
            new = source.from_tgz_file(DATA / r["tgz"])
            new.published = r.get("mal_published")
            new.meta = r.get("meta") or {}
        else:
            new = source.from_registry(r["name"], r["new_version"], pack)
        if kind == "mal":
            # the live packument may have lost the malicious version; merge the one captured with the sample
            merged = dict(pack)
            merged["versions"] = {**(info.get("versions") or {}), **(pack.get("versions") or {})}
            merged["time"] = {**(info.get("time") or {}), **(pack.get("time") or {})}
            pack = merged
        rep = rules.evaluate(delta.compute(old, new, pack), dep_lookup)
        return {**r, "kind": kind, **rep.as_dict()}
    except Exception as e:
        return {**r, "kind": kind, "error": f"{type(e).__name__}: {e}"}


def load(kind):
    f = {"mal": "mal_pairs.jsonl", "benign": "benign_pairs.jsonl", "extra": "extra_pairs.jsonl"}[kind]
    p = DATA / f
    if not p.exists():
        return []
    recs = [json.loads(l) for l in p.open()]
    recs = [x for x in recs if "drop" not in x]
    if kind in ("mal", "extra"):
        assign(recs) if kind == "mal" else None
    return recs


def summarize(results, split):
    mal = [x for x in results if x["kind"] == "mal" and "error" not in x and (split == "all" or x["split"] == split)]
    ben = [x for x in results if x["kind"] == "benign" and "error" not in x and (split == "all" or x["split"] == split)]
    extra = [x for x in results if x["kind"] == "extra" and "error" not in x]
    errs = [x for x in results if "error" in x]
    print(f"\n==== split={split}  malicious pairs={len(mal)}  benign pairs={len(ben)}  errors={len(errs)}")
    by = defaultdict(list)
    for x in mal:
        by[x["campaign"]].append(x)
    rows = []
    for c in sorted(by):
        xs = by[c]
        hit = sum(x["blocked"] for x in xs)
        names = Counter(x["name"].split("/")[0] for x in xs).most_common(2)
        rows.append((c, len(xs), hit, hit / len(xs)))
        print(f"  {c}  n={len(xs):4d}  blocked={hit:4d}  recall={hit / len(xs):6.1%}  e.g. {', '.join(n for n, _ in names)}")
    if rows:
        macro = sum(r[3] for r in rows) / len(rows)
        micro = sum(r[2] for r in rows) / sum(r[1] for r in rows)
        print(f"  campaigns={len(rows)}  macro recall={macro:.1%}  per-sample recall={micro:.1%}")
    if extra:
        print("  extra (post-dataset) samples:")
        for x in extra:
            print(f"    {x['name']}@{x['new']} blocked={x['blocked']} score={x['score']} {[f['rule'] for f in x['findings']]}")
    if ben:
        fp = sum(x["blocked"] for x in ben)
        pk = len({x["name"] for x in ben})
        pk_fp = len({x["name"] for x in ben if x["blocked"]})
        print(f"  benign: {fp}/{len(ben)} updates blocked = FP rate {fp / len(ben):.2%}  "
              f"({pk_fp}/{pk} packages ever blocked)")
    # which rules fire where
    rc_m, rc_b = Counter(), Counter()
    for x in mal:
        rc_m.update({f["rule"] for f in x["findings"]})
    for x in ben:
        rc_b.update({f["rule"] for f in x["findings"]})
    print("  rule                              mal-hit    benign-hit")
    for rule in sorted(set(rc_m) | set(rc_b), key=lambda k: -rc_m[k]):
        print(f"  {rule:34s}{rc_m[rule]:6d} {rc_m[rule] / max(1, len(mal)):6.1%}  {rc_b[rule]:6d} {rc_b[rule] / max(1, len(ben)):6.2%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="train")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--kinds", default="mal,benign,extra")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default="results.jsonl")
    a = ap.parse_args()
    jobs = []
    for kind in a.kinds.split(","):
        recs = load(kind)
        if a.split != "all" and kind != "extra":
            recs = [x for x in recs if x.get("split") == a.split]
        if a.limit:
            recs = recs[: a.limit]
        jobs += [(kind, x) for x in recs]
    with cf.ProcessPoolExecutor(a.workers) as ex:
        results = list(ex.map(run_one, jobs, chunksize=4))
    with (DATA / a.out).open("w") as f:
        for x in results:
            f.write(json.dumps(x) + "\n")
    summarize(results, a.split)
    errs = [x for x in results if "error" in x]
    for x in errs[:8]:
        print("  ERR", x["name"], x.get("base_version"), x["error"][:160])


if __name__ == "__main__":
    main()
