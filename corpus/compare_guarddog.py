"""GuardDog vs pkgdelta on the same samples, same campaign grouping.

GuardDog scans the new version alone (it has no version-diff mode). We report
three GuardDog thresholds so nobody can say we picked the one that loses:
  high_risk          GuardDog's own top verdict
  suspicious+        high_risk or suspicious
  any threat rule    any threat-* rule fired (capability-* rules are informational)
pkgdelta numbers come from a results file written by evaluate.py.
"""
import json
import pathlib
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from corpus.campaigns import assign  # noqa: E402

DATA = ROOT / "data"


def main(pk_files):
    pairs = [json.loads(l) for l in open(DATA / "mal_pairs.jsonl")]
    pairs = [p for p in pairs if "drop" not in p]
    assign(pairs)
    camp = {f"{p['name']}@{p['mal_version']}": (p["campaign"], p["split"]) for p in pairs}

    gd = [json.loads(l) for l in open(DATA / "guarddog" / "guarddog.jsonl")]
    gd = {g["id"]: g for g in gd}
    tests = {
        "GuardDog high_risk": lambda g: g.get("label") == "high_risk",
        "GuardDog suspicious+": lambda g: g.get("label") in ("high_risk", "suspicious"),
        "GuardDog any threat rule": lambda g: bool(g.get("threat_fired")),
    }

    pk = {}
    for f in pk_files:
        for l in open(DATA / f):
            x = json.loads(l)
            key = ("mal:" if x["kind"] == "mal" else "ben:") + f"{x['name']}@{x.get('mal_version') or x.get('new_version')}"
            pk[key] = bool(x.get("blocked"))

    ben_ids = [k for k, g in gd.items() if g["kind"] == "benign" and "error" not in g]
    print(f"benign sample scanned by both: {sum(1 for k in ben_ids if k in pk)} of {len(ben_ids)}")
    rows = []
    for split in ("train", "test", "all"):
        mal_ids = [k for k, g in gd.items() if g["kind"] == "mal" and "error" not in g
                   and k[4:] in camp and (split == "all" or camp[k[4:]][1] == split)]
        mal_ids = [k for k in mal_ids if k in pk]
        bens = [k for k in ben_ids if k in pk and (split == "all" or gd[k].get("split") == split)]
        judges = dict(tests)
        judges["pkgdelta"] = None
        for name, fn in judges.items():
            hit = (lambda k: pk[k]) if fn is None else (lambda k, fn=fn: fn(gd[k]))
            by = defaultdict(list)
            for k in mal_ids:
                by[camp[k[4:]][0]].append(hit(k))
            macro = sum(sum(v) / len(v) for v in by.values()) / max(1, len(by))
            micro = sum(sum(v) for v in by.values()) / max(1, len(mal_ids))
            fp = sum(hit(k) for k in bens)
            rows.append((split, name, len(by), macro, micro, fp, len(bens)))
    print(f"{'split':6} {'detector':26} {'camps':>5} {'macro':>7} {'sample':>7} {'benign flagged':>16}")
    for s, n, c, ma, mi, fp, nb in rows:
        print(f"{s:6} {n:26} {c:5d} {ma:7.1%} {mi:7.1%} {fp:6d}/{nb:<5d} {fp / max(1, nb):6.2%}")
    return rows


if __name__ == "__main__":
    main(sys.argv[1:] or ["results_train_v2.jsonl", "results_test_v2.jsonl"])
