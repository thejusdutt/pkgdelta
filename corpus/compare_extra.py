"""pkgdelta v2 vs GuardDog on the post-June holdout (OSV entries after 2026-06-26).

Groups:
  chaindrop            documented compromise, found 2026-08-04 (the keyv/cacheable worm)
  other compromise     advisory text describes a hijacked release, other dates
  automated label      advisory is one scanner's judgement of the package itself
"""
import json
import pathlib
from collections import defaultdict

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def group(x):
    if x.get("label") == "compromise":
        return "chaindrop" if x.get("discovered") == "2026-08-04" else "other compromise"
    return "automated label"


def main():
    pk = {f"{x['name']}@{x['mal_version']}": x for x in map(json.loads, open(DATA / "results_extra_v2.jsonl"))}
    gd_path = DATA / "guarddog_extra" / "guarddog.jsonl"
    gd = {g["id"][6:]: g for g in map(json.loads, open(gd_path))} if gd_path.exists() else {}
    rows = defaultdict(lambda: defaultdict(int))
    for k, x in pk.items():
        g = group(x)
        r = rows[g]
        r["n"] += 1
        r["pkgdelta"] += bool(x.get("blocked"))
        d = gd.get(k)
        if d and "error" not in d:
            r["gd_n"] += 1
            r["gd_high"] += d.get("label") == "high_risk"
            r["gd_susp"] += d.get("label") in ("high_risk", "suspicious")
            r["gd_any"] += bool(d.get("threat_fired"))
    print(f"{'group':18} {'n':>4} {'pkgdelta v2':>12} {'GD high_risk':>13} {'GD susp+':>9} {'GD any threat':>14}")
    for g in ("chaindrop", "other compromise", "automated label"):
        r = rows[g]
        if not r["n"]:
            continue
        f = lambda a, b: f"{a}/{b} {a / b:5.0%}" if b else "-"  # noqa: E731
        print(f"{g:18} {r['n']:4d} {f(r['pkgdelta'], r['n']):>12} {f(r['gd_high'], r['gd_n']):>13} "
              f"{f(r['gd_susp'], r['gd_n']):>9} {f(r['gd_any'], r['gd_n']):>14}")


if __name__ == "__main__":
    main()
