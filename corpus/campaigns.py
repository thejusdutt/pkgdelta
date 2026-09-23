"""Group samples into campaigns and assign the time split.

Samples discovered within one day of each other form one campaign. That merges
a few distinct attacks that happened on adjacent days, which is why the headline
number is the macro average of per-campaign recall: a missed attack inside a
merged cluster still pulls its cluster's recall down.

Rules were designed looking only at the train split (discovered before 2026).
Everything from 2026 is held out.
"""
import datetime as dt

HOLDOUT_FROM = "2026-01-01"


def assign(recs: list[dict]) -> None:
    dates = sorted({r["discovered"] for r in recs if r.get("discovered")})
    label = {}
    start = prev = None
    for d in dates:
        day = dt.date.fromisoformat(d)
        if prev is None or (day - prev).days > 1:
            start = d
        label[d] = start
        prev = day
    for r in recs:
        r["campaign"] = label.get(r.get("discovered"), r.get("discovered") or "unknown")
        r["split"] = "test" if r["campaign"] >= HOLDOUT_FROM else "train"
