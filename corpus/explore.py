"""Print what changed in one sample per campaign. Train split only unless --all."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pkgdelta import delta, source  # noqa: E402
from corpus.campaigns import assign  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"

recs = [json.loads(l) for l in open(DATA / "mal_pairs.jsonl")]
recs = [r for r in recs if "drop" not in r]
assign(recs)
show_all = "--all" in sys.argv
seen = {}
for r in recs:
    if not show_all and r["split"] != "train":
        continue
    seen.setdefault(r["campaign"], []).append(r)

for camp, rs in seen.items():
    print("=" * 100)
    print(camp, len(rs), "samples")
    for r in rs[:: max(1, len(rs) // 3)][:3]:
        new, info = source.from_dd_zip(DATA / "dd_zips" / r["zip"])
        old = source.from_registry(r["name"], r["base_version"], source.packument(r["name"], max_age=1e12))
        d = delta.compute(old, new)
        print(f"-- {r['name']} {r['base_version']} -> {r['mal_version']}  files old={len(old.files)} new={len(new.files)}")
        print("   added:", [(p, len(new.files[p])) for p in d.added][:8])
        print("   changed:", d.changed[:8], "... n=", len(d.changed))
        ls_old, ls_new = delta.lifecycle_scripts(old.manifest), delta.lifecycle_scripts(new.manifest)
        if ls_old != ls_new:
            print("   lifecycle:", ls_old, "->", ls_new)
        do, dn = delta.deps(old.manifest), delta.deps(new.manifest)
        nd = {k: v for k, v in dn.items() if k not in do}
        if nd:
            print("   new deps:", nd)
        pu_old = (old.meta.get("_npmUser") or {}).get("name")
        pu_new = (new.meta.get("_npmUser") or {}).get("name")
        print("   publisher:", pu_old, "->", pu_new, "| attest old/new:",
              bool(old.meta.get("dist", {}).get("attestations")), bool(new.meta.get("dist", {}).get("attestations")))
        for p in d.changed[:3]:
            a, b = old.files[p], new.files[p]
            print(f"   ~ {p}: {len(a)} -> {len(b)} bytes; tail: {b[-160:]!r}")
