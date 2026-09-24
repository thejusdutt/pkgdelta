"""Fill the numbers into docs/incidents/*.md from the files in results/.

Each incident page is written by hand, except the block between
<!-- numbers:start --> and <!-- numbers:end -->, which this script rewrites:
the detection table, the rules that fired, and the full list of releases.

OSV malware ids come from results/osv_mal_ids.json. `--fetch-osv` refreshes
that file from api.osv.dev (one querybatch call per 1,000 versions).
"""
import json
import pathlib
import sys
import urllib.request
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pkgdelta.rules import redact  # noqa: E402

RES = ROOT / "results"
DOCS = ROOT / "docs" / "incidents"
OSV_FILE = RES / "osv_mal_ids.json"
START, END = "<!-- numbers:start -->", "<!-- numbers:end -->"


def dataset(split, camps, name=None):
    def pick(x):
        return x["kind"] == "mal" and x["campaign"] in camps and (name is None or name(x["name"]))
    return ("dataset", split, pick)


def fresh(pick):
    return ("fresh", None, pick)


# page -> where its releases are in results/
INCIDENTS = {
    "nx-s1ngularity": dataset("train", {"2025-08-26"}),
    "chalk-debug": dataset("train", {"2025-09-08"}),
    "shai-hulud": dataset("train", {"2025-09-14"}),
    "shai-hulud-2": dataset("train", {"2025-11-24"}),
    "axios-plain-crypto-js": dataset("test", {"2026-03-31"}),
    "bitwarden-cli": dataset("test", {"2026-04-21"}, lambda n: n == "@bitwarden/cli"),
    "sap-cap-js": dataset("test", {"2026-04-29"}),
    "tanstack-mini-shai-hulud": dataset("test", {"2026-05-11", "2026-05-19"}),
    "redhat-cloud-services": dataset("test", {"2026-06-01"}),
    "node-gyp-miasma": dataset("test", {"2026-06-03", "2026-06-25"}),
    "mastra-easy-day-js": dataset("test", {"2026-06-17"}),
    "chaindrop-keyv": fresh(lambda x: x.get("label") == "compromise" and x.get("discovered") == "2026-08-04"),
}


def load(name):
    with open(RES / name, encoding="utf-8") as f:
        return [json.loads(l) for l in f]


def rows_for(spec):
    kind, split, pick = spec
    if kind == "dataset":
        v1 = {(x["name"], x["new"]): x for x in load(f"v1_{split}.jsonl")}
        v2 = [x for x in load(f"v2_{split}.jsonl") if pick(x)]
        gd = {g["id"]: g for g in load("guarddog_dataset.jsonl")}
        gkey = lambda x: f"mal:{x['name']}@{x['mal_version']}"  # noqa: E731
    else:
        v1 = {(x["name"], x["new"]): x for x in load("v1_fresh.jsonl")}
        v2 = [x for x in load("v2_fresh.jsonl") if pick(x)]
        gd = {g["id"]: g for g in load("guarddog_fresh.jsonl")}
        gkey = lambda x: f"extra:{x['name']}@{x['mal_version']}"  # noqa: E731
    out = []
    for x in v2:
        g = gd.get(gkey(x))
        if g and "error" in g:
            g = None
        out.append({
            "name": x["name"], "old": x["old"], "new": x["new"], "found": x.get("discovered", ""),
            "v1": bool(v1[(x["name"], x["new"])]["blocked"]), "v2": bool(x["blocked"]), "score": x["score"],
            "gd": g, "findings": x["findings"], "partial": x.get("missing_files", 0),
        })
    return sorted(out, key=lambda r: (r["name"], r["new"]))


def fetch_osv(keys):
    ids = {}
    keys = sorted(keys)
    for i in range(0, len(keys), 1000):
        chunk = keys[i:i + 1000]
        body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req, timeout=120))["results"]
        for (n, v), r in zip(chunk, res):
            mal = sorted(a["id"] for a in r.get("vulns") or [] if a["id"].startswith("MAL-"))
            if mal:
                ids[f"{n}@{v}"] = mal
    OSV_FILE.write_text(json.dumps(ids, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    return ids


def pct(a, b):
    return f"{a} / {b} ({100 * a / b:.0f}%)" if b else "–"


def block(rows, osv):
    n = len(rows)
    g = [r["gd"] for r in rows if r["gd"]]
    lines = [
        "| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |",
        "|---|---|---|---|---|---|",
        f"| Blocked | {n} | {pct(sum(r['v1'] for r in rows), n)} | {pct(sum(r['v2'] for r in rows), n)} | "
        f"{pct(sum(x.get('label') == 'high_risk' for x in g), len(g))} | "
        f"{pct(sum(bool(x.get('threat_fired')) for x in g), len(g))} |",
        "",
    ]
    rules = Counter(f"`{f['rule']}` ({f['severity']})" for r in rows for f in r["findings"] if f["severity"] != "low")
    if rules:
        lines.append("Findings in these releases (pkgdelta v2, medium and high only; count = releases):")
        lines.append("")
        lines += [f"- {k}: {v}" for k, v in rules.most_common()]
        lines.append("")
    lines += [
        f"<details><summary>{f'All {n} releases' if n > 1 else 'The release'} "
        "(baseline = the clean release it was compared with)</summary>",
        "",
        "| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        ids = ", ".join(f"[{i}](https://osv.dev/vulnerability/{i})" for i in osv.get(f"{r['name']}@{r['new']}", []))
        verdict = f"BLOCK ({r['score']})" if r["v2"] else f"pass ({r['score']})"
        gd = r["gd"]["label"] if r["gd"] else "not scanned"
        lines.append(f"| `{r['name']}` | {r['new']} | {r['old']} | {ids or '–'} | {verdict} | {gd} |")
    lines += ["", "</details>"]
    return redact("\n".join(lines))


# page -> (title in the index, when)
TITLES = {
    "nx-s1ngularity": ("Nx / s1ngularity (`@nx/*` 21.5.0)", "Aug 2025"),
    "chalk-debug": ("chalk, debug and 16 more (phished maintainer)", "Sep 2025"),
    "shai-hulud": ("Shai-Hulud worm (`@ctrl/tinycolor` and 369 more)", "Sep 2025"),
    "shai-hulud-2": ("Shai-Hulud 2.0 (Postman, PostHog, AsyncAPI, …)", "Nov 2025"),
    "axios-plain-crypto-js": ("axios 1.14.1 / `plain-crypto-js`", "Mar 2026"),
    "bitwarden-cli": ("`@bitwarden/cli` 2026.4.0", "Apr 2026"),
    "sap-cap-js": ("SAP `@cap-js/*` and `mbt`", "Apr 2026"),
    "tanstack-mini-shai-hulud": ("TanStack / Mini Shai-Hulud and the `@antv` wave", "May 2026"),
    "redhat-cloud-services": ("`@redhat-cloud-services/*`", "Jun 2026"),
    "node-gyp-miasma": ("Miasma: `binding.gyp` / node-gyp wave", "Jun 2026"),
    "mastra-easy-day-js": ("Mastra / `easy-day-js`", "Jun 2026"),
    "chaindrop-keyv": ("ChainDrop worm (`keyv` 6.0.0, `cacheable`, …)", "Aug 2026"),
}


def index_block(all_rows):
    lines = [
        "| Incident | When | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` |",
        "|---|---|---|---|---|---|",
    ]
    for page, rows in all_rows.items():
        title, when = TITLES[page]
        g = [r["gd"] for r in rows if r["gd"]]
        n = len(rows)
        lines.append(f"| [{title}]({page}.md) | {when} | {n} | {sum(r['v1'] for r in rows)} | "
                     f"{sum(r['v2'] for r in rows)} | {sum(x.get('label') == 'high_risk' for x in g)} of {len(g)} |")
    return "\n".join(lines)


def splice(path, body):
    text = path.read_text(encoding="utf-8")
    a, b = text.index(START) + len(START), text.index(END)
    path.write_text(text[:a] + "\n" + body + "\n" + text[b:], encoding="utf-8", newline="\n")


def main():
    all_rows = {page: rows_for(spec) for page, spec in INCIDENTS.items()}
    if "--fetch-osv" in sys.argv or not OSV_FILE.exists():
        osv = fetch_osv({(r["name"], r["new"]) for rows in all_rows.values() for r in rows})
    else:
        osv = json.loads(OSV_FILE.read_text(encoding="utf-8"))
    for page, rows in all_rows.items():
        path = DOCS / f"{page}.md"
        if not path.exists():
            print(f"skip {page}: no page yet ({len(rows)} releases)")
            continue
        splice(path, block(rows, osv))
        print(f"{page}: {len(rows)} releases")
    if (DOCS / "README.md").exists():
        splice(DOCS / "README.md", index_block(all_rows))


if __name__ == "__main__":
    main()
