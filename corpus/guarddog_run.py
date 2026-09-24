"""Runs INSIDE the GuardDog container. Scans every target in /jobs/jobs.jsonl
and writes one compact summary line per target (no code excerpts) to /out.

Host side:
  docker run --rm -v <data>:/data:ro -v <jobs>:/jobs -v <out>:/out \
    --entrypoint python3 ghcr.io/datadog/guarddog:latest /jobs/guarddog_run.py
"""
import concurrent.futures as cf
import json
import os
import subprocess

JOBS = "/jobs/jobs.jsonl"
OUT = "/out/guarddog.jsonl"


def scan(job):
    cmd = ["guarddog", "npm", "scan", job["path"], "--no-sandbox", "--output-format", "json"]
    if job["path"].endswith(".zip"):
        cmd += ["--zip-password", "infected"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        d = json.loads(p.stdout[p.stdout.find("{"):])
    except Exception as e:
        return {**job, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    res = d.get("results") or {}
    fired = sorted(k for k, v in res.items() if v)
    rs = d.get("risk_score") or {}
    return {**job, "issues": d.get("issues"), "label": rs.get("label"), "score": rs.get("score"),
            "fired": fired, "threat_fired": [k for k in fired if not k.startswith("capability-")],
            "errors": list((d.get("errors") or {}).keys())[:5]}


def main():
    jobs = [json.loads(l) for l in open(JOBS)]
    done = set()
    if os.path.exists(OUT):
        for l in open(OUT):
            try:
                done.add(json.loads(l)["id"])
            except Exception:
                pass
    jobs = [j for j in jobs if j["id"] not in done]
    print(f"{len(jobs)} to scan, {len(done)} already done", flush=True)
    with open(OUT, "a") as f, cf.ThreadPoolExecutor(int(os.environ.get("WORKERS", "8"))) as ex:
        for i, r in enumerate(ex.map(scan, jobs)):
            f.write(json.dumps(r) + "\n")
            f.flush()
            if i % 100 == 0:
                print(i, flush=True)


if __name__ == "__main__":
    main()
