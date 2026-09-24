"""Write the GuardDog job list: every malicious sample and a fixed random sample of
benign updates (the new version of each pair, scanned standalone, since GuardDog
has no version-diff mode)."""
import json
import pathlib
import random
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
N_BENIGN = 1500


def main():
    out = DATA / "guarddog"
    out.mkdir(exist_ok=True)
    jobs = []
    for l in open(DATA / "mal_pairs.jsonl"):
        r = json.loads(l)
        if "drop" in r:
            continue
        jobs.append({"id": f"mal:{r['name']}@{r['mal_version']}", "kind": "mal", "name": r["name"],
                     "version": r["mal_version"], "path": "/data/dd_zips/" + r["zip"]})
    ben = [json.loads(l) for l in open(DATA / "benign_pairs.jsonl")]
    ben = [r for r in ben if "drop" not in r]
    random.Random(20260924).shuffle(ben)
    for r in ben[:N_BENIGN]:
        tgz = f"/data/cache/tarballs/{r['name'].replace('/', '__')}/{r['new_version']}.tgz"
        jobs.append({"id": f"ben:{r['name']}@{r['new_version']}", "kind": "benign", "name": r["name"],
                     "version": r["new_version"], "split": r["split"], "path": tgz})
    with open(out / "jobs.jsonl", "w") as f:
        for j in jobs:
            f.write(json.dumps(j) + "\n")
    shutil.copy(ROOT / "corpus" / "guarddog_run.py", out / "guarddog_run.py")
    print(len(jobs), "jobs")


if __name__ == "__main__":
    main()
