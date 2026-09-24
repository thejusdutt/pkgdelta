"""Download DataDog compromised_lib samples one by one as encrypted zips.

We never check out the dataset with git (one path in another folder is not
valid on NTFS) and we never extract the zips to disk. They stay encrypted
(password `infected`) and are read in memory by the analysis code.
"""
import concurrent.futures as cf
import pathlib
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent / "data"
LIST = pathlib.Path(__file__).resolve().parent / "dd_files.txt"
OUT = ROOT / "dd_zips"
BASE = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/"


def fetch(rel: str) -> tuple[str, str]:
    dest = OUT / rel.removeprefix("samples/npm/compromised_lib/")
    if dest.exists() and dest.stat().st_size > 0:
        return rel, "cached"
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = BASE + urllib.parse.quote(rel)
    for attempt in range(4):
        try:
            data = urllib.request.urlopen(url, timeout=60).read()
            tmp = dest.with_suffix(".part")
            tmp.write_bytes(data)
            tmp.replace(dest)
            return rel, "ok"
        except Exception as e:  # network blips, 429s
            err = str(e)
    return rel, "fail " + err


def main() -> None:
    rels = [l.strip() for l in LIST.read_text().splitlines() if l.strip().endswith(".zip")]
    with cf.ThreadPoolExecutor(16) as ex:
        results = list(ex.map(fetch, rels))
    fails = [r for r in results if r[1].startswith("fail")]
    print(f"{len(rels)} listed, {len(rels) - len(fails)} present, {len(fails)} failed")
    for f in fails[:20]:
        print(f)
    man = ROOT / "dd_manifest.json"
    if not man.exists():
        man.write_bytes(urllib.request.urlopen(BASE + "samples/npm/manifest.json", timeout=60).read())


if __name__ == "__main__":
    main()
