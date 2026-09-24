"""Load package contents into memory from the npm registry, a tarball or a sample zip.

Nothing here writes package contents to disk or runs package code. Tarballs are
cached as the original .tgz bytes only.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import pathlib
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field

REGISTRY = os.environ.get("PKGDELTA_REGISTRY", "https://registry.npmjs.org")
CACHE = pathlib.Path(os.environ.get("PKGDELTA_CACHE", pathlib.Path.home() / ".cache" / "pkgdelta"))

# Files above this are recorded but not read. Kept high on purpose: the
# @bitwarden/cli 2026.4.0 payload was a 10 MB file.
MAX_FILE = 64 * 1024 * 1024


@dataclass
class Package:
    name: str
    version: str
    files: dict[str, bytes]
    manifest: dict  # package.json from the tarball
    meta: dict = field(default_factory=dict)  # this version's registry record, if known
    published: str | None = None  # ISO time from the registry


def _get(url: str, tries: int = 4) -> bytes:
    err = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "pkgdelta"})
            return urllib.request.urlopen(req, timeout=120).read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            err = e
        except Exception as e:
            err = e
        time.sleep(1.5 * (i + 1))
    raise err


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    # threads may race on the same cache file; on Windows replace() can fail
    # while another thread holds the target, so a lost race is fine
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.part")
    tmp.write_bytes(data)
    for _ in range(5):
        try:
            tmp.replace(path)
            return
        except PermissionError:
            time.sleep(0.2)
    tmp.unlink(missing_ok=True)


def _enc(name: str) -> str:
    # scoped names keep the @ but escape the slash
    return urllib.parse.quote(name, safe="@")


def packument(name: str, max_age: float = 6 * 3600, offline: bool = False) -> dict:
    path = CACHE / "packuments" / (name.replace("/", "__") + ".json")
    if path.exists() and (offline or time.time() - path.stat().st_mtime < max_age):
        return json.loads(path.read_text(encoding="utf-8"))
    data = _get(f"{REGISTRY}/{_enc(name)}")
    _atomic_write(path, data)
    return json.loads(data)


def tarball_bytes(name: str, version: str, url: str | None = None) -> bytes:
    path = CACHE / "tarballs" / name.replace("/", "__") / f"{version}.tgz"
    if path.exists() and path.stat().st_size:
        return path.read_bytes()
    if url is None:
        base = name.split("/")[-1]
        url = f"{REGISTRY}/{_enc(name)}/-/{base}-{version}.tgz"
    data = _get(url)
    _atomic_write(path, data)
    return data


def _strip_root(path: str) -> str:
    # npm tarballs put everything under one top dir, usually "package/"
    parts = path.replace("\\", "/").split("/", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def files_from_tgz(data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not m.isfile():
                continue
            p = _strip_root(m.name)
            if m.size > MAX_FILE:
                out[p] = b""  # present but not read
                continue
            f = tf.extractfile(m)
            if f is not None:
                out[p] = f.read()
    return out


def _manifest(files: dict[str, bytes]) -> dict:
    raw = files.get("package.json")
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8-sig", "replace"))
    except Exception:
        return {}


def from_registry(name: str, version: str, pack: dict | None = None) -> Package:
    pack = pack or packument(name)
    meta = pack.get("versions", {}).get(version, {})
    url = meta.get("dist", {}).get("tarball")
    files = files_from_tgz(tarball_bytes(name, version, url))
    return Package(name, version, files, _manifest(files), meta, pack.get("time", {}).get(version))


def from_tgz_file(path: str | os.PathLike) -> Package:
    files = files_from_tgz(pathlib.Path(path).read_bytes())
    man = _manifest(files)
    return Package(man.get("name", "?"), man.get("version", "?"), files, man)


def from_dir(path: str | os.PathLike) -> Package:
    root = pathlib.Path(path)
    files = {}
    for p in root.rglob("*"):
        if p.is_file() and "node_modules" not in p.parts:
            rel = p.relative_to(root).as_posix()
            files[rel] = b"" if p.stat().st_size > MAX_FILE else p.read_bytes()
    man = _manifest(files)
    return Package(man.get("name", "?"), man.get("version", "?"), files, man)


# Python decrypts ZipCrypto in pure Python, which takes tens of seconds for the
# 10 MB Shai-Hulud payloads. After the first read we keep a scrambled copy
# (every byte XOR 0x5A): nothing on disk is runnable or matches a malware
# signature, and unscrambling with bytes.translate runs at C speed.
_XOR = bytes(b ^ 0x5A for b in range(256))


def _scrambled_cache(path) -> pathlib.Path:
    import hashlib
    h = hashlib.sha1(str(pathlib.Path(path).resolve()).encode()).hexdigest()[:20]
    return CACHE / "dd_scrambled" / f"{h}.bin"


def from_dd_zip(path: str | os.PathLike, password: bytes = b"infected") -> tuple[Package, dict]:
    """Read a DataDog dataset sample in memory. Returns the package and the
    registry record (packument) captured at discovery time."""
    import pickle
    cpath = _scrambled_cache(path)
    if cpath.exists():
        files, info = pickle.loads(cpath.read_bytes().translate(_XOR))
    else:
        files, info = _read_dd_zip(path, password)
        _atomic_write(cpath, pickle.dumps((files, info), protocol=5).translate(_XOR))
    man = _manifest(files)
    name = man.get("name") or info.get("name", "?")
    ver = man.get("version", "?")
    meta = info.get("versions", {}).get(ver, {})
    return Package(name, ver, files, man, meta, info.get("time", {}).get(ver)), info


SEVENZIP = os.environ.get("PKGDELTA_7Z") or next(
    (p for p in (r"C:\Program Files\7-Zip\7z.exe", "/usr/bin/7z", "/usr/local/bin/7z") if os.path.exists(p)), None)


def _read_dd_zip_7z(path, password):
    """Decrypt with 7-Zip into memory. `7z x -so` writes every file's bytes to
    stdout in archive order; the listing gives the sizes to split them again."""
    import subprocess
    pw = "-p" + password.decode()
    listing = subprocess.run([SEVENZIP, "l", "-slt", pw, str(path)], capture_output=True, timeout=300).stdout.decode("utf-8", "replace")
    entries, cur = [], {}
    for line in listing.splitlines()[listing.splitlines().index("----------") + 1:] if "----------" in listing else []:
        if not line.strip():
            if cur.get("Path") is not None:
                entries.append(cur)
            cur = {}
            continue
        k, _, v = line.partition(" = ")
        cur[k] = v
    if cur.get("Path") is not None:
        entries.append(cur)
    files_in_order = [(e["Path"].replace("\\", "/"), int(e.get("Size") or 0)) for e in entries
                      if "D" not in (e.get("Attributes") or "") and e.get("Folder") != "+"]
    blob = subprocess.run([SEVENZIP, "x", "-so", pw, str(path)], capture_output=True, timeout=600).stdout
    if len(blob) != sum(s for _, s in files_in_order):
        raise ValueError("7z output does not match listing")
    out, i = {}, 0
    for name, size in files_in_order:
        out[name] = blob[i:i + size]
        i += size
    return out


def _read_dd_zip(path, password):
    raw = None
    if SEVENZIP:
        try:
            raw = _read_dd_zip_7z(path, password)
        except Exception:
            raw = None
    if raw is not None:
        files: dict[str, bytes] = {}
        info: dict = {}
        for n, b in raw.items():
            if "/package_info-" in n and n.endswith(".json"):
                try:
                    info = json.loads(b)
                except Exception:
                    info = {}
            elif n.startswith("package/"):
                files[n[len("package/"):]] = b"" if len(b) > MAX_FILE else b
            elif "/package/" in n:
                files[n.split("/package/", 1)[1]] = b"" if len(b) > MAX_FILE else b
            elif n.endswith(".tgz") and not files:
                files = files_from_tgz(b)
        return files, info
    zf = zipfile.ZipFile(path)
    files: dict[str, bytes] = {}
    info: dict = {}
    for zi in zf.infolist():
        if zi.is_dir():
            continue
        n = zi.filename.replace("\\", "/")
        if "/package_info-" in n and n.endswith(".json"):
            try:
                info = json.loads(zf.read(zi, pwd=password))
            except Exception:
                info = {}
            continue
        if n.startswith("package/"):
            rel = n[len("package/"):]
        elif "/package/" in n:
            rel = n.split("/package/", 1)[1]
        else:
            continue
        files[rel] = b"" if zi.file_size > MAX_FILE else zf.read(zi, pwd=password)
    # some samples ship only the raw tarball
    if not files:
        for zi in zf.infolist():
            if zi.filename.endswith(".tgz"):
                files = files_from_tgz(zf.read(zi, pwd=password))
                break
    return files, info
