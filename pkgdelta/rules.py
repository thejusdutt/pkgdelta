"""Deterministic rules. Each looks at what the new version adds relative to the
package's own previous version, never at the new version alone.

Severity scores: high=3, medium=2, low=1. A version is blocked when its total
score reaches BLOCK_AT. Every finding carries the file and a short excerpt so a
human can check it in seconds.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field

from .delta import Delta, deps, lifecycle_scripts

SCORE = {"high": 3, "medium": 2, "low": 1}
BLOCK_AT = 3

INSTALL_HOOKS = ("preinstall", "install", "postinstall")
CODE_EXT = (".js", ".cjs", ".mjs", ".jsx")
BINARY_EXT = (".node", ".dll", ".exe", ".so", ".dylib", ".bin", ".elf")


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str | None = None
    evidence: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Report:
    name: str
    old_version: str
    new_version: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(SCORE[f.severity] for f in self.findings)

    @property
    def blocked(self) -> bool:
        return self.score >= BLOCK_AT

    def as_dict(self) -> dict:
        return {"name": self.name, "old": self.old_version, "new": self.new_version,
                "score": self.score, "blocked": self.blocked,
                "findings": [f.as_dict() for f in self.findings]}


# ---------------------------------------------------------------- helpers

def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace")


def _is_code(path: str) -> bool:
    p = path.lower()
    return p.endswith(CODE_EXT) and not p.endswith((".min.js.map",))


def _clip(s: str, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _around(text: str, pos: int, n: int = 70) -> str:
    return _clip(text[max(0, pos - n): pos + n])


def _code_files(pkg_files: dict[str, bytes]):
    for p, b in pkg_files.items():
        if _is_code(p) and b:
            yield p, b


# ---------------------------------------------------------------- capability vocabulary
# Categories of behaviour. A category is "new" when the new version's touched
# code uses it and no code file anywhere in the previous version did.

CAPS: dict[str, re.Pattern] = {
    "child_process": re.compile(r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s*['"](?:node:)?child_process['"]|\bexecSync\s*\(|\bspawnSync\s*\("""),
    "dynamic_code": re.compile(r"""\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|vm\.runIn(?:New|This)?Context"""),
    "env_dump": re.compile(r"""JSON\.stringify\(\s*process\.env\b|Object\.(?:keys|entries|values)\(\s*process\.env\b|\{\s*\.\.\.process\.env\s*\}"""),
    "secret_env": re.compile(r"""process\.env\.(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN|CI_JOB_TOKEN)\b"""),
    "credential_paths": re.compile(r"""['"`/\\](?:\.npmrc|\.ssh|id_rsa|id_ed25519|\.aws[/\\]credentials|\.aws['"`]|\.git-credentials|\.docker[/\\]config\.json|\.kube[/\\]config|\.claude(?:\.json)?|\.cursor|\.config[/\\]gcloud|\.azure|Local State|Login Data|\.bitcoin|\.electrum|exodus|keystore|wallet\.dat)['"`/\\]"""),
    "token_tools": re.compile(r"""gh\s+auth\s+token|npm\s+(?:whoami|token)|trufflehog|aws\s+sts\s+get-caller-identity|gcloud\s+auth\s+print-access-token|169\.254\.169\.254|169\.254\.170\.2|/proc/\d*/?(?:self/)?(?:environ|mem)\b|Runner\.Worker"""),
    "exfil_service": re.compile(r"""//(?:[\w-]+\.)*(?:webhook\.site|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|burpcollaborator|oastify\.com|interact\.sh|oast\.(?:pro|live|fun|me|site|online)|requestbin|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com|canarytokens|\.trycloudflare\.com|transfer\.sh|paste(?:bin)?\.(?:com|ee)/raw)"""),
    "download_exec": re.compile(r"""(?:curl|wget|iwr|Invoke-WebRequest)\s[^'"`\n]{0,200}(?:\|\s*(?:sh|bash|cmd|powershell|iex)\b|-o\s)|\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b|base64\s+(?:-d|--decode|-D)\b[^|\n]{0,60}\|\s*(?:ba|z)?sh\b|bun\.sh/install|oven-sh/bun/releases|registry\.npmjs\.org/bun"""),
    "crypto_wallet": re.compile(r"""window\.ethereum|ethereum\.request|solana\.signTransaction|\bsecretKey\b[^;\n]{0,60}(?:fetch|send|post)|\bprivateKey\b[^;\n]{0,60}(?:fetch|send|post)|\bmnemonic\b[^;\n]{0,60}(?:fetch|send|post)"""),
    "persistence": re.compile(r"""\.claude[/\\]settings|SessionStart|runOn['"]?\s*:\s*['"]folderOpen|\.vscode[/\\]tasks\.json|LaunchAgents|systemctl\s+(?:--user\s+)?enable|crontab\s|\\CurrentVersion\\Run|\.github[/\\]workflows"""),
}

# Categories strong enough to matter on their own when new.
CAP_SEVERITY = {
    "token_tools": "high", "exfil_service": "high", "download_exec": "high", "persistence": "high",
    "credential_paths": "medium", "secret_env": "medium", "env_dump": "medium", "crypto_wallet": "medium",
    "child_process": "low", "dynamic_code": "low",
}


B64_LIT = re.compile(r"""['"`]([A-Za-z0-9+/]{40,}={0,2})['"`]""")


def _decoded_strings(t: str) -> str:
    """Text hidden in base64 string literals, e.g. exec(`echo '<b64>' | base64 -d | bash`)."""
    import base64
    import binascii
    out = []
    for m in B64_LIT.finditer(t):
        raw = m.group(1)
        if len(raw) > 200_000:
            continue
        try:
            dec = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        txt = dec.decode("utf-8", "ignore")
        if txt and sum(c.isprintable() or c in "\n\t" for c in txt) / len(txt) > 0.95:
            out.append(txt)
    return "\n".join(out)


def cap_set(files: dict[str, bytes], only: list[str] | None = None) -> dict[str, tuple[str, str]]:
    """category -> (file, excerpt) for the first hit. Also scans text decoded
    from base64 string literals."""
    out: dict[str, tuple[str, str]] = {}
    items = ((p, files[p]) for p in only if p in files) if only is not None else files.items()
    for p, b in items:
        if not (_is_code(p) and b):
            continue
        t = _text(b)
        hidden = None
        for cat, rx in CAPS.items():
            if cat in out:
                continue
            m = rx.search(t)
            if m:
                out[cat] = (p, _around(t, m.start()))
                continue
            if hidden is None:
                hidden = _decoded_strings(t) if "base64" in t or "atob" in t or "Buffer.from" in t else ""
            if hidden:
                m = rx.search(hidden)
                if m:
                    out[cat] = (p, "decoded from base64: " + _around(hidden, m.start()))
    return out


# ---------------------------------------------------------------- network endpoints

URL_RX = re.compile(r"""['"`](?:https?|wss?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?[^'"`\s]*['"`]""")
NET_CALL = re.compile(r"""\bfetch\s*\(|\baxios\b|https?\.(?:request|get)\s*\(|XMLHttpRequest|new\s+WebSocket\s*\(|navigator\.sendBeacon|\.post\s*\(|got\s*\(|request\s*\(|net\.connect|dns\.resolve""")
# Hosts that show up in legitimate code constantly. Being on this list does not
# make a host trusted, it only means a new reference to it is not interesting.
COMMON_HOSTS = re.compile(r"""(?:^|\.)(?:github\.com|githubusercontent\.com|npmjs\.(?:org|com)|nodejs\.org|w3\.org|mozilla\.org|microsoft\.com|google(?:apis)?\.com|gstatic\.com|googleusercontent\.com|apple\.com|example\.(?:com|org|net)|localhost|schema\.org|json-schema\.org|unpkg\.com|jsdelivr\.net|cloudflare\.com|amazonaws\.com|typescriptlang\.org|reactjs\.org|react\.dev|stackoverflow\.com|wikipedia\.org|ietf\.org|opensource\.org|creativecommons\.org|twitter\.com|x\.com|youtube\.com|gitlab\.com|bitbucket\.org|npm\.im|yarnpkg\.com|sentry\.io|tc39\.es|whatwg\.org|spdx\.org|mit-license\.org|apache\.org|eslint\.org|babeljs\.io|webpack\.js\.org|vitejs\.dev|mdn\.io|goo\.gl|bit\.ly|fb\.me|shields\.io|codecov\.io|opencollective\.com|patreon\.com|funding\.)$""")


# Names of secret material. Seeing one of these within a few hundred characters
# of a request to a brand-new host is a cheap stand-in for data-flow tracking.
SECRET_NEAR = re.compile(r"""\b(?:seed|secretKey|secret_key|privateKey|private_key|mnemonic|passphrase|password|keypair|process\.env|document\.cookie|localStorage|sessionStorage|credentials|npmrc|id_rsa|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET)\b""", re.I)


FUNC_HEAD = re.compile(r"""(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:^|[\s;{}])(?:static\s+|async\s+)*([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*\{|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function\b|\([^()]*\)\s*=>))""")
_NOT_FUNCS = {"if", "for", "while", "switch", "catch", "function", "return", "with"}


def _secret_at_callers(t: str, pos: int):
    """One hop of data flow: name the function that wraps the request, then look
    for secret names in the arguments at its call sites. Catches payloads that
    launder the secret through a harmless parameter name, as in @solana/web3.js
    1.95.7 (addToQueue(secretKey) -> fetch to a new host)."""
    head = t[max(0, pos - 1500): pos]
    name = None
    for m in FUNC_HEAD.finditer(head):
        cand = next((g for g in m.groups() if g), None)
        if cand and cand not in _NOT_FUNCS:
            name = cand
    if not name or len(name) < 3:
        return None
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(([^()]{0,120})\)", t):
        if abs(m.start() - pos) < 200:
            continue  # the definition itself
        hit = SECRET_NEAR.search(m.group(1))
        if hit:
            return hit
    return None


def hosts_in(files: dict[str, bytes], only: list[str] | None = None) -> dict[str, list[tuple[str, int, str]]]:
    out: dict[str, list] = {}
    items = ((p, files[p]) for p in only if p in files) if only is not None else files.items()
    for p, b in items:
        if not b:
            continue
        t = _text(b)
        for m in URL_RX.finditer(t):
            out.setdefault(m.group(1).lower(), []).append((p, m.start(), t))
    return out


def all_hosts_text(files: dict[str, bytes]) -> str:
    # every host mentioned anywhere in the old version (code, docs, json)
    hs = set()
    for b in files.values():
        if b:
            hs.update(h.lower() for h in re.findall(r"(?:https?|wss?)://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", _text(b)))
    return hs


# ---------------------------------------------------------------- obfuscation

OBF_HEXNAME = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBF_ROTATE = re.compile(r"while\s*\(\s*!!\s*\[\s*\]\s*\)|\['push'\]\(_0x|\[\s*'shift'\s*\]\(\)")
OBF_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){24,}|(?:\\u[0-9a-fA-F]{4}){16,}")
B64_BLOB = re.compile(r"""['"`]([A-Za-z0-9+/]{3000,}={0,2})['"`]""")


def obf_score(t: str) -> int:
    s = 0
    n = len(OBF_HEXNAME.findall(t))
    if n >= 30:
        s += 2
    elif n >= 8:
        s += 1
    if OBF_ROTATE.search(t):
        s += 1
    if OBF_ESC.search(t):
        s += 1
    return s


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# ---------------------------------------------------------------- rules

def rule_install_hooks(d: Delta, r: Report) -> None:
    old, new = lifecycle_scripts(d.old.manifest), lifecycle_scripts(d.new.manifest)
    added = set(d.added)
    for hook in INSTALL_HOOKS:
        cmd = new.get(hook)
        if not cmd or old.get(hook) == cmd:
            continue
        # does the hook run a file that is new in this version?
        runs_new = any(f in cmd for f in added if f.endswith(CODE_EXT + (".sh", ".ps1", ".py")))
        risky = bool(re.search(r"curl|wget|bun\b|node\s+-e|base64|\|\s*(?:sh|bash)|powershell|iex|webhook|https?://", cmd))
        was = old.get(hook)
        what = "added" if was is None else "changed"
        sev = "high" if (runs_new or risky or was is None) else "medium"
        # a build step that already existed under another hook name is not new behaviour
        if was is None and any(cmd == v for v in old.values()):
            sev = "low"
        if was is None and re.fullmatch(r"\s*(?:node-gyp(?:-build)?\s+rebuild|prebuild-install(?:\s+\|\|\s+node-gyp\s+rebuild)?|node-gyp-build)\s*", cmd):
            sev = "medium"
        r.findings.append(Finding("install-hook", sev, f"{hook} script {what}: {_clip(cmd, 120)}",
                                  "package.json", f"before: {was!r}" if was else None))
    # npm runs `node-gyp rebuild` by itself when binding.gyp exists and there is no install script
    if "binding.gyp" in added and "binding.gyp" not in d.old.files and not new.get("install") and not new.get("preinstall"):
        r.findings.append(Finding("implicit-install", "high",
                                  "binding.gyp added: npm will run node-gyp at install time", "binding.gyp",
                                  _clip(_text(d.new.files.get("binding.gyp", b"")), 160)))


# Editor and agent configs that execute commands when a folder is opened or a
# session starts. CI workflows and git hooks inside node_modules never run, so
# they are not listed.
AGENT_FILES = re.compile(r"(?:^|/)(?:\.claude/(?:settings(?:\.local)?\.json|hooks/)|\.mcp\.json|\.vscode/(?:tasks|settings)\.json|\.cursor/(?:mcp\.json|hooks\.json|rules/)|\.gemini/settings\.json|\.windsurf/)")


def rule_agent_autorun(d: Delta, r: Report) -> None:
    for p in d.touched:
        if not AGENT_FILES.search(p):
            continue
        t = _text(d.new.files.get(p, b""))
        auto = re.search(r"SessionStart|PreToolUse|PostToolUse|UserPromptSubmit|folderOpen|\"command\"\s*:|mcpServers|alwaysApply", t)
        sev = "high" if auto else "medium"
        r.findings.append(Finding("agent-autorun", sev,
                                  f"ships editor/agent config that can run commands: {p}", p,
                                  _around(t, auto.start()) if auto else None))


def rule_binaries(d: Delta, r: Report) -> None:
    old_bins = [p for p in d.old.files if p.lower().endswith(BINARY_EXT)]
    for p in d.added:
        if p.lower().endswith(BINARY_EXT) and not old_bins:
            r.findings.append(Finding("new-binary", "medium", f"first native binary in this package: {p}", p,
                                      f"{len(d.new.files[p])} bytes"))
            break


def rule_capabilities(d: Delta, r: Report) -> None:
    old_caps = cap_set(d.old.files)
    new_caps = cap_set(d.new.files, only=d.touched)
    for cat, (p, ex) in new_caps.items():
        if cat in old_caps:
            continue
        r.findings.append(Finding(f"new-capability:{cat}", CAP_SEVERITY[cat],
                                  f"code starts using {cat.replace('_', ' ')} (previous version never did)", p, ex))


def rule_network(d: Delta, r: Report) -> None:
    old_hosts = all_hosts_text(d.old.files)
    touched_code = [p for p in d.touched if _is_code(p)]
    new_hosts = hosts_in(d.new.files, only=touched_code)
    reported = 0
    for host, hits in new_hosts.items():
        if host in old_hosts or COMMON_HOSTS.search(host):
            continue
        # a new host only matters if code near it makes a request
        for p, pos, t in hits:
            window = t[max(0, pos - 400): pos + 400]
            if NET_CALL.search(window):
                secret = SECRET_NEAR.search(window) or _secret_at_callers(t, pos)
                sev = "high" if secret else "medium"
                msg = f"code sends requests to a host the previous version never mentioned: {host}"
                if secret:
                    msg += f" (next to {secret.group(0)!r})"
                r.findings.append(Finding("new-endpoint", sev, msg, p, _around(t, pos)))
                reported += 1
                break
        if reported >= 3:
            break


def rule_obfuscation(d: Delta, r: Report) -> None:
    old_max = 0
    for p, b in _code_files(d.old.files):
        old_max = max(old_max, obf_score(_text(b)))
        if old_max >= 2:
            return  # package was already obfuscated/minified this way, nothing new
    for p in d.touched:
        if not _is_code(p):
            continue
        t = _text(d.new.files.get(p, b""))
        s = obf_score(t)
        if s >= 2:
            m = OBF_HEXNAME.search(t) or OBF_ROTATE.search(t) or OBF_ESC.search(t)
            r.findings.append(Finding("obfuscation", "high", "obfuscated code appears (previous version had none)",
                                      p, _around(t, m.start()) if m else None))
            return


HIDDEN_RX = re.compile(r"[^\s][ \t]{200,}[^\s]")


def rule_hidden_code(d: Delta, r: Report) -> None:
    """Code pushed far to the right of a normal line so editors and diffs don't show it."""
    if any(HIDDEN_RX.search(_text(b)) for p, b in _code_files(d.old.files)):
        return
    for p in d.touched:
        if not _is_code(p):
            continue
        t = _text(d.new.files.get(p, b""))
        m = HIDDEN_RX.search(t)
        if m:
            tail = t[m.end() - 1: m.end() + 120]
            r.findings.append(Finding("hidden-code", "high",
                                      "code hidden after a long run of whitespace on one line", p, _clip(tail)))
            return


def rule_blob(d: Delta, r: Report) -> None:
    old_has = any(B64_BLOB.search(_text(b)) for p, b in _code_files(d.old.files))
    if old_has:
        return
    for p in d.touched:
        if not _is_code(p):
            continue
        t = _text(d.new.files.get(p, b""))
        m = B64_BLOB.search(t)
        if m and _shannon(m.group(1)[:4000]) > 5.3:
            r.findings.append(Finding("encoded-blob", "medium", f"large encoded blob added ({len(m.group(1))} chars)",
                                      p, m.group(1)[:60] + "…"))
            return


def rule_injected_growth(d: Delta, r: Report) -> None:
    """An existing small source file balloons, typical of a payload appended to index.js."""
    for p in d.changed:
        if not _is_code(p) or p.endswith(".min.js"):
            continue
        a, b = len(d.old.files[p]), len(d.new.files[p])
        if a and b > 20_000 and b > 8 * a and (b - a) > 15_000:
            r.findings.append(Finding("injected-growth", "medium",
                                      f"{p} grew from {a} to {b} bytes in a {d_bump(d)} release", p))
            return


def d_bump(d: Delta) -> str:
    from .semver import bump_kind
    return bump_kind(d.old.version, d.new.version)


def first_published(pack: dict) -> str | None:
    """When the package really first appeared. `time.created` is reset when npm
    replaces a malicious package with a "0.0.1-security" placeholder, but the
    removed versions keep their timestamps, so use the earliest of those."""
    times = pack.get("time") or {}
    vs = [t for v, t in times.items() if v not in ("created", "modified") and "security" not in v]
    return min(vs) if vs else times.get("created")


def _maintainers(meta_or_pack: dict) -> set[str]:
    out = set()
    for m in meta_or_pack.get("maintainers") or []:
        if isinstance(m, dict) and m.get("name"):
            out.add(m["name"].lower())
        elif isinstance(m, str):
            out.add(m.split("<")[0].strip().lower())
    u = (meta_or_pack.get("_npmUser") or {}).get("name")
    if u:
        out.add(u.lower())
    return out


def rule_new_deps(d: Delta, r: Report, lookup=None) -> None:
    """A new runtime dependency that is days old and owned by someone else.

    Maintainers split code into new packages all the time; that is fine when the
    same people own both. The axios attack added plain-crypto-js, published a day
    earlier by an account unrelated to axios."""
    old, new = deps(d.old.manifest), deps(d.new.manifest)
    fresh = [n for n in new if n not in old]
    if not fresh or lookup is None:
        return
    ours = _maintainers(d.new.meta or {}) | _maintainers(d.old.meta or {})
    worst = None
    for n in fresh[:15]:
        info = lookup(n, d.new.published)
        if not info:
            continue
        age_days, has_hooks, theirs = info
        if age_days is None or age_days < 0 or age_days >= 30:
            continue
        if ours and theirs and ours & theirs:
            continue
        sev = "high" if has_hooks else "medium"
        f = Finding("fresh-dependency", sev,
                    f"new dependency {n} was first published {age_days:.1f} days before this release by "
                    f"{', '.join(sorted(theirs)) or 'unknown'}, who does not maintain this package"
                    + (" (it has install scripts)" if has_hooks else ""), "package.json")
        if worst is None or SCORE[sev] > SCORE[worst.severity]:
            worst = f
    if worst:
        r.findings.append(worst)


NON_REGISTRY = re.compile(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|[\w.-]+/[\w.-]+(?:#.*)?$)")


def rule_nonregistry_deps(d: Delta, r: Report) -> None:
    """A dependency that installs from git or a URL instead of the registry.

    npm clones git dependencies and runs their `prepare` script, so the payload
    never has to be in the published tarball. The May 2026 TanStack/antv/
    opensearch wave used exactly this: an orphan commit in the real upstream
    repo, referenced as `github:org/repo#<sha>` in optionalDependencies."""
    old = deps(d.old.manifest)
    for name, spec in deps(d.new.manifest).items():
        if NON_REGISTRY.match(spec.strip()) and old.get(name) != spec:
            r.findings.append(Finding("non-registry-dependency", "high",
                                      f"new dependency {name} installs from outside the registry: {_clip(spec, 90)}",
                                      "package.json"))
            return


def rule_new_publisher(d: Delta, r: Report) -> None:
    """Publisher who never published an earlier version. Weak on its own: teams change."""
    pack = d.pack or {}
    who = ((d.new.meta or {}).get("_npmUser") or {}).get("name")
    if not who or not pack:
        return
    times = pack.get("time") or {}
    cutoff = d.new.published or times.get(d.new.version)
    prior = set()
    for v, meta in (pack.get("versions") or {}).items():
        t = times.get(v)
        if v == d.new.version or not t or (cutoff and t >= cutoff):
            continue
        u = (meta.get("_npmUser") or {}).get("name")
        if u:
            prior.add(u.lower())
    if prior and who.lower() not in prior:
        r.findings.append(Finding("new-publisher", "low",
                                  f"published by {who}, who never published this package before"))


def rule_metadata(d: Delta, r: Report) -> None:
    om, nm = d.old.meta or {}, d.new.meta or {}
    if not om or not nm:
        return
    had = bool((om.get("dist") or {}).get("attestations")) or bool(om.get("_npmUser", {}).get("trustedPublisher"))
    has = bool((nm.get("dist") or {}).get("attestations")) or bool(nm.get("_npmUser", {}).get("trustedPublisher"))
    if had and not has:
        r.findings.append(Finding("provenance-dropped", "medium",
                                  "previous version had build provenance, this one does not"))


RULES = (rule_install_hooks, rule_agent_autorun, rule_binaries, rule_capabilities, rule_network,
         rule_obfuscation, rule_hidden_code, rule_blob, rule_injected_growth, rule_metadata, rule_new_publisher,
         rule_nonregistry_deps)


def evaluate(d: Delta, dep_lookup=None) -> Report:
    r = Report(d.new.name, d.old.version, d.new.version)
    for rule in RULES:
        rule(d, r)
    rule_new_deps(d, r, dep_lookup)
    return r
