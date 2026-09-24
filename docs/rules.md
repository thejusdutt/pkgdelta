# pkgdelta rules: what counts as suspicious in an npm update

Every rule compares the new release with the one before it. Something the package already did in the previous release is not reported. Something it starts doing now is.

Each rule compares the new version with the old one. Scores: high 3, medium 2, low 1. A version is blocked at 3.

| Rule | Severity | Fires when |
|---|---|---|
| `install-hook` | high | a `preinstall` / `install` / `postinstall` script appears or changes, especially one that runs a new file |
| `implicit-install` | high | `binding.gyp` appears (npm then runs `node-gyp` at install time with no script at all; the June 2026 Miasma wave) |
| `non-registry-dependency` | high | a new dependency installs from git or a URL (npm runs a git dependency's `prepare`; in May 2026 the TanStack, antv and OpenSearch releases pointed at attacker commits reachable through the real project's GitHub URL) |
| `new-capability:*` | low–high | code starts doing something no file in the old version did: download-and-run, token tools (`gh auth token`, cloud metadata IPs), exfil services, persistence (`.claude/settings.json`, `folderOpen` tasks), credential paths, secret env vars, env dumps, wallet hooks, `child_process`, `eval`. Also looks inside base64 string literals. |
| `new-endpoint` | medium / high | code sends a request to a host the old version never mentioned; high when secret material (`seed`, `privateKey`, `process.env`, …) is next to the request or passed to the function that makes it |
| `obfuscation` | high | `_0x`-style obfuscation appears in a package that had none |
| `hidden-code` | high | code placed after hundreds of spaces on one line, off-screen in editors and diffs |
| `agent-autorun` | medium / high | ships a Claude Code, VS Code, Cursor or Gemini config that runs commands when a folder opens or a session starts |
| `fresh-dependency` | medium / high | a new dependency that is days old and owned by someone who does not maintain this package |
| `encoded-blob`, `injected-growth`, `new-binary` | medium | large encoded blob; a small source file grows past 20 KB and 8×; first native binary |
| `provenance-dropped` | medium | the old release had build provenance, the new one doesn't |
| `new-publisher` | low | published by an account that never published this package before |

## Why a new publisher is only "low"

Teams change and projects move to [trusted publishing](https://docs.npmjs.com/trusted-publishers) all the time. In the benign set, 4.6% of normal updates had a first-time publisher. On its own that proves nothing, so it can add weight to other findings but never block by itself.

## Why a fresh dependency is only "medium"

The axios (March 2026) and Mastra (June 2026) attacks both added a days-old dependency owned by a stranger. But 3 of 6,707 normal updates look the same (4 before v2 read dependency age from the real version times), for example `fast-levenshtein` 3.0.0 switching to `fastest-levenshtein`. A dependency from the same maintainers (`call-bind-apply-helpers` from ljharb) is not reported at all. If the fresh dependency already has an install script, it becomes high.

## Secrets in findings are masked

Findings quote the package's own code. Some malicious releases carry credentials: the `@velliajs/discord` releases put a GitHub token inside a git dependency URL. Since pkgdelta output often ends up in public CI logs, tokens (`ghp_`, `github_pat_`, `npm_`, `AKIA…`, `sk-…`) and `user:password@` in URLs are replaced with `[redacted]`.

## Where the rules came from

They were written from the 2024–2025 campaigns in the [DataDog dataset](https://github.com/DataDog/malicious-software-packages-dataset) and frozen before testing on 2026 attacks. See [evaluation.md](evaluation.md) for how each rule performs on malicious and normal releases, and [incidents/](incidents/README.md) for which rules fired on each attack.
