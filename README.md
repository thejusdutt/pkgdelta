# pkgdelta

Check each npm update against the package's own previous release.

When an attacker takes over a popular package, the new release does something the old one never did: it adds an install script, calls a host it never called, starts reading `~/.npmrc`, or ships obfuscated code. pkgdelta looks only at that difference. The package's history is the baseline.

```
$ pkgdelta local ./ms-2.1.3-injected.tgz
BLOCK ms 2.1.3 -> 2.1.3  (score 12)
        HIGH install-hook: preinstall script added: node setup.mjs [package.json]
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [setup.mjs]
             import {execSync} from 'child_process'; const t = execSync('gh auth token').toString();
        HIGH new-endpoint: code sends requests to a host the previous version never mentioned: exfil-demo.invalid (next to 'process.env') [setup.mjs]
        ...
```

## Why this exists

Two facts from 2026:

1. **Signatures don't help anymore.** `keyv@6.0.0` (ChainDrop, 4 Aug 2026) shipped with valid SLSA provenance. So did the TanStack and Red Hat releases in May and June. The build was real. The attacker just controlled what went into it.
2. **Cooldowns are outsourced trust.** pnpm 11, Yarn 4.10 and Deno now wait 24 hours before installing a new version. That works only because a vendor scanner (Socket flagged `keyv@6.0.0` six minutes after publish) catches the attack first and npm pulls it. Nobody outside those vendors can check that work, and none of them publish a false-positive rate.

The research on npm malware detection names the core problem: malware and normal code call the same APIs ("the capability–intent gap", [arXiv 2603.27549](https://arxiv.org/abs/2603.27549), March 2026). A scanner that looks at one version has to guess intent. A scanner that compares with the previous version does not: `debug` has no business reading `~/.ssh` in a patch release, whatever the API.

That idea is not new. Amalfi (ICSE 2022) used "capabilities the package never used before" as ML features, but the code was never released. RogueOne (ICSE 2024) does differential data-flow analysis as a research prototype. pkgdelta is the practical version: deterministic rules, no model, no server, every finding points at a file and a line of evidence, and the false-positive rate is measured and published below.

## Results

Ground truth is the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), folder `samples/npm/compromised_lib`: 1,443 real malicious releases of existing packages (account takeovers), 2024-12 to 2026-06. For each one, the baseline is the newest earlier clean release still on the registry. 1,363 pairs remain (80 had no earlier release or the package is gone).

Benign updates: the last 6 real releases of each of the top 1,200 npm packages ([npm-high-impact](https://github.com/wooorm/npm-high-impact)), 6,707 pairs, compared the same way.

**How the test was kept honest**

- Time split. Rules were written looking only at campaigns found before 2026-01-01 (11 campaigns, 864 samples) and half of the benign packages. Every 2026 campaign (16 campaigns, 499 samples) and the other benign half were held out.
- The rules were committed ([c3484c5](#)) before the held-out run. One loader bug was fixed after (a zip layout, [5758d7a](#)); that fix touches no rule.
- Shai-Hulud-style worms put one payload into hundreds of packages. Per-sample recall rewards that. The headline is the **macro average of per-campaign recall** (campaign = samples found within a day of each other).

**v1, frozen rules, held-out 2026 data**

| | |
|---|---|
| Campaigns | 16 |
| Macro recall (per campaign) | **92.7%** |
| Per-sample recall | 96.8% (483 / 499) |
| Benign updates blocked | **1 / 3,457 (0.03%)** |

On the train split the same rules block every sample that contains a payload, with 0 of 3,250 benign updates blocked.

__V2_RESULTS__

__GUARDDOG_RESULTS__

__EXTRA_RESULTS__

### What it misses, and why

- **No payload in the tarball.** Three `vant` 4.9.x samples and two `@rxap/ngx-bootstrap` samples differ from the previous release only in the version number. Either the dataset captured a clean copy or the attack was elsewhere. No content check can catch them.
- **The payload lives in a new dependency that has since been deleted.** 8 Mastra packages (June 2026) added `easy-day-js`, published 0.8 days earlier by an unrelated account. pkgdelta flags that (medium) but does not block on it alone, because 4 of 6,707 benign updates look the same (for example `fast-levenshtein` 3.0.0 switching to `fastest-levenshtein`). The malicious `easy-day-js` version is gone from the registry, so its code can't be scanned after the fact.
- **The one false positive** is `@octokit/openapi-types` 28 → 29: a first-time publisher, on a major release, without the build provenance every earlier release had. That is a real anomaly. A human should look.

## Install

```
pip install git+<this repo>
```

Python 3.10+, no dependencies. It downloads tarballs from the registry and reads them in memory. It never runs package code.

## Use

```
pkgdelta check <name> <version>          # one version vs the release before it
pkgdelta diff old-lock.json new-lock.json   # every version a lockfile change brings in
pkgdelta audit package-lock.json         # every locked version (incident response)
pkgdelta local ./my-pkg-1.2.3.tgz        # before you publish: compare with your last release
```

Exit code 1 means something was blocked. `--json` for machine output. Lockfiles: npm (v1–v3), pnpm, yarn.

`diff` and `audit` also ask [OSV](https://osv.dev) whether a version is already known as malware, and flag locked versions that npm has since removed. A lockfile that still pins `chalk@5.6.1` fails with the OSV id and a note to treat the machine as compromised.

**In CI (GitHub Actions)**

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: <this repo>@main
  with:
    lockfile: package-lock.json
```

**For maintainers**: run `pkgdelta local` on the output of `npm pack` as the last step before `npm publish`. The Nx (2025), TanStack (2026) and keyv (2026) releases came out of the projects' own compromised CI. A check that compares what is about to ship with what shipped last time is cheap and would have stopped all three.

## Rules

Each rule compares the new version with the old one. Scores: high 3, medium 2, low 1. A version is blocked at 3.

| Rule | Severity | Fires when |
|---|---|---|
| `install-hook` | high | a `preinstall` / `install` / `postinstall` script appears or changes, especially one that runs a new file |
| `implicit-install` | high | `binding.gyp` appears (npm then runs `node-gyp` at install time with no script at all; the June 2026 Miasma wave) |
| `non-registry-dependency` | high | a new dependency installs from git or a URL (npm runs a git dependency's `prepare`; the May 2026 TanStack/antv wave pinned an orphan commit in the real upstream repo) |
| `new-capability:*` | low–high | code starts doing something no file in the old version did: download-and-run, token tools (`gh auth token`, cloud metadata IPs), exfil services, persistence (`.claude/settings.json`, `folderOpen` tasks), credential paths, secret env vars, env dumps, wallet hooks, `child_process`, `eval`. Also looks inside base64 string literals. |
| `new-endpoint` | medium / high | code sends a request to a host the old version never mentioned; high when secret material (`seed`, `privateKey`, `process.env`, …) is next to the request or passed to the function that makes it |
| `obfuscation` | high | `_0x`-style obfuscation appears in a package that had none |
| `hidden-code` | high | code placed after hundreds of spaces on one line, off-screen in editors and diffs |
| `agent-autorun` | medium / high | ships a Claude Code, VS Code, Cursor or Gemini config that runs commands when a folder opens or a session starts |
| `fresh-dependency` | medium / high | a new dependency that is days old and owned by someone who does not maintain this package |
| `encoded-blob`, `injected-growth`, `new-binary` | medium | large encoded blob; a small source file grows past 20 KB and 8×; first native binary |
| `provenance-dropped` | medium | the old release had build provenance, the new one doesn't |
| `new-publisher` | low | published by an account that never published this package before |

## Reproduce

```
python corpus/fetch_dd.py        # 1,443 encrypted zips, never extracted to disk
python corpus/build_mal.py       # malicious pairs + clean baselines
python corpus/build_benign.py    # benign pairs
python corpus/evaluate.py --split train
python corpus/evaluate.py --split test
python -m pytest
```

Samples stay in their encrypted zips and are read in memory. After the first read, a scrambled copy (every byte XOR 0x5A) is cached so later runs are fast. Nothing that can run, and nothing an antivirus would match, is written to disk.

## Limits

- npm only. Static only: code that fetches its payload at run time from a host already in the old version will pass.
- A patient attacker can split a change over several releases. Each step is compared only with the step before.
- Rules are regular expressions, not a parser. That keeps them fast and readable, and it means minified code can hide things a real data-flow analysis would find.
- The evaluation's benign set is popular packages. Small packages with one maintainer may behave differently.
