# pkgdelta: catch hijacked npm releases by comparing each update with the previous one

pkgdelta checks every npm version your lockfile brings in against the same package's previous release, and blocks the ones that suddenly add an install hook, a new network host, credential theft, obfuscated code or a git dependency. It caught 92.7% of 2026's npm account-takeover campaigns on held-out data, with rules frozen before 2026, and blocked 1 of 3,457 normal updates.

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

Python 3.10+, no dependencies, no server, no LLM. It downloads tarballs and reads them in memory; it never runs package code. Exit code 1 means something was blocked.

> Status: research project with a working tool. The rules are simple and a determined attacker can get around them. Use it as one layer, not the only one.

## Headline result

Ground truth: 1,363 real hijacked releases of existing npm packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (2024-12 to 2026-06), and 6,707 normal updates of the top 1,200 npm packages. Rules were written looking only at pre-2026 attacks and committed (`c3484c5`) before the 2026 run.

| Held-out 2026 attacks (16 campaigns, 499 releases) | Campaigns caught (macro recall) | Releases caught | Normal updates blocked |
|---|---|---|---|
| **pkgdelta v1, frozen rules** | **92.7%** | **96.8%** | **1 of 3,457 (0.03%)** |
| GuardDog 3.2.0, its own `high_risk` verdict | 53.2% | 42.4% | 7 of 751 (0.93%) |
| GuardDog 3.2.0, any `threat-*` rule | 81.1% | 83.5% | 25 of 751 (3.33%) |

Across all 6,707 normal updates, no high-severity rule fired even once. The single blocked update, `@octokit/openapi-types` 28 → 29, is a first-time publisher on a major release without the build provenance every earlier release had. A human should look at that one anyway.

After the dataset ends, on attacks nobody had tuned for: the [ChainDrop worm](docs/incidents/chaindrop-keyv.md) (`keyv` 6.0.0, August 2026), 49 of 53 blocked; the 4 misses carry no payload in the tarball.

Full method, v2 numbers, the post-June holdout and every miss: [docs/evaluation.md](docs/evaluation.md).

## Am I affected?

Run `pkgdelta audit` on your lockfile. It compares every locked version with the release before it, and asks [OSV](https://osv.dev) whether the version is known malware, so a lockfile that still pins a version npm has deleted fails too.

Each incident page lists every malicious version, its OSV id, what changed compared with the previous release, and what to clean up.

| Incident | Malicious versions include | pkgdelta blocked |
|---|---|---|
| [ChainDrop worm](docs/incidents/chaindrop-keyv.md), Aug 2026 | `keyv` 6.0.0, `cache-manager` 7.2.10, `file-entry-cache` 11.1.6, `@cacheable/node-cache` 3.1.2, `@qlik/*`, `@servicetitan/*` | 49 of 53 |
| [Mastra / easy-day-js](docs/incidents/mastra-easy-day-js.md), Jun 2026 | 117 `@mastra/*` packages, `mastra`, `create-mastra`, `easy-day-js` 1.11.22 | 111 of 119 |
| [Miasma (binding.gyp)](docs/incidents/node-gyp-miasma.md), Jun 2026 | `@vapi-ai/server-sdk` 0.11.2, `leo-logger` 1.0.8, `autotel-*`, `awaitly-*`, `executable-stories-*` | 44 of 44 |
| [Red Hat Cloud Services](docs/incidents/redhat-cloud-services.md), Jun 2026 | `@redhat-cloud-services/chrome` 2.3.1 and 15 more | 16 of 16 |
| [TanStack / Mini Shai-Hulud](docs/incidents/tanstack-mini-shai-hulud.md), May 2026 | 60 `@tanstack/*` packages (e.g. `@tanstack/react-router` 1.169.5), `@uipath/*`, `@mistralai/*`, `@opensearch-project/opensearch`, 44 `@antv/*`, `jest-canvas-mock` 2.5.3 | 214 of 214 (v1: 207) |
| [SAP cap-js](docs/incidents/sap-cap-js.md), Apr 2026 | `@cap-js/db-service` 2.10.1, `@cap-js/postgres` 2.2.2, `@cap-js/sqlite` 2.2.2, `mbt` 1.2.48 | 4 of 4 |
| [Bitwarden CLI](docs/incidents/bitwarden-cli.md), Apr 2026 | `@bitwarden/cli` 2026.4.0 | 1 of 1 |
| [axios / plain-crypto-js](docs/incidents/axios-plain-crypto-js.md), Mar 2026 | `axios` 1.14.1, `plain-crypto-js` 4.2.1 | 1 of 1, narrowly |
| [Shai-Hulud 2.0](docs/incidents/shai-hulud-2.md), Nov 2025 | `@postman/tunnel-agent` 0.6.5, `@posthog/*`, `@asyncapi/*`, `@voiceflow/*`, `@ensdomains/*` | 412 of 412 |
| [Shai-Hulud](docs/incidents/shai-hulud.md), Sep 2025 | `@ctrl/tinycolor` 4.1.1, `@operato/*`, `@things-factory/*`, `@nativescript-community/*` | 370 of 370 |
| [chalk and debug](docs/incidents/chalk-debug.md), Sep 2025 | `chalk` 5.6.1, `debug` 4.4.2, `ansi-styles` 6.2.2, `ansi-regex` 6.2.1, `wrap-ansi` 9.0.1, `duckdb` 1.3.3 | 18 of 18 |
| [Nx / s1ngularity](docs/incidents/nx-s1ngularity.md), Aug 2025 | `@nx/devkit`, `@nx/js`, `@nx/workspace` 21.5.0 | 7 of 7 |

The 2025 incidents are training data (the rules were written while looking at them). The index with GuardDog's numbers per incident is [docs/incidents](docs/incidents/README.md).

## How it works

When an attacker takes over a popular package, the new release does something the old one never did: it adds an install script, calls a host it never called, starts reading `~/.npmrc`, or ships obfuscated code. pkgdelta looks only at that difference. The package's own history is the baseline.

```
$ pkgdelta local ./ms-2.1.3-injected.tgz
BLOCK ms 2.1.3 -> 2.1.3  (score 12)
        HIGH install-hook: preinstall script added: node setup.mjs [package.json]
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [setup.mjs]
             import {execSync} from 'child_process'; const t = execSync('gh auth token').toString();
        HIGH new-endpoint: code sends requests to a host the previous version never mentioned: exfil-demo.invalid (next to 'process.env') [setup.mjs]
        ...
```

A scanner that looks at one version has to guess intent, because malware and normal code call the same APIs ("the capability–intent gap", [arXiv 2603.27549](https://arxiv.org/abs/2603.27549)). A scanner that compares with the previous version doesn't: `debug` has no business reading `~/.ssh` in a patch release, whatever the API. Every finding points at a file and a line of evidence. Scores: high 3, medium 2, low 1; a version is blocked at 3. The rules and why each has its severity: [docs/rules.md](docs/rules.md).

## Compared with other defences

| | What it answers | Blind spot on 2026 attacks |
|---|---|---|
| **pkgdelta** | Does this release do something the package never did before? | No payload in the tarball; payload in a fresh dependency that is already deleted ([Mastra](docs/incidents/mastra-easy-day-js.md)); code that builds its host at run time |
| [GuardDog](https://github.com/DataDog/guarddog) (open source) | Does this package look malicious on its own? | Git dependencies, 10 MB bundles, `binding.gyp`; its verdict caught 42% of 2026 releases vs 97% of pre-2026 ones. It also flags what a package *is* (a remote-shell tool) as malware, release after release |
| Cooldowns (pnpm 11 `minimumReleaseAge`, Yarn 4.10, Deno) | Has anyone else noticed yet? | Works only because a vendor scanner flags the release within the wait (Socket flagged `keyv@6.0.0` six minutes after publish). Nobody outside the vendor can check that work |
| npm provenance / SLSA, trusted publishing | Was this built by the project's own pipeline? | `keyv` 6.0.0, the TanStack and the Red Hat releases all had valid provenance: the pipeline was real, the attacker controlled its input |
| `npm audit` | Is this version in the advisory database? | Nothing, until someone files the advisory. pkgdelta asks OSV the same question and also compares the code |
| Socket, Snyk, Aikido and other vendor scanners | Vendor's judgement, usually with a model | Closed; no published false-positive rate |

pkgdelta is meant to sit next to these, not replace them.

## Use

```
pkgdelta check <name> <version>             # one version vs the release before it
pkgdelta diff old-lock.json new-lock.json   # every version a lockfile change brings in
pkgdelta audit package-lock.json            # every locked version (incident response)
pkgdelta local ./my-pkg-1.2.3.tgz           # before you publish: compare with your last release
```

`--json` for machine output, `--no-osv` to skip the OSV lookup, `--against <version>` to pick the baseline yourself. Lockfiles: npm (v1–v3), pnpm, yarn. A private registry: set `PKGDELTA_REGISTRY`.

**In CI (GitHub Actions)**

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: thejusdutt/pkgdelta@v0.1.0
  with:
    lockfile: package-lock.json   # or pnpm-lock.yaml / yarn.lock
    # mode: audit                 # check every locked version, not only the changed ones
```

On a pull request it checks only the versions the lockfile change brings in. This repo's own CI runs the action against a lockfile that pins `chalk@5.6.1` and checks that the build fails.

**For maintainers**: run `pkgdelta local` on the output of `npm pack` as the last step before `npm publish`. The TanStack (2026) and `keyv` (2026) malicious releases were built by the projects' own CI, with valid provenance. A check in that pipeline that compares what is about to ship with what shipped last time would have failed the build.

## FAQ

**Does `npm audit` catch compromised packages like these?**
Only after an advisory exists. For the first hours of an attack there is none. `pkgdelta audit` asks OSV too, and also compares the code with the previous release, so it can block a version no one has reported yet.

**Is a cooldown like `minimumReleaseAge` enough?**
It is a good idea and you should keep it. It delays you until someone else notices. pkgdelta is a way to notice yourself, with a published false-positive rate.

**Doesn't npm provenance or trusted publishing prevent this?**
No. Provenance proves which pipeline built a release. The `keyv`, TanStack and Red Hat attacks ran through the real pipelines, so their provenance is valid. pkgdelta does use provenance as a weak signal: when a package that always had it suddenly doesn't, that adds weight (medium, never blocks alone).

**How many false positives?**
1 of 6,707 normal updates of popular packages, and no high-severity finding on any of them. Small single-maintainer packages may behave differently; that has not been measured.

**What does it miss?**
Releases with no payload in the tarball, payloads in a fresh dependency that has since been deleted, and code that assembles its host at run time (for example with `String.fromCharCode`). A patient attacker can also spread a change over several releases. The known misses are listed in [evaluation.md](docs/evaluation.md#what-it-misses-and-why).

**Does it run package code or extract malware to disk?**
No. Tarballs are read in memory. The evaluation corpus stays in its encrypted zips; the local cache is XOR-scrambled so nothing on disk is runnable or matches an antivirus signature.

**How is this different from GuardDog or Socket?**
They judge a version on its own. pkgdelta judges the change. On 2026 attacks that difference is most of the gap in the table above. GuardDog also answers a question pkgdelta doesn't: "is this package bad in itself?" If you want that answer too, run both.

**Which ecosystems?**
npm only.

## Reproduce

Every number comes from files in [`results/`](results): the pair lists, each detector's verdict on every pair, GuardDog's raw verdicts, and the comparison tables. The incident pages are generated from the same files by [`corpus/incident_tables.py`](corpus/incident_tables.py). Rebuilding everything from scratch takes about 3 GB of downloads and a few hours; the steps are in [docs/evaluation.md](docs/evaluation.md#reproduce).

## Limits

- npm only. Static only: code that fetches its payload at run time from a host already in the old version will pass.
- Each release is compared only with the one before it, so a change spread over several releases can slip through.
- Rules are regular expressions, not a parser. That keeps them fast and readable, and it means minified code can hide things a real data-flow analysis would find.
- The benign set is popular packages. Small packages with one maintainer may behave differently.

Prior work: Amalfi (ICSE 2022) used "capabilities the package never used before" as ML features, but the code was never released. RogueOne (ICSE 2024) does differential data-flow analysis as a research prototype.

## License

Apache-2.0. See [LICENSE](LICENSE).
