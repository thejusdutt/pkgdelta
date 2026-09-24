# ChainDrop npm worm (keyv 6.0.0, cacheable, file-entry-cache): detection results and how to check your lockfile

On 4 August 2026 a worm published malicious releases of `keyv` 6.0.0, `cacheable`, `file-entry-cache`, `cache-manager` and dozens of `@qlik`, `@nebula.js` and `@servicetitan` packages. pkgdelta blocks 49 of the 53 releases we could recover, with rules frozen months before the attack. The 4 it passes have no payload in the tarball.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results) · [Misses](#what-pkgdelta-missed)

## What happened

`keyv@6.0.0` ([MAL-2026-11524](https://osv.dev/vulnerability/MAL-2026-11524)) shipped with valid SLSA build provenance: it came out of the project's real release pipeline, the attacker just controlled what went into it. Socket flagged it six minutes after publish and npm removed it. Every infected release added the same thing: a `preinstall` hook that runs `node setup.mjs`, which downloads the Bun runtime from GitHub and runs an obfuscated second file (`Math_Symbol.js` in `keyv`, `math_init.js` in others).

npm had already deleted these versions by the time this test ran. The tarballs come from jsDelivr's cache, and 49 of the 53 copies are partial. `keyv@6.0.0` kept `setup.mjs` and `Math_Symbol.js` but lost `dist/`, which Socket found to be identical to the clean `6.0.0-rc.1` anyway.

## What changed compared with the previous release

pkgdelta's findings for `@arv-bedrock/logger` 1.7.0 → 1.7.2 (from `results/v2_fresh.jsonl`, low-severity lines left out):

```
BLOCK @arv-bedrock/logger 1.7.0 -> 1.7.2  (score 11)
        HIGH install-hook: preinstall script added: node setup.mjs [package.json]
        HIGH new-capability:download_exec: code starts using download exec (previous version never did) [setup.mjs]
             const _0x9e5ce7 = "https://github.com/oven-sh/bun/releases/download/bun-v" + V + "/" + _0x2dfbd9 + ".zip";
        HIGH obfuscation: obfuscated code appears (previous version had none) [setup.mjs]
```

The install hook alone is enough to block. Across 6,707 normal updates of popular packages, no high-severity rule fired even once.

## Detection results

This is part of the [fresh holdout](../evaluation.md#fresh-holdout-attacks-after-the-dataset-ends): attacks published after the DataDog dataset ends, so neither rule set had seen them.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 53 | 49 / 53 (92%) | 49 / 53 (92%) | 49 / 53 (92%) | 49 / 53 (92%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 49
- `new-capability:download_exec` (high): 26
- `obfuscation` (high): 26

<details><summary>All 53 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@arv-bedrock/logger` | 1.7.2 | 1.7.0 | [MAL-2026-11557](https://osv.dev/vulnerability/MAL-2026-11557) | BLOCK (11) | high_risk |
| `@cacheable/node-cache` | 3.1.2 | 3.1.1 | [MAL-2026-11560](https://osv.dev/vulnerability/MAL-2026-11560) | BLOCK (3) | high_risk |
| `@deliveroo/reevent` | 1.0.1 | 1.0.0 | [MAL-2026-11563](https://osv.dev/vulnerability/MAL-2026-11563) | BLOCK (11) | high_risk |
| `@keyv/compress-brotli` | 6.0.0 | 2.0.5 | [MAL-2026-12009](https://osv.dev/vulnerability/MAL-2026-12009) | pass (0) | no_risks_detected |
| `@nebula.js/cli` | 7.1.2 | 7.1.1 | [MAL-2026-11565](https://osv.dev/vulnerability/MAL-2026-11565) | BLOCK (3) | high_risk |
| `@nebula.js/cli-build` | 7.1.2 | 7.1.1 | [MAL-2026-11566](https://osv.dev/vulnerability/MAL-2026-11566) | BLOCK (3) | high_risk |
| `@nebula.js/cli-sense` | 7.1.2 | 7.1.1 | [MAL-2026-11567](https://osv.dev/vulnerability/MAL-2026-11567) | BLOCK (3) | high_risk |
| `@nebula.js/cli-serve` | 7.1.2 | 7.1.1 | [MAL-2026-11568](https://osv.dev/vulnerability/MAL-2026-11568) | BLOCK (3) | high_risk |
| `@nebula.js/sn-line-chart` | 2.7.1 | 2.7.0 | [MAL-2026-11575](https://osv.dev/vulnerability/MAL-2026-11575) | BLOCK (3) | high_risk |
| `@nebula.js/stardust` | 7.1.2 | 7.1.1 | [MAL-2026-11584](https://osv.dev/vulnerability/MAL-2026-11584) | BLOCK (3) | high_risk |
| `@ornikar/jest-config` | 13.0.5 | 13.0.2 | [MAL-2026-11758](https://osv.dev/vulnerability/MAL-2026-11758) | BLOCK (3) | high_risk |
| `@qlik/api` | 2.14.2 | 2.14.1 | [MAL-2026-11783](https://osv.dev/vulnerability/MAL-2026-11783) | BLOCK (3) | high_risk |
| `@qlik/browserslist-config` | 3.0.2 | 3.0.1 | [MAL-2026-11784](https://osv.dev/vulnerability/MAL-2026-11784) | BLOCK (3) | high_risk |
| `@qlik/embed-react` | 2.5.3 | 2.5.2 | [MAL-2026-11789](https://osv.dev/vulnerability/MAL-2026-11789) | BLOCK (3) | high_risk |
| `@qlik/embed-runtime` | 1.6.4 | 1.6.3 | [MAL-2026-11790](https://osv.dev/vulnerability/MAL-2026-11790) | BLOCK (3) | high_risk |
| `@qlik/embed-web-components` | 1.7.3 | 1.7.2 | [MAL-2026-11792](https://osv.dev/vulnerability/MAL-2026-11792) | BLOCK (3) | high_risk |
| `@qlik/oxfmt-config` | 0.1.6 | 0.1.5 | [MAL-2026-11799](https://osv.dev/vulnerability/MAL-2026-11799) | BLOCK (3) | high_risk |
| `@qlik/oxlint-config` | 0.7.2 | 0.7.1 | [MAL-2026-11800](https://osv.dev/vulnerability/MAL-2026-11800) | BLOCK (3) | high_risk |
| `@qlik/sdk` | 0.28.1 | 0.28.0 | [MAL-2026-11804](https://osv.dev/vulnerability/MAL-2026-11804) | BLOCK (3) | high_risk |
| `@qlik/tsconfig` | 1.0.3 | 1.0.2 | [MAL-2026-11810](https://osv.dev/vulnerability/MAL-2026-11810) | BLOCK (3) | high_risk |
| `@servicetitan/eslint-plugin-mobx-6` | 12.8.17 | 12.8.14 | [MAL-2026-11864](https://osv.dev/vulnerability/MAL-2026-11864) | BLOCK (11) | high_risk |
| `@servicetitan/examples` | 1.2.5 | 1.2.4 | [MAL-2026-11866](https://osv.dev/vulnerability/MAL-2026-11866) | BLOCK (10) | high_risk |
| `@servicetitan/examples` | 1.2.6 | 1.2.4 | [MAL-2026-11866](https://osv.dev/vulnerability/MAL-2026-11866) | BLOCK (10) | high_risk |
| `@servicetitan/examples` | 1.2.7 | 1.2.4 | [MAL-2026-11866](https://osv.dev/vulnerability/MAL-2026-11866) | BLOCK (10) | high_risk |
| `@servicetitan/grid` | 0.0.63 | 0.0.62 | [MAL-2026-11872](https://osv.dev/vulnerability/MAL-2026-11872) | BLOCK (11) | high_risk |
| `@servicetitan/grid` | 0.0.64 | 0.0.62 | [MAL-2026-11872](https://osv.dev/vulnerability/MAL-2026-11872) | BLOCK (11) | high_risk |
| `@servicetitan/grid` | 0.0.65 | 0.0.62 | [MAL-2026-11872](https://osv.dev/vulnerability/MAL-2026-11872) | BLOCK (11) | high_risk |
| `@servicetitan/marketing-ui` | 9.3.1 | 9.3.0 | [MAL-2026-11896](https://osv.dev/vulnerability/MAL-2026-11896) | BLOCK (11) | high_risk |
| `@servicetitan/marketing-ui` | 9.3.2 | 9.3.0 | [MAL-2026-11896](https://osv.dev/vulnerability/MAL-2026-11896) | BLOCK (11) | high_risk |
| `@servicetitan/measure-sheet-data` | 2.6.3 | 2.6.0 | [MAL-2026-11898](https://osv.dev/vulnerability/MAL-2026-11898) | BLOCK (11) | high_risk |
| `@servicetitan/micro-frontend` | 0.0.4 | 0.0.3 | [MAL-2026-11900](https://osv.dev/vulnerability/MAL-2026-11900) | BLOCK (11) | high_risk |
| `@servicetitan/micro-frontend` | 0.0.5 | 0.0.3 | [MAL-2026-11900](https://osv.dev/vulnerability/MAL-2026-11900) | BLOCK (11) | high_risk |
| `@servicetitan/micro-frontend` | 0.0.6 | 0.0.3 | [MAL-2026-11900](https://osv.dev/vulnerability/MAL-2026-11900) | BLOCK (11) | high_risk |
| `@servicetitan/microfront` | 0.0.2 | 0.0.1 | [MAL-2026-11901](https://osv.dev/vulnerability/MAL-2026-11901) | BLOCK (11) | high_risk |
| `@servicetitan/microfront` | 0.0.3 | 0.0.1 | [MAL-2026-11901](https://osv.dev/vulnerability/MAL-2026-11901) | BLOCK (11) | high_risk |
| `@servicetitan/microfront` | 0.0.4 | 0.0.1 | [MAL-2026-11901](https://osv.dev/vulnerability/MAL-2026-11901) | BLOCK (11) | high_risk |
| `@servicetitan/microfront-auth` | 0.0.5 | 0.0.4 | [MAL-2026-11902](https://osv.dev/vulnerability/MAL-2026-11902) | BLOCK (11) | high_risk |
| `@servicetitan/microfront-auth` | 0.0.6 | 0.0.4 | [MAL-2026-11902](https://osv.dev/vulnerability/MAL-2026-11902) | BLOCK (11) | high_risk |
| `@servicetitan/microfront-auth` | 0.0.7 | 0.0.4 | [MAL-2026-11902](https://osv.dev/vulnerability/MAL-2026-11902) | BLOCK (11) | high_risk |
| `@servicetitan/suppress-warnings` | 34.0.1 | 34.0.0 | [MAL-2026-11928](https://osv.dev/vulnerability/MAL-2026-11928) | pass (0) | no_risks_detected |
| `@servicetitan/suppress-warnings` | 34.1.0 | 34.0.0 | [MAL-2026-11928](https://osv.dev/vulnerability/MAL-2026-11928) | pass (0) | no_risks_detected |
| `@servicetitan/suppress-warnings` | 34.2.0 | 34.0.0 | [MAL-2026-11928](https://osv.dev/vulnerability/MAL-2026-11928) | pass (0) | no_risks_detected |
| `@servicetitan/table` | 41.3.1 | 41.3.0 | [MAL-2026-11929](https://osv.dev/vulnerability/MAL-2026-11929) | BLOCK (3) | high_risk |
| `@servicetitan/table` | 41.3.2 | 41.3.0 | [MAL-2026-11929](https://osv.dev/vulnerability/MAL-2026-11929) | BLOCK (11) | high_risk |
| `@servicetitan/table` | 41.3.3 | 41.3.0 | [MAL-2026-11929](https://osv.dev/vulnerability/MAL-2026-11929) | BLOCK (11) | high_risk |
| `@servicetitan/unit-tests` | 0.0.2 | 0.0.1 | [MAL-2026-11947](https://osv.dev/vulnerability/MAL-2026-11947) | BLOCK (11) | high_risk |
| `@servicetitan/unit-tests` | 0.0.3 | 0.0.1 | [MAL-2026-11947](https://osv.dev/vulnerability/MAL-2026-11947) | BLOCK (11) | high_risk |
| `@servicetitan/unit-tests` | 0.0.4 | 0.0.1 | [MAL-2026-11947](https://osv.dev/vulnerability/MAL-2026-11947) | BLOCK (11) | high_risk |
| `cache-manager` | 7.2.10 | 7.2.9 | [MAL-2026-11523](https://osv.dev/vulnerability/MAL-2026-11523) | BLOCK (3) | high_risk |
| `file-entry-cache` | 11.1.6 | 11.1.5 | [MAL-2026-11970](https://osv.dev/vulnerability/MAL-2026-11970) | BLOCK (4) | high_risk |
| `http-metrics-middleware` | 2.2.2 | 2.2.1 | [MAL-2026-11975](https://osv.dev/vulnerability/MAL-2026-11975) | BLOCK (3) | high_risk |
| `keyv` | 6.0.0 | 5.6.0 | [MAL-2026-11524](https://osv.dev/vulnerability/MAL-2026-11524) | BLOCK (5) | high_risk |
| `picasso.js` | 2.11.6 | 2.11.5 | [MAL-2026-11979](https://osv.dev/vulnerability/MAL-2026-11979) | BLOCK (3) | high_risk |

</details>
<!-- numbers:end -->

## What pkgdelta missed

- `@keyv/compress-brotli` 6.0.0 differs from its previous release only in the version number and git hash. Socket's write-up says the `@keyv/*` 6.0.0 tarballs don't carry the payload. GuardDog passes it too.
- The three `@servicetitan/suppress-warnings` versions (34.0.1, 34.1.0, 34.2.0) were published in February and March 2026, five months before the worm. The advisory bundles them with the ChainDrop releases, but they are not part of it, and the content change is again only the version.

## Am I affected?

Check your lockfile. `audit` compares every locked version with its previous release and also asks [OSV](https://osv.dev) whether the version is known malware, so a lockfile that still pins `keyv@6.0.0` fails even though npm deleted it.

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

If a listed version was ever installed on a machine, treat that machine as compromised: the preinstall hook ran before your code did. Rotate the npm, GitHub and cloud credentials it could read.

Other incidents with the same `setup.mjs` → Bun shape: [SAP cap-js](sap-cap-js.md), [Bitwarden CLI](bitwarden-cli.md), [TanStack](tanstack-mini-shai-hulud.md). All incidents: [index](README.md).
