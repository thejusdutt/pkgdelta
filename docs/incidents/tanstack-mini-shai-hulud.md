# TanStack npm compromise (Mini Shai-Hulud, May 2026) and the @antv wave: detection results and how to check your lockfile

On 11 and 12 May 2026 60 malicious releases went out across 40 `@tanstack/*` packages, plus `@uipath`, `@squawk`, `@tallyui`, `@mistralai`, `@opensearch-project/opensearch` and others: 163 releases in the DataDog dataset. A week later, on 19 May, 44 releases of 38 `@antv/*` packages and `echarts-for-react`, `jest-canvas-mock`, `jest-date-mock` and `size-sensor` followed with the same trick: 51 more. The first wave is the one people call Mini Shai-Hulud.

pkgdelta's frozen v1 rules block 207 of the 214. The 7 it missed carried no code at all, only a new git dependency. v2 blocks all 214 — but v2 was written after looking at these misses, so read that number as "what the rules can do", not as a clean test.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results) · [The git-dependency trick](#the-git-dependency-trick)

## What happened

The TanStack releases carry valid SLSA build provenance, so a signature check passes. Each release added a dependency named like `@tanstack/setup` that installs from `github:tanstack/router#<commit>`: a commit reachable through the real project's GitHub URL, but pushed by the attacker. npm runs a git dependency's `prepare` script when it installs it, so the payload can live entirely outside the npm tarball. Most releases also carried an obfuscated payload in the tarball itself, with the same pieces seen in the [SAP cap-js](sap-cap-js.md) and [Bitwarden CLI](bitwarden-cli.md) attacks: AWS keys from the environment, the cloud metadata IPs (`169.254.169.254`, `169.254.170.2`), and files written into `.vscode/tasks.json` and `.claude/` so the code runs again when a developer opens the folder.

The `@antv` wave on 19 May used the same shape: a `preinstall` of `bun run index.js`, obfuscated `index.js`, and an `@antv/setup` dependency from `github:antvis/G2#<commit>`.

The DataDog dataset splits these into two campaigns (found 2026-05-11 and 2026-05-19). This page shows both.

## What changed compared with the previous release

pkgdelta's findings for `@tanstack/arktype-adapter` 1.166.9 → 1.166.12 (from `results/v2_test.jsonl`, low-severity lines left out):

```
BLOCK @tanstack/arktype-adapter 1.166.9 -> 1.166.12  (score 19)
        HIGH non-registry-dependency: new dependency @tanstack/setup installs from outside the registry:
             github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c [package.json]
        HIGH new-capability:token_tools: code starts using token tools (previous version never did)
             …'http://169.254.170.2'+_0x347655…
        HIGH new-capability:persistence: code starts using persistence (previous version never did)
             var hO={'.vscode/tasks.json':FO,'.claude/router_runtime.js':{'sourcePath':Bun[…]},…
        HIGH obfuscation: obfuscated code appears (previous version had none)
      MEDIUM new-capability:secret_env: code starts using secret env (previous version never did)
      MEDIUM new-capability:credential_paths: code starts using credential paths (previous version never did)
      MEDIUM encoded-blob: large encoded blob added (3643 chars)
```

## Detection results

Both waves are in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 214 | 207 / 214 (97%) | 214 / 214 (100%) | 143 / 214 (67%) | 210 / 214 (98%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `obfuscation` (high): 207
- `encoded-blob` (medium): 205
- `new-capability:persistence` (high): 157
- `new-capability:secret_env` (medium): 154
- `new-capability:credential_paths` (medium): 153
- `install-hook` (high): 147
- `new-capability:token_tools` (high): 142
- `non-registry-dependency` (high): 111
- `new-capability:download_exec` (high): 99
- `provenance-dropped` (medium): 26
- `injected-growth` (medium): 1

<details><summary>All 214 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@antv/algorithm` | 0.3.26 | 0.1.26 | [MAL-2026-3850](https://osv.dev/vulnerability/MAL-2026-3850) | BLOCK (12) | high_risk |
| `@antv/ava` | 3.6.1 | 3.4.1 | [MAL-2026-3853](https://osv.dev/vulnerability/MAL-2026-3853) | BLOCK (12) | high_risk |
| `@antv/ava-react` | 3.5.2 | 3.3.2 | [MAL-2026-3854](https://osv.dev/vulnerability/MAL-2026-3854) | BLOCK (12) | high_risk |
| `@antv/data-samples` | 1.2.1 | 1.0.1 | [MAL-2026-3867](https://osv.dev/vulnerability/MAL-2026-3867) | BLOCK (12) | high_risk |
| `@antv/data-set` | 0.12.8 | 0.11.8 | [MAL-2026-3868](https://osv.dev/vulnerability/MAL-2026-3868) | BLOCK (12) | high_risk |
| `@antv/dumi-theme-antv` | 0.10.4 | 0.8.4 | [MAL-2026-3874](https://osv.dev/vulnerability/MAL-2026-3874) | BLOCK (14) | high_risk |
| `@antv/f-engine` | 1.11.0 | 1.10.0 | [MAL-2026-3882](https://osv.dev/vulnerability/MAL-2026-3882) | BLOCK (13) | high_risk |
| `@antv/f2-graphic` | 0.2.16 | 0.0.16 | [MAL-2026-3893](https://osv.dev/vulnerability/MAL-2026-3893) | BLOCK (12) | high_risk |
| `@antv/f6` | 0.1.19 | 0.0.19 | [MAL-2026-3900](https://osv.dev/vulnerability/MAL-2026-3900) | BLOCK (13) | high_risk |
| `@antv/f6-core` | 0.2.2 | 0.0.2 | [MAL-2026-3902](https://osv.dev/vulnerability/MAL-2026-3902) | BLOCK (12) | high_risk |
| `@antv/g` | 6.4.1 | 6.3.1 | [MAL-2026-3908](https://osv.dev/vulnerability/MAL-2026-3908) | BLOCK (11) | high_risk |
| `@antv/g-device-api` | 1.7.13 | 1.6.13 | [MAL-2026-3917](https://osv.dev/vulnerability/MAL-2026-3917) | BLOCK (13) | high_risk |
| `@antv/g-lite` | 2.8.0 | 2.7.0 | [MAL-2026-3921](https://osv.dev/vulnerability/MAL-2026-3921) | BLOCK (13) | high_risk |
| `@antv/g-lite` | 2.9.0 | 2.7.0 | [MAL-2026-3921](https://osv.dev/vulnerability/MAL-2026-3921) | BLOCK (12) | high_risk |
| `@antv/g2-extension-3d` | 0.3.0 | 0.2.0 | [MAL-2026-3975](https://osv.dev/vulnerability/MAL-2026-3975) | BLOCK (13) | high_risk |
| `@antv/g6-mobile` | 0.2.2 | 0.1.2 | [MAL-2026-3990](https://osv.dev/vulnerability/MAL-2026-3990) | BLOCK (13) | high_risk |
| `@antv/g6-pc` | 0.10.25 | 0.8.25 | [MAL-2026-3991](https://osv.dev/vulnerability/MAL-2026-3991) | BLOCK (12) | high_risk |
| `@antv/g6-pc` | 0.9.25 | 0.8.25 | [MAL-2026-3991](https://osv.dev/vulnerability/MAL-2026-3991) | BLOCK (13) | high_risk |
| `@antv/gi-assets-algorithm` | 2.4.19 | 2.3.19 | [MAL-2026-4000](https://osv.dev/vulnerability/MAL-2026-4000) | BLOCK (13) | high_risk |
| `@antv/gi-assets-scene` | 2.3.21 | 2.2.21 | [MAL-2026-4007](https://osv.dev/vulnerability/MAL-2026-4007) | BLOCK (13) | high_risk |
| `@antv/gi-assets-xlab` | 0.2.30 | 0.1.30 | [MAL-2026-4010](https://osv.dev/vulnerability/MAL-2026-4010) | BLOCK (13) | high_risk |
| `@antv/gi-assets-xlab` | 0.3.30 | 0.1.30 | [MAL-2026-4010](https://osv.dev/vulnerability/MAL-2026-4010) | BLOCK (12) | high_risk |
| `@antv/gpt-vis` | 1.1.0 | 1.0.0 | [MAL-2026-4020](https://osv.dev/vulnerability/MAL-2026-4020) | BLOCK (10) | high_risk |
| `@antv/insight-component` | 1.1.0 | 1.0.0 | [MAL-2026-4029](https://osv.dev/vulnerability/MAL-2026-4029) | BLOCK (13) | high_risk |
| `@antv/l7-component` | 2.27.10 | 2.25.10 | [MAL-2026-4034](https://osv.dev/vulnerability/MAL-2026-4034) | BLOCK (12) | high_risk |
| `@antv/l7-composite-layers` | 0.19.1 | 0.17.1 | [MAL-2026-4035](https://osv.dev/vulnerability/MAL-2026-4035) | BLOCK (12) | high_risk |
| `@antv/l7-core` | 2.27.10 | 2.25.10 | [MAL-2026-4036](https://osv.dev/vulnerability/MAL-2026-4036) | BLOCK (12) | high_risk |
| `@antv/l7-draw` | 3.2.5 | 3.1.5 | [MAL-2026-4038](https://osv.dev/vulnerability/MAL-2026-4038) | BLOCK (13) | high_risk |
| `@antv/l7-map` | 2.27.10 | 2.25.10 | [MAL-2026-4043](https://osv.dev/vulnerability/MAL-2026-4043) | BLOCK (12) | high_risk |
| `@antv/l7-source` | 2.27.10 | 2.25.10 | [MAL-2026-4051](https://osv.dev/vulnerability/MAL-2026-4051) | BLOCK (12) | high_risk |
| `@antv/li-aiearth-assets` | 0.5.7 | 0.4.7 | [MAL-2026-4059](https://osv.dev/vulnerability/MAL-2026-4059) | BLOCK (13) | high_risk |
| `@antv/li-aiearth-assets` | 0.6.7 | 0.4.7 | [MAL-2026-4059](https://osv.dev/vulnerability/MAL-2026-4059) | BLOCK (12) | high_risk |
| `@antv/lite-insight` | 2.2.1 | 2.1.1 | [MAL-2026-4066](https://osv.dev/vulnerability/MAL-2026-4066) | BLOCK (13) | high_risk |
| `@antv/mcp-server-chart` | 0.10.10 | 0.9.10 | [MAL-2026-4069](https://osv.dev/vulnerability/MAL-2026-4069) | BLOCK (12) | high_risk |
| `@antv/narrative-text-editor` | 0.3.20 | 0.2.20 | [MAL-2026-4072](https://osv.dev/vulnerability/MAL-2026-4072) | BLOCK (13) | high_risk |
| `@antv/narrative-text-editor` | 0.4.20 | 0.2.20 | [MAL-2026-4072](https://osv.dev/vulnerability/MAL-2026-4072) | BLOCK (12) | high_risk |
| `@antv/narrative-text-vis` | 0.5.16 | 0.3.16 | [MAL-2026-4074](https://osv.dev/vulnerability/MAL-2026-4074) | BLOCK (12) | high_risk |
| `@antv/s2-react` | 2.5.1 | 2.3.1 | [MAL-2026-4078](https://osv.dev/vulnerability/MAL-2026-4078) | BLOCK (12) | high_risk |
| `@antv/s2-react-components` | 2.3.2 | 2.1.2 | [MAL-2026-4079](https://osv.dev/vulnerability/MAL-2026-4079) | BLOCK (12) | high_risk |
| `@antv/scale` | 0.6.2 | 0.5.2 | [MAL-2026-4083](https://osv.dev/vulnerability/MAL-2026-4083) | BLOCK (12) | high_risk |
| `@antv/t8` | 0.5.0 | 0.3.0 | [MAL-2026-4087](https://osv.dev/vulnerability/MAL-2026-4087) | BLOCK (12) | high_risk |
| `@antv/x6-geometry` | 2.2.5 | 2.0.5 | [MAL-2026-3840](https://osv.dev/vulnerability/MAL-2026-3840) | BLOCK (12) | high_risk |
| `@antv/x6-react-components` | 2.1.9 | 2.0.9 | [MAL-2026-4113](https://osv.dev/vulnerability/MAL-2026-4113) | BLOCK (13) | high_risk |
| `@antv/x6-react-components` | 2.2.9 | 2.0.9 | [MAL-2026-4113](https://osv.dev/vulnerability/MAL-2026-4113) | BLOCK (12) | high_risk |
| `@beproduct/nestjs-auth` | 0.1.14 | 0.1.1 | [MAL-2026-3433](https://osv.dev/vulnerability/MAL-2026-3433) | BLOCK (22) | high_risk |
| `@beproduct/nestjs-auth` | 0.1.16 | 0.1.1 | [MAL-2026-3433](https://osv.dev/vulnerability/MAL-2026-3433) | BLOCK (22) | high_risk |
| `@beproduct/nestjs-auth` | 0.1.17 | 0.1.1 | [MAL-2026-3433](https://osv.dev/vulnerability/MAL-2026-3433) | BLOCK (19) | high_risk |
| `@beproduct/nestjs-auth` | 0.1.19 | 0.1.1 | [MAL-2026-3433](https://osv.dev/vulnerability/MAL-2026-3433) | BLOCK (22) | high_risk |
| `@beproduct/nestjs-auth` | 0.1.8 | 0.1.1 | [MAL-2026-3433](https://osv.dev/vulnerability/MAL-2026-3433) | BLOCK (22) | high_risk |
| `@draftlab/auth` | 0.24.2 | 0.24.0 | [MAL-2026-3596](https://osv.dev/vulnerability/MAL-2026-3596) | BLOCK (22) | high_risk |
| `@draftlab/db` | 0.16.2 | 0.16.0 | [MAL-2026-3598](https://osv.dev/vulnerability/MAL-2026-3598) | BLOCK (22) | high_risk |
| `@mesadev/rest` | 0.28.3 | 0.28.2 | [MAL-2026-3510](https://osv.dev/vulnerability/MAL-2026-3510) | BLOCK (22) | high_risk |
| `@mesadev/saguaro` | 0.4.22 | 0.4.21 | [MAL-2026-3599](https://osv.dev/vulnerability/MAL-2026-3599) | BLOCK (11) | suspicious |
| `@mesadev/sdk` | 0.28.3 | 0.28.2 | [MAL-2026-3600](https://osv.dev/vulnerability/MAL-2026-3600) | BLOCK (23) | high_risk |
| `@mistralai/mistralai-azure` | 1.7.1 | 1.7.0 | [MAL-2026-3511](https://osv.dev/vulnerability/MAL-2026-3511) | BLOCK (22) | high_risk |
| `@mistralai/mistralai-azure` | 1.7.2 | 1.7.0 | [MAL-2026-3511](https://osv.dev/vulnerability/MAL-2026-3511) | BLOCK (22) | high_risk |
| `@mistralai/mistralai-azure` | 1.7.3 | 1.7.0 | [MAL-2026-3511](https://osv.dev/vulnerability/MAL-2026-3511) | BLOCK (22) | high_risk |
| `@mistralai/mistralai-gcp` | 1.7.1 | 1.7.0 | [MAL-2026-3512](https://osv.dev/vulnerability/MAL-2026-3512) | BLOCK (22) | high_risk |
| `@mistralai/mistralai-gcp` | 1.7.2 | 1.7.0 | [MAL-2026-3512](https://osv.dev/vulnerability/MAL-2026-3512) | BLOCK (22) | high_risk |
| `@mistralai/mistralai-gcp` | 1.7.3 | 1.7.0 | [MAL-2026-3512](https://osv.dev/vulnerability/MAL-2026-3512) | BLOCK (22) | high_risk |
| `@openclaw-cn/cli` | 1.4.1 | 1.3.1 | [MAL-2026-3841](https://osv.dev/vulnerability/MAL-2026-3841) | BLOCK (9) | high_risk |
| `@openclaw-cn/feishu` | 0.2.11 | 0.1.11 | [MAL-2026-3842](https://osv.dev/vulnerability/MAL-2026-3842) | BLOCK (9) | high_risk |
| `@openclaw-cn/libsignal` | 2.1.1 | 2.0.1 | [MAL-2026-3843](https://osv.dev/vulnerability/MAL-2026-3843) | BLOCK (11) | high_risk |
| `@opensearch-project/opensearch` | 3.5.3 | 3.5.1 | [MAL-2026-3434](https://osv.dev/vulnerability/MAL-2026-3434) | BLOCK (3) | low |
| `@opensearch-project/opensearch` | 3.6.2 | 3.6.0 | [MAL-2026-3434](https://osv.dev/vulnerability/MAL-2026-3434) | BLOCK (22) | high_risk |
| `@opensearch-project/opensearch` | 3.7.0 | 3.6.0 | [MAL-2026-3434](https://osv.dev/vulnerability/MAL-2026-3434) | BLOCK (3) | low |
| `@opensearch-project/opensearch` | 3.8.0 | 3.6.0 | [MAL-2026-3434](https://osv.dev/vulnerability/MAL-2026-3434) | BLOCK (3) | low |
| `@squawk/airport-data` | 0.7.4 | 0.7.3 | [MAL-2026-3435](https://osv.dev/vulnerability/MAL-2026-3435) | BLOCK (24) | high_risk |
| `@squawk/airports` | 0.6.3 | 0.6.1 | [MAL-2026-3436](https://osv.dev/vulnerability/MAL-2026-3436) | BLOCK (21) | high_risk |
| `@squawk/airspace` | 0.8.2 | 0.8.0 | [MAL-2026-3437](https://osv.dev/vulnerability/MAL-2026-3437) | BLOCK (21) | high_risk |
| `@squawk/airspace-data` | 0.5.3 | 0.5.2 | [MAL-2026-3438](https://osv.dev/vulnerability/MAL-2026-3438) | BLOCK (24) | high_risk |
| `@squawk/airway-data` | 0.5.4 | 0.5.3 | [MAL-2026-3439](https://osv.dev/vulnerability/MAL-2026-3439) | BLOCK (24) | high_risk |
| `@squawk/airways` | 0.4.2 | 0.4.1 | [MAL-2026-3440](https://osv.dev/vulnerability/MAL-2026-3440) | BLOCK (24) | high_risk |
| `@squawk/fix-data` | 0.6.4 | 0.6.3 | [MAL-2026-3441](https://osv.dev/vulnerability/MAL-2026-3441) | BLOCK (24) | high_risk |
| `@squawk/fixes` | 0.3.3 | 0.3.1 | [MAL-2026-3442](https://osv.dev/vulnerability/MAL-2026-3442) | BLOCK (21) | high_risk |
| `@squawk/flight-math` | 0.5.4 | 0.5.3 | [MAL-2026-3443](https://osv.dev/vulnerability/MAL-2026-3443) | BLOCK (24) | high_risk |
| `@squawk/flightplan` | 0.5.3 | 0.5.1 | [MAL-2026-3444](https://osv.dev/vulnerability/MAL-2026-3444) | BLOCK (21) | high_risk |
| `@squawk/geo` | 0.4.4 | 0.4.3 | [MAL-2026-3445](https://osv.dev/vulnerability/MAL-2026-3445) | BLOCK (24) | high_risk |
| `@squawk/icao-registry` | 0.5.2 | 0.5.1 | [MAL-2026-3446](https://osv.dev/vulnerability/MAL-2026-3446) | BLOCK (24) | high_risk |
| `@squawk/icao-registry-data` | 0.8.5 | 0.8.3 | [MAL-2026-3447](https://osv.dev/vulnerability/MAL-2026-3447) | BLOCK (21) | high_risk |
| `@squawk/mcp` | 0.9.1 | 0.9.0 | [MAL-2026-3448](https://osv.dev/vulnerability/MAL-2026-3448) | BLOCK (24) | high_risk |
| `@squawk/navaid-data` | 0.6.4 | 0.6.3 | [MAL-2026-3449](https://osv.dev/vulnerability/MAL-2026-3449) | BLOCK (24) | high_risk |
| `@squawk/navaids` | 0.4.2 | 0.4.1 | [MAL-2026-3450](https://osv.dev/vulnerability/MAL-2026-3450) | BLOCK (24) | high_risk |
| `@squawk/notams` | 0.3.6 | 0.3.5 | [MAL-2026-3451](https://osv.dev/vulnerability/MAL-2026-3451) | BLOCK (24) | high_risk |
| `@squawk/procedure-data` | 0.7.4 | 0.7.2 | [MAL-2026-3452](https://osv.dev/vulnerability/MAL-2026-3452) | BLOCK (21) | high_risk |
| `@squawk/procedures` | 0.5.2 | 0.5.1 | [MAL-2026-3453](https://osv.dev/vulnerability/MAL-2026-3453) | BLOCK (24) | high_risk |
| `@squawk/types` | 0.8.1 | 0.8.0 | [MAL-2026-3454](https://osv.dev/vulnerability/MAL-2026-3454) | BLOCK (24) | high_risk |
| `@squawk/units` | 0.4.4 | 0.4.2 | [MAL-2026-3455](https://osv.dev/vulnerability/MAL-2026-3455) | BLOCK (21) | high_risk |
| `@squawk/weather` | 0.5.6 | 0.5.5 | [MAL-2026-3456](https://osv.dev/vulnerability/MAL-2026-3456) | BLOCK (24) | high_risk |
| `@supersurkhet/cli` | 0.0.2 | 0.0.1 | [MAL-2026-3457](https://osv.dev/vulnerability/MAL-2026-3457) | BLOCK (22) | high_risk |
| `@supersurkhet/cli` | 0.0.4 | 0.0.1 | [MAL-2026-3457](https://osv.dev/vulnerability/MAL-2026-3457) | BLOCK (22) | high_risk |
| `@supersurkhet/cli` | 0.0.6 | 0.0.1 | [MAL-2026-3457](https://osv.dev/vulnerability/MAL-2026-3457) | BLOCK (19) | high_risk |
| `@supersurkhet/sdk` | 0.0.2 | 0.0.1 | [MAL-2026-3513](https://osv.dev/vulnerability/MAL-2026-3513) | BLOCK (22) | high_risk |
| `@supersurkhet/sdk` | 0.0.4 | 0.0.1 | [MAL-2026-3513](https://osv.dev/vulnerability/MAL-2026-3513) | BLOCK (22) | high_risk |
| `@supersurkhet/sdk` | 0.0.6 | 0.0.1 | [MAL-2026-3513](https://osv.dev/vulnerability/MAL-2026-3513) | BLOCK (19) | high_risk |
| `@tallyui/components` | 1.0.1 | 1.0.0 | [MAL-2026-3514](https://osv.dev/vulnerability/MAL-2026-3514) | BLOCK (22) | high_risk |
| `@tallyui/components` | 1.0.3 | 1.0.0 | [MAL-2026-3514](https://osv.dev/vulnerability/MAL-2026-3514) | BLOCK (22) | high_risk |
| `@tallyui/connector-medusa` | 1.0.1 | 1.0.0 | [MAL-2026-3515](https://osv.dev/vulnerability/MAL-2026-3515) | BLOCK (22) | high_risk |
| `@tallyui/connector-medusa` | 1.0.3 | 1.0.0 | [MAL-2026-3515](https://osv.dev/vulnerability/MAL-2026-3515) | BLOCK (22) | high_risk |
| `@tallyui/connector-shopify` | 1.0.1 | 1.0.0 | [MAL-2026-3516](https://osv.dev/vulnerability/MAL-2026-3516) | BLOCK (22) | high_risk |
| `@tallyui/connector-shopify` | 1.0.3 | 1.0.0 | [MAL-2026-3516](https://osv.dev/vulnerability/MAL-2026-3516) | BLOCK (22) | high_risk |
| `@tallyui/connector-vendure` | 1.0.1 | 1.0.0 | [MAL-2026-3458](https://osv.dev/vulnerability/MAL-2026-3458) | BLOCK (22) | high_risk |
| `@tallyui/connector-woocommerce` | 1.0.1 | 1.0.0 | [MAL-2026-3517](https://osv.dev/vulnerability/MAL-2026-3517) | BLOCK (22) | high_risk |
| `@tallyui/connector-woocommerce` | 1.0.3 | 1.0.0 | [MAL-2026-3517](https://osv.dev/vulnerability/MAL-2026-3517) | BLOCK (22) | high_risk |
| `@tallyui/core` | 0.2.1 | 0.2.0 | [MAL-2026-3603](https://osv.dev/vulnerability/MAL-2026-3603) | BLOCK (22) | high_risk |
| `@tallyui/database` | 1.0.1 | 1.0.0 | [MAL-2026-3518](https://osv.dev/vulnerability/MAL-2026-3518) | BLOCK (22) | high_risk |
| `@tallyui/database` | 1.0.3 | 1.0.0 | [MAL-2026-3518](https://osv.dev/vulnerability/MAL-2026-3518) | BLOCK (22) | high_risk |
| `@tallyui/pos` | 0.1.1 | 0.1.0 | [MAL-2026-3459](https://osv.dev/vulnerability/MAL-2026-3459) | BLOCK (22) | high_risk |
| `@tallyui/pos` | 0.1.3 | 0.1.0 | [MAL-2026-3459](https://osv.dev/vulnerability/MAL-2026-3459) | BLOCK (22) | high_risk |
| `@tallyui/storage-sqlite` | 0.2.1 | 0.2.0 | [MAL-2026-3604](https://osv.dev/vulnerability/MAL-2026-3604) | BLOCK (21) | high_risk |
| `@tallyui/storage-sqlite` | 0.2.2 | 0.2.0 | [MAL-2026-3604](https://osv.dev/vulnerability/MAL-2026-3604) | BLOCK (18) | high_risk |
| `@tallyui/storage-sqlite` | 0.2.3 | 0.2.0 | [MAL-2026-3604](https://osv.dev/vulnerability/MAL-2026-3604) | BLOCK (21) | high_risk |
| `@tallyui/theme` | 0.2.1 | 0.2.0 | [MAL-2026-3519](https://osv.dev/vulnerability/MAL-2026-3519) | BLOCK (22) | high_risk |
| `@tanstack/arktype-adapter` | 1.166.12 | 1.166.9 | [MAL-2026-3460](https://osv.dev/vulnerability/MAL-2026-3460) | BLOCK (19) | low |
| `@tanstack/eslint-plugin-router` | 1.161.12 | 1.161.6 | [MAL-2026-3461](https://osv.dev/vulnerability/MAL-2026-3461) | BLOCK (19) | low |
| `@tanstack/eslint-plugin-router` | 1.161.9 | 1.161.6 | [MAL-2026-3461](https://osv.dev/vulnerability/MAL-2026-3461) | BLOCK (19) | low |
| `@tanstack/eslint-plugin-start` | 0.0.4 | 0.0.1 | [MAL-2026-3462](https://osv.dev/vulnerability/MAL-2026-3462) | BLOCK (20) | low |
| `@tanstack/eslint-plugin-start` | 0.0.7 | 0.0.1 | [MAL-2026-3462](https://osv.dev/vulnerability/MAL-2026-3462) | BLOCK (19) | low |
| `@tanstack/history` | 1.161.9 | 1.161.6 | [MAL-2026-3463](https://osv.dev/vulnerability/MAL-2026-3463) | BLOCK (19) | low |
| `@tanstack/nitro-v2-vite-plugin` | 1.154.12 | 1.154.9 | [MAL-2026-3464](https://osv.dev/vulnerability/MAL-2026-3464) | BLOCK (19) | low |
| `@tanstack/react-router` | 1.169.5 | 1.169.2 | [MAL-2026-3465](https://osv.dev/vulnerability/MAL-2026-3465) | BLOCK (19) | low |
| `@tanstack/react-router` | 1.169.8 | 1.169.2 | [MAL-2026-3465](https://osv.dev/vulnerability/MAL-2026-3465) | BLOCK (19) | low |
| `@tanstack/react-router-devtools` | 1.166.16 | 1.166.13 | [MAL-2026-3466](https://osv.dev/vulnerability/MAL-2026-3466) | BLOCK (19) | low |
| `@tanstack/react-start` | 1.167.68 | 1.167.65 | [MAL-2026-3468](https://osv.dev/vulnerability/MAL-2026-3468) | BLOCK (19) | low |
| `@tanstack/react-start` | 1.167.71 | 1.167.65 | [MAL-2026-3468](https://osv.dev/vulnerability/MAL-2026-3468) | BLOCK (19) | low |
| `@tanstack/react-start-client` | 1.166.51 | 1.166.48 | [MAL-2026-3469](https://osv.dev/vulnerability/MAL-2026-3469) | BLOCK (19) | low |
| `@tanstack/react-start-client` | 1.166.54 | 1.166.48 | [MAL-2026-3469](https://osv.dev/vulnerability/MAL-2026-3469) | BLOCK (19) | low |
| `@tanstack/react-start-rsc` | 0.0.47 | 0.0.44 | [MAL-2026-3470](https://osv.dev/vulnerability/MAL-2026-3470) | BLOCK (19) | low |
| `@tanstack/react-start-rsc` | 0.0.50 | 0.0.44 | [MAL-2026-3470](https://osv.dev/vulnerability/MAL-2026-3470) | BLOCK (19) | low |
| `@tanstack/react-start-server` | 1.166.55 | 1.166.52 | [MAL-2026-3471](https://osv.dev/vulnerability/MAL-2026-3471) | BLOCK (19) | low |
| `@tanstack/router-cli` | 1.166.46 | 1.166.43 | [MAL-2026-3472](https://osv.dev/vulnerability/MAL-2026-3472) | BLOCK (19) | low |
| `@tanstack/router-cli` | 1.166.49 | 1.166.43 | [MAL-2026-3472](https://osv.dev/vulnerability/MAL-2026-3472) | BLOCK (19) | low |
| `@tanstack/router-core` | 1.169.5 | 1.169.2 | [MAL-2026-3473](https://osv.dev/vulnerability/MAL-2026-3473) | BLOCK (19) | low |
| `@tanstack/router-core` | 1.169.8 | 1.169.2 | [MAL-2026-3473](https://osv.dev/vulnerability/MAL-2026-3473) | BLOCK (19) | low |
| `@tanstack/router-devtools` | 1.166.16 | 1.166.13 | [MAL-2026-3474](https://osv.dev/vulnerability/MAL-2026-3474) | BLOCK (19) | low |
| `@tanstack/router-devtools-core` | 1.167.6 | 1.167.3 | [MAL-2026-3475](https://osv.dev/vulnerability/MAL-2026-3475) | BLOCK (19) | low |
| `@tanstack/router-devtools-core` | 1.167.9 | 1.167.3 | [MAL-2026-3475](https://osv.dev/vulnerability/MAL-2026-3475) | BLOCK (19) | low |
| `@tanstack/router-generator` | 1.166.45 | 1.166.42 | [MAL-2026-3476](https://osv.dev/vulnerability/MAL-2026-3476) | BLOCK (19) | low |
| `@tanstack/router-generator` | 1.166.48 | 1.166.42 | [MAL-2026-3476](https://osv.dev/vulnerability/MAL-2026-3476) | BLOCK (19) | low |
| `@tanstack/router-plugin` | 1.167.38 | 1.167.35 | [MAL-2026-3477](https://osv.dev/vulnerability/MAL-2026-3477) | BLOCK (19) | low |
| `@tanstack/router-plugin` | 1.167.41 | 1.167.35 | [MAL-2026-3477](https://osv.dev/vulnerability/MAL-2026-3477) | BLOCK (19) | low |
| `@tanstack/router-ssr-query-core` | 1.168.3 | 1.168.0 | [MAL-2026-3478](https://osv.dev/vulnerability/MAL-2026-3478) | BLOCK (19) | low |
| `@tanstack/router-ssr-query-core` | 1.168.6 | 1.168.0 | [MAL-2026-3478](https://osv.dev/vulnerability/MAL-2026-3478) | BLOCK (19) | low |
| `@tanstack/router-utils` | 1.161.11 | 1.161.8 | [MAL-2026-3479](https://osv.dev/vulnerability/MAL-2026-3479) | BLOCK (19) | low |
| `@tanstack/router-utils` | 1.161.14 | 1.161.8 | [MAL-2026-3479](https://osv.dev/vulnerability/MAL-2026-3479) | BLOCK (19) | low |
| `@tanstack/router-vite-plugin` | 1.166.53 | 1.166.50 | [MAL-2026-3480](https://osv.dev/vulnerability/MAL-2026-3480) | BLOCK (19) | low |
| `@tanstack/solid-router` | 1.169.5 | 1.169.2 | [MAL-2026-3481](https://osv.dev/vulnerability/MAL-2026-3481) | BLOCK (19) | low |
| `@tanstack/solid-router` | 1.169.8 | 1.169.2 | [MAL-2026-3481](https://osv.dev/vulnerability/MAL-2026-3481) | BLOCK (19) | low |
| `@tanstack/solid-router-devtools` | 1.166.16 | 1.166.13 | [MAL-2026-3482](https://osv.dev/vulnerability/MAL-2026-3482) | BLOCK (19) | low |
| `@tanstack/solid-router-ssr-query` | 1.166.15 | 1.166.12 | [MAL-2026-3483](https://osv.dev/vulnerability/MAL-2026-3483) | BLOCK (19) | low |
| `@tanstack/solid-start` | 1.167.65 | 1.167.62 | [MAL-2026-3484](https://osv.dev/vulnerability/MAL-2026-3484) | BLOCK (19) | low |
| `@tanstack/solid-start` | 1.167.68 | 1.167.62 | [MAL-2026-3484](https://osv.dev/vulnerability/MAL-2026-3484) | BLOCK (19) | low |
| `@tanstack/solid-start-client` | 1.166.50 | 1.166.47 | [MAL-2026-3485](https://osv.dev/vulnerability/MAL-2026-3485) | BLOCK (19) | low |
| `@tanstack/solid-start-server` | 1.166.54 | 1.166.51 | [MAL-2026-3486](https://osv.dev/vulnerability/MAL-2026-3486) | BLOCK (19) | low |
| `@tanstack/start-client-core` | 1.168.5 | 1.168.2 | [MAL-2026-3487](https://osv.dev/vulnerability/MAL-2026-3487) | BLOCK (19) | low |
| `@tanstack/start-client-core` | 1.168.8 | 1.168.2 | [MAL-2026-3487](https://osv.dev/vulnerability/MAL-2026-3487) | BLOCK (19) | low |
| `@tanstack/start-fn-stubs` | 1.161.9 | 1.161.6 | [MAL-2026-3488](https://osv.dev/vulnerability/MAL-2026-3488) | BLOCK (19) | low |
| `@tanstack/start-plugin-core` | 1.169.23 | 1.169.20 | [MAL-2026-3489](https://osv.dev/vulnerability/MAL-2026-3489) | BLOCK (19) | low |
| `@tanstack/start-plugin-core` | 1.169.26 | 1.169.20 | [MAL-2026-3489](https://osv.dev/vulnerability/MAL-2026-3489) | BLOCK (19) | low |
| `@tanstack/start-server-core` | 1.167.33 | 1.167.30 | [MAL-2026-3490](https://osv.dev/vulnerability/MAL-2026-3490) | BLOCK (19) | low |
| `@tanstack/start-server-core` | 1.167.36 | 1.167.30 | [MAL-2026-3490](https://osv.dev/vulnerability/MAL-2026-3490) | BLOCK (19) | low |
| `@tanstack/start-static-server-functions` | 1.166.44 | 1.166.41 | [MAL-2026-3491](https://osv.dev/vulnerability/MAL-2026-3491) | BLOCK (19) | low |
| `@tanstack/start-storage-context` | 1.166.38 | 1.166.35 | [MAL-2026-3492](https://osv.dev/vulnerability/MAL-2026-3492) | BLOCK (19) | low |
| `@tanstack/virtual-file-routes` | 1.161.10 | 1.161.7 | [MAL-2026-3494](https://osv.dev/vulnerability/MAL-2026-3494) | BLOCK (19) | low |
| `@tanstack/vue-router` | 1.169.5 | 1.169.2 | [MAL-2026-3495](https://osv.dev/vulnerability/MAL-2026-3495) | BLOCK (19) | low |
| `@tanstack/vue-router` | 1.169.8 | 1.169.2 | [MAL-2026-3495](https://osv.dev/vulnerability/MAL-2026-3495) | BLOCK (19) | low |
| `@tanstack/vue-router-devtools` | 1.166.16 | 1.166.13 | [MAL-2026-3496](https://osv.dev/vulnerability/MAL-2026-3496) | BLOCK (19) | low |
| `@tanstack/vue-router-ssr-query` | 1.166.15 | 1.166.12 | [MAL-2026-3497](https://osv.dev/vulnerability/MAL-2026-3497) | BLOCK (19) | low |
| `@tanstack/vue-start` | 1.167.61 | 1.167.58 | [MAL-2026-3498](https://osv.dev/vulnerability/MAL-2026-3498) | BLOCK (19) | low |
| `@tanstack/vue-start` | 1.167.64 | 1.167.58 | [MAL-2026-3498](https://osv.dev/vulnerability/MAL-2026-3498) | BLOCK (19) | low |
| `@tanstack/vue-start-client` | 1.166.46 | 1.166.43 | [MAL-2026-3499](https://osv.dev/vulnerability/MAL-2026-3499) | BLOCK (19) | low |
| `@tanstack/vue-start-server` | 1.166.50 | 1.166.47 | [MAL-2026-3500](https://osv.dev/vulnerability/MAL-2026-3500) | BLOCK (19) | low |
| `@tanstack/zod-adapter` | 1.166.12 | 1.166.9 | [MAL-2026-3501](https://osv.dev/vulnerability/MAL-2026-3501) | BLOCK (19) | low |
| `@taskflow-corp/cli` | 0.1.24 | 0.1.23 | [MAL-2026-3520](https://osv.dev/vulnerability/MAL-2026-3520) | BLOCK (19) | suspicious |
| `@taskflow-corp/cli` | 0.1.26 | 0.1.23 | [MAL-2026-3520](https://osv.dev/vulnerability/MAL-2026-3520) | BLOCK (19) | suspicious |
| `@taskflow-corp/cli` | 0.1.28 | 0.1.23 | [MAL-2026-3520](https://osv.dev/vulnerability/MAL-2026-3520) | BLOCK (16) | suspicious |
| `@tolka/cli` | 1.0.2 | 1.0.1 | [MAL-2026-3521](https://osv.dev/vulnerability/MAL-2026-3521) | BLOCK (21) | high_risk |
| `@tolka/cli` | 1.0.4 | 1.0.1 | [MAL-2026-3521](https://osv.dev/vulnerability/MAL-2026-3521) | BLOCK (18) | high_risk |
| `@uipath/access-policy-sdk` | 0.3.1 | 0.3.0 | [MAL-2026-3522](https://osv.dev/vulnerability/MAL-2026-3522) | BLOCK (21) | high_risk |
| `@uipath/agent-sdk` | 1.0.2 | 1.0.1 | [MAL-2026-3525](https://osv.dev/vulnerability/MAL-2026-3525) | BLOCK (21) | high_risk |
| `@uipath/agent-tool` | 1.0.1 | 1.0.0 | [MAL-2026-3526](https://osv.dev/vulnerability/MAL-2026-3526) | BLOCK (21) | high_risk |
| `@uipath/ap-chat` | 1.5.7 | 1.5.6 | [MAL-2026-3529](https://osv.dev/vulnerability/MAL-2026-3529) | BLOCK (23) | high_risk |
| `@uipath/apollo-core` | 5.9.2 | 5.9.1 | [MAL-2026-3531](https://osv.dev/vulnerability/MAL-2026-3531) | BLOCK (23) | high_risk |
| `@uipath/apollo-react` | 4.24.5 | 4.24.4 | [MAL-2026-3532](https://osv.dev/vulnerability/MAL-2026-3532) | BLOCK (23) | high_risk |
| `@uipath/apollo-wind` | 2.16.2 | 2.16.1 | [MAL-2026-3533](https://osv.dev/vulnerability/MAL-2026-3533) | BLOCK (23) | high_risk |
| `@uipath/case-tool` | 1.0.1 | 1.0.0 | [MAL-2026-3535](https://osv.dev/vulnerability/MAL-2026-3535) | BLOCK (21) | high_risk |
| `@uipath/data-fabric-tool` | 1.0.2 | 1.0.1 | [MAL-2026-3542](https://osv.dev/vulnerability/MAL-2026-3542) | BLOCK (21) | high_risk |
| `@uipath/flow-tool` | 1.0.2 | 1.0.1 | [MAL-2026-3545](https://osv.dev/vulnerability/MAL-2026-3545) | BLOCK (21) | high_risk |
| `@uipath/integrationservice-tool` | 1.0.2 | 1.0.1 | [MAL-2026-3552](https://osv.dev/vulnerability/MAL-2026-3552) | BLOCK (21) | high_risk |
| `@uipath/maestro-sdk` | 1.0.1 | 1.0.0 | [MAL-2026-3554](https://osv.dev/vulnerability/MAL-2026-3554) | BLOCK (21) | high_risk |
| `@uipath/maestro-tool` | 1.0.1 | 1.0.0 | [MAL-2026-3555](https://osv.dev/vulnerability/MAL-2026-3555) | BLOCK (21) | high_risk |
| `@uipath/packager-tool-workflowcompiler` | 0.0.16 | 0.0.15 | [MAL-2026-3564](https://osv.dev/vulnerability/MAL-2026-3564) | BLOCK (21) | high_risk |
| `@uipath/project-packager` | 1.1.16 | 1.1.15 | [MAL-2026-3567](https://osv.dev/vulnerability/MAL-2026-3567) | BLOCK (21) | high_risk |
| `@uipath/robot` | 1.3.4 | 1.3.3 | [MAL-2026-3571](https://osv.dev/vulnerability/MAL-2026-3571) | BLOCK (23) | high_risk |
| `@uipath/rpa-tool` | 0.9.5 | 0.9.4 | [MAL-2026-3573](https://osv.dev/vulnerability/MAL-2026-3573) | BLOCK (21) | high_risk |
| `@uipath/solution-tool` | 1.0.1 | 1.0.0 | [MAL-2026-3575](https://osv.dev/vulnerability/MAL-2026-3575) | BLOCK (21) | high_risk |
| `@uipath/solutionpackager-sdk` | 1.0.11 | 1.0.10 | [MAL-2026-3576](https://osv.dev/vulnerability/MAL-2026-3576) | BLOCK (21) | high_risk |
| `@uipath/vss` | 0.1.6 | 0.1.5 | [MAL-2026-3586](https://osv.dev/vulnerability/MAL-2026-3586) | BLOCK (21) | high_risk |
| `@uipath/widget.sdk` | 1.2.3 | 1.2.2 | [MAL-2026-3587](https://osv.dev/vulnerability/MAL-2026-3587) | BLOCK (23) | high_risk |
| `cmux-agent-mcp` | 0.1.3 | 0.1.2 | [MAL-2026-3588](https://osv.dev/vulnerability/MAL-2026-3588) | BLOCK (19) | high_risk |
| `cmux-agent-mcp` | 0.1.5 | 0.1.2 | [MAL-2026-3588](https://osv.dev/vulnerability/MAL-2026-3588) | BLOCK (19) | high_risk |
| `cmux-agent-mcp` | 0.1.7 | 0.1.2 | [MAL-2026-3588](https://osv.dev/vulnerability/MAL-2026-3588) | BLOCK (16) | high_risk |
| `cross-stitch` | 1.1.3 | 1.1.2 | [MAL-2026-3502](https://osv.dev/vulnerability/MAL-2026-3502) | BLOCK (22) | high_risk |
| `echarts-for-react` | 3.0.7 | 3.0.6 | [MAL-2026-4132](https://osv.dev/vulnerability/MAL-2026-4132) | BLOCK (3) | no_risks_detected |
| `git-branch-selector` | 1.3.3 | 1.3.2 | [MAL-2026-3503](https://osv.dev/vulnerability/MAL-2026-3503) | BLOCK (21) | high_risk |
| `git-branch-selector` | 1.3.5 | 1.3.2 | [MAL-2026-3503](https://osv.dev/vulnerability/MAL-2026-3503) | BLOCK (18) | high_risk |
| `git-git-git` | 1.0.10 | 1.0.7 | [MAL-2026-3504](https://osv.dev/vulnerability/MAL-2026-3504) | BLOCK (19) | high_risk |
| `git-git-git` | 1.0.8 | 1.0.7 | [MAL-2026-3504](https://osv.dev/vulnerability/MAL-2026-3504) | BLOCK (22) | high_risk |
| `jest-canvas-mock` | 2.5.3 | 2.5.2 | [MAL-2026-4136](https://osv.dev/vulnerability/MAL-2026-4136) | BLOCK (3) | no_risks_detected |
| `jest-date-mock` | 1.0.11 | 1.0.10 | [MAL-2026-4137](https://osv.dev/vulnerability/MAL-2026-4137) | BLOCK (3) | no_risks_detected |
| `nextmove-mcp` | 0.1.3 | 0.1.2 | [MAL-2026-3589](https://osv.dev/vulnerability/MAL-2026-3589) | BLOCK (13) | high_risk |
| `nextmove-mcp` | 0.1.5 | 0.1.2 | [MAL-2026-3589](https://osv.dev/vulnerability/MAL-2026-3589) | BLOCK (13) | high_risk |
| `safe-action` | 0.8.4 | 0.8.2 | [MAL-2026-3590](https://osv.dev/vulnerability/MAL-2026-3590) | BLOCK (22) | high_risk |
| `size-sensor` | 1.0.4 | 1.0.3 | [MAL-2026-4153](https://osv.dev/vulnerability/MAL-2026-4153) | BLOCK (3) | no_risks_detected |

</details>
<!-- numbers:end -->

## The git-dependency trick

Seven releases changed nothing in the tarball except `package.json`, where a new git dependency appeared:

| Release | New dependency |
|---|---|
| `@opensearch-project/opensearch` 3.5.3, 3.7.0, 3.8.0 | `@opensearch/setup` from `github:opensearch-project/opensearch-js#d446803…` |
| `echarts-for-react` 3.0.7, `jest-canvas-mock` 2.5.3, `jest-date-mock` 1.0.11, `size-sensor` 1.0.4 | `@antv/setup` from `github:antvis/G2#1916faa…` |

A single-version scanner sees a normal library with one extra dependency. v1 had no rule for it and passed all seven. That miss is why v2 has the `non-registry-dependency` rule, which fires when a new dependency installs from git or a URL. It fired on none of the 6,707 normal updates in the benign set. It later caught five more git-dependency injections in the post-June holdout that no rule had been tuned on (`@velliajs/discord` ×3, `@polymarkets/clob-client-v2`, `@devmikets/hyperliquid-sdk`).

GuardDog's own verdict (`high_risk`) catches 143 of the 214. On the seven git-dependency-only releases its verdict is `low` (three OpenSearch versions, one `threat-runtime-system-info` hit) or no risk at all.

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` checks every locked version against its previous release and asks [OSV](https://osv.dev) whether it is known malware, so versions npm has since deleted still fail. Check the full list of versions below. If one was installed, the preinstall hook or the git dependency's `prepare` script ran on that machine: rotate the npm, GitHub and cloud credentials it could reach, and look for new files in `.vscode/` and `.claude/` in your projects.

Related: [Shai-Hulud](shai-hulud.md) and [Shai-Hulud 2.0](shai-hulud-2.md), the 2025 worms this one is named after; [ChainDrop](chaindrop-keyv.md). All incidents: [index](README.md).
