# SAP @cap-js npm compromise (April 2026, @cap-js/db-service, @cap-js/postgres, @cap-js/sqlite, mbt): detection results and how to check your lockfile

On 29 April 2026 malicious releases of SAP's Cloud Application Programming packages went out: `@cap-js/db-service` 2.10.1 ([MAL-2026-3176](https://osv.dev/vulnerability/MAL-2026-3176)), `@cap-js/postgres` 2.2.2, `@cap-js/sqlite` 2.2.2, and the SAP build tool `mbt` 1.2.48 ([MAL-2026-3179](https://osv.dev/vulnerability/MAL-2026-3179)). pkgdelta blocks all 4 with rules frozen before 2026. GuardDog's own verdict flags 3 of 4 (it rates `@cap-js/sqlite` as `suspicious`).

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

Each release added `"preinstall": "node setup.mjs"`. `setup.mjs` downloads the Bun runtime from GitHub and runs `execution.js`, an obfuscated payload that:

- reads `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` and queries the cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`, `[fd00:ec2::254]`),
- writes itself into `.vscode/tasks.json` and `.claude/execution.js` inside the project, so it runs again when someone opens the folder in VS Code or starts Claude Code there.

This is the same structure as the [Bitwarden CLI](bitwarden-cli.md) payload a week earlier and the [TanStack](tanstack-mini-shai-hulud.md) payload two weeks later.

## What changed compared with the previous release

pkgdelta's findings for `@cap-js/db-service` 2.10.0 → 2.10.1 (from `results/v2_test.jsonl`, low-severity lines left out):

```
BLOCK @cap-js/db-service 2.10.0 -> 2.10.1  (score 22)
        HIGH install-hook: preinstall script added: node setup.mjs [package.json]
        HIGH new-capability:download_exec: code starts using download exec (previous version never did) [setup.mjs]
             const url = `https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/…
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [execution.js]
             Ip0='169.254.170.2',…,Ap0='[fd00:ec…
        HIGH new-capability:persistence: code starts using persistence (previous version never did) [execution.js]
             var STf={'.vscode/tasks.json':a8f,'.claude/execution.js':{'sourcePath':Bun[…]},…
        HIGH obfuscation: obfuscated code appears (previous version had none) [execution.js]
      MEDIUM new-capability:secret_env, credential_paths
      MEDIUM encoded-blob: large encoded blob added (3318 chars) [execution.js]
```

Five independent high findings. Any one of them blocks.

## Detection results

These releases are in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 4 | 4 / 4 (100%) | 4 / 4 (100%) | 3 / 4 (75%) | 4 / 4 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 4
- `new-capability:secret_env` (medium): 4
- `new-capability:credential_paths` (medium): 4
- `new-capability:token_tools` (high): 4
- `new-capability:persistence` (high): 4
- `new-capability:download_exec` (high): 4
- `obfuscation` (high): 4
- `encoded-blob` (medium): 4

<details><summary>All 4 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@cap-js/db-service` | 2.10.1 | 2.10.0 | [MAL-2026-3176](https://osv.dev/vulnerability/MAL-2026-3176) | BLOCK (22) | high_risk |
| `@cap-js/postgres` | 2.2.2 | 2.2.1 | [MAL-2026-3177](https://osv.dev/vulnerability/MAL-2026-3177) | BLOCK (22) | high_risk |
| `@cap-js/sqlite` | 2.2.2 | 2.2.1 | [MAL-2026-3178](https://osv.dev/vulnerability/MAL-2026-3178) | BLOCK (22) | suspicious |
| `mbt` | 1.2.48 | 1.2.47 | [MAL-2026-3179](https://osv.dev/vulnerability/MAL-2026-3179) | BLOCK (23) | high_risk |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` asks [OSV](https://osv.dev) about every locked version, so versions npm removed still fail. If one was installed:

- delete `.claude/execution.js` and check `.vscode/tasks.json` in every project on that machine (and in any repository where those files may have been committed),
- rotate the cloud keys, npm and GitHub tokens that machine or CI job could read.

All incidents: [index](README.md).
