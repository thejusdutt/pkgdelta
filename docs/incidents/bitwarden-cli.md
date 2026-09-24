# @bitwarden/cli 2026.4.0 npm compromise (April 2026): detection results and how to check your lockfile

On 23 April 2026 a malicious `@bitwarden/cli` 2026.4.0 was published to npm ([MAL-2026-3020](https://osv.dev/vulnerability/MAL-2026-3020)). It is a password manager's command-line tool, so the machines that install it are the ones with the most secrets on them. pkgdelta blocks it with both rule sets, including the v1 rules frozen before 2026. GuardDog flags it too.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

The release added `"preinstall": "node bw_setup.js"`. `bw_setup.js` downloads Bun 1.3.13 from GitHub and runs `bw1.js`, a 10 MB obfuscated file that reads AWS keys from the environment and asks the cloud metadata endpoint (`169.254.169.254`) for more. It is the same Bun-download shape as [Shai-Hulud 2.0](shai-hulud-2.md), and the same payload structure turns up a week later in [SAP cap-js](sap-cap-js.md).

## What changed compared with the previous release

pkgdelta's findings for `@bitwarden/cli` 2026.3.0 → 2026.4.0 (from `results/v2_test.jsonl`):

```
BLOCK @bitwarden/cli 2026.3.0 -> 2026.4.0  (score 14)
        HIGH install-hook: preinstall script added: node bw_setup.js [package.json]
        HIGH new-capability:download_exec: code starts using download exec (previous version never did) [bw_setup.js]
             const BUN_VERSION = "1.3.13"; const downloadUrl = `https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/…
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [bw1.js]
             _0x2356e0['IPv4']='http://169.254.169.254'
        HIGH obfuscation: obfuscated code appears (previous version had none) [bw1.js]
      MEDIUM new-capability:secret_env: code starts using secret env (previous version never did) [bw1.js]
```

v1 had an 8 MB per-file limit and skipped `bw1.js` entirely. It still blocked the release on the first two lines (score 6), which come from the small setup script. v2 raised the limit to 64 MB after this case and reads the payload too.

## Detection results

`@bitwarden/cli` is in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 1 | 1 / 1 (100%) | 1 / 1 (100%) | 1 / 1 (100%) | 1 / 1 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 1
- `new-capability:secret_env` (medium): 1
- `new-capability:token_tools` (high): 1
- `new-capability:download_exec` (high): 1
- `obfuscation` (high): 1

<details><summary>The release (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@bitwarden/cli` | 2026.4.0 | 2026.3.0 | [MAL-2026-3020](https://osv.dev/vulnerability/MAL-2026-3020) | BLOCK (14) | high_risk |

</details>
<!-- numbers:end -->

The DataDog campaign grouping puts `@bitwarden/cli` in one cluster with 16 other releases found 21–23 April (`@automagik/genie`, `pgserve`, `@openwebconcept/*`). Those carry a different payload, a `postinstall` running `check-env.cjs` that hunts for npm tokens. Both rule sets block all 16 as well.

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

If `@bitwarden/cli` is installed globally, check `npm ls -g @bitwarden/cli`; `audit` only reads lockfiles. If 2026.4.0 was ever installed, rotate the cloud keys and tokens in that machine's environment and in any CI job that installed it.

All incidents: [index](README.md).
