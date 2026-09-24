# chalk and debug npm compromise (September 2025): detection results and how to check your lockfile

On 8 September 2025 a phished maintainer account published malicious releases of `chalk` 5.6.1, `debug` 4.4.2, `ansi-styles`, `ansi-regex`, `color-convert`, `wrap-ansi`, `supports-color` and more: some of the most downloaded packages on npm. `@duckdb/*` and `duckdb` were hit the next day through the same phishing domain. The DataDog dataset has 18 of these releases with a clean earlier version. pkgdelta blocks all 18. GuardDog does too.

This is training data: pkgdelta's rules were written while looking at it.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

The maintainer got an email from `npmjs.help`, a look-alike of npm's domain, asking them to "update 2FA". The attacker used the captured login to publish new patch versions. The payload is a browser crypto-wallet hijacker: when the package runs in a web page it wraps `fetch`, `XMLHttpRequest` and `window.ethereum`, and swaps crypto addresses in transactions for the attacker's. There is no install script. Nothing happens at `npm install`; the code runs when your bundled app loads in a browser.

## What changed compared with the previous release

The payload is appended to the package's main file, obfuscated. pkgdelta's findings for `debug` 4.4.1 → 4.4.2 (from `results/v2_train.jsonl`):

```
BLOCK debug 4.4.1 -> 4.4.2  (score 5)
        HIGH obfuscation: obfuscated code appears (previous version had none) [src/index.js]
             const _0x112fa8=_0x180f;(function(_0x13c8b9,_0x35f660){…
      MEDIUM injected-growth: src/index.js grew from 314 to 76754 bytes in a patch release [src/index.js]
```

A 314-byte file becoming 76 KB in a patch release, with `_0x` names that the package has never used, is not a normal update. No install-hook rule is needed.

## Detection results

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 18 | 18 / 18 (100%) | 18 / 18 (100%) | 18 / 18 (100%) | 18 / 18 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `obfuscation` (high): 18
- `injected-growth` (medium): 16
- `new-binary` (medium): 1

<details><summary>All 18 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@coveops/abi` | 2.0.1 | 2.0.0 | [MAL-2025-47025](https://osv.dev/vulnerability/MAL-2025-47025) | BLOCK (6) | high_risk |
| `@duckdb/duckdb-wasm` | 1.29.2 | 1.29.0 | [MAL-2025-46991](https://osv.dev/vulnerability/MAL-2025-46991) | BLOCK (4) | high_risk |
| `@duckdb/node-api` | 1.3.3 | 1.3.2-alpha.26 | [MAL-2025-46992](https://osv.dev/vulnerability/MAL-2025-46992) | BLOCK (5) | high_risk |
| `ansi-regex` | 6.2.1 | 6.2.0 | [MAL-2025-46966](https://osv.dev/vulnerability/MAL-2025-46966) | BLOCK (5) | high_risk |
| `ansi-styles` | 6.2.2 | 6.2.1 | [MAL-2025-46967](https://osv.dev/vulnerability/MAL-2025-46967) | BLOCK (5) | high_risk |
| `backslash` | 0.2.1 | 0.2.0 | [MAL-2025-46968](https://osv.dev/vulnerability/MAL-2025-46968) | BLOCK (5) | high_risk |
| `chalk-template` | 1.1.1 | 1.1.0 | [MAL-2025-46970](https://osv.dev/vulnerability/MAL-2025-46970) | BLOCK (5) | high_risk |
| `color-convert` | 3.1.1 | 3.1.0 | [MAL-2025-46971](https://osv.dev/vulnerability/MAL-2025-46971) | BLOCK (5) | high_risk |
| `color-name` | 2.0.1 | 2.0.0 | [MAL-2025-46972](https://osv.dev/vulnerability/MAL-2025-46972) | BLOCK (6) | high_risk |
| `debug` | 4.4.2 | 4.4.1 | [MAL-2025-46974](https://osv.dev/vulnerability/MAL-2025-46974) | BLOCK (5) | high_risk |
| `duckdb` | 1.3.3 | 1.3.2 | [MAL-2025-46994](https://osv.dev/vulnerability/MAL-2025-46994) | BLOCK (5) | high_risk |
| `error-ex` | 1.3.3 | 1.3.2 | [MAL-2025-46975](https://osv.dev/vulnerability/MAL-2025-46975) | BLOCK (5) | high_risk |
| `has-ansi` | 6.0.1 | 6.0.0 | [MAL-2025-46976](https://osv.dev/vulnerability/MAL-2025-46976) | BLOCK (6) | high_risk |
| `is-arrayish` | 0.3.3 | 0.3.2 | [MAL-2025-46977](https://osv.dev/vulnerability/MAL-2025-46977) | BLOCK (5) | high_risk |
| `simple-swizzle` | 0.2.3 | 0.2.2 | [MAL-2025-46978](https://osv.dev/vulnerability/MAL-2025-46978) | BLOCK (5) | high_risk |
| `slice-ansi` | 7.1.1 | 7.1.0 | [MAL-2025-46979](https://osv.dev/vulnerability/MAL-2025-46979) | BLOCK (6) | high_risk |
| `supports-hyperlinks` | 4.1.1 | 4.1.0 | [MAL-2025-46982](https://osv.dev/vulnerability/MAL-2025-46982) | BLOCK (6) | high_risk |
| `wrap-ansi` | 9.0.1 | 9.0.0 | [MAL-2025-46983](https://osv.dev/vulnerability/MAL-2025-46983) | BLOCK (6) | high_risk |

</details>
<!-- numbers:end -->

## What about chalk 5.6.1 itself?

`chalk` 5.6.1 is not in the DataDog set (only `chalk-template` 1.1.1 is), and npm has removed it, so there is no tarball left to compare. pkgdelta still fails a lockfile that pins it: `diff` and `audit` ask [OSV](https://osv.dev) about every version, and `chalk@5.6.1` is [MAL-2025-46969](https://osv.dev/vulnerability/MAL-2025-46969). This repo's CI runs the GitHub Action against exactly that lockfile and checks that the build fails.

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

The bad versions were live for about two hours before npm removed them. A lockfile written in that window can still pin them. If a build with one of them shipped to users, the risk is on your users' side: their wallet transactions in that web app. Rebuild with clean versions and redeploy.

All incidents: [index](README.md).
