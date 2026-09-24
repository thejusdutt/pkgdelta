# axios 1.14.1 and plain-crypto-js (March 2026): detection results and how to check your lockfile

On 31 March 2026 `axios` 1.14.1 was published with one change that mattered: a new dependency, `plain-crypto-js`, which is where the malware lived. axios 1.14.1 is [MAL-2026-2307](https://osv.dev/vulnerability/MAL-2026-2307); `plain-crypto-js` is [MAL-2026-2306](https://osv.dev/vulnerability/MAL-2026-2306).

pkgdelta blocks axios 1.14.1 with rules frozen before 2026. GuardDog finds nothing. But be clear about how: pkgdelta blocked it on two metadata signals and never saw the malicious code. The margin is thin.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What changed compared with the previous release

axios's own code in 1.14.1 is clean. pkgdelta's findings for `axios` 1.14.0 → 1.14.1 (from `results/v2_test.jsonl`):

```
BLOCK axios 1.14.0 -> 1.14.1  (score 4)
      MEDIUM provenance-dropped: previous version had build provenance, this one does not
      MEDIUM fresh-dependency: new dependency plain-crypto-js was first published 0.8 days before this release
             by unknown, who does not maintain this package [package.json]
```

Two medium findings add up to 4, over the blocking line of 3. Either one alone would not block:

- `provenance-dropped` fires on 5 of 6,707 normal updates in the benign set.
- `fresh-dependency` fires on 3 of 6,707 (for example `fast-levenshtein` 3.0.0 switching to `fastest-levenshtein`).

The two together fired on none of them. Had the attacker published through axios's real CI and kept provenance, axios 1.14.1 would have scored 2 and passed. That is the same shape as the eight [Mastra](mastra-easy-day-js.md) releases that got through.

`plain-crypto-js` itself is not in the DataDog set, and npm has removed the malicious version, so there is no tarball left to scan.

## Detection results

axios is in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 1 | 1 / 1 (100%) | 1 / 1 (100%) | 0 / 1 (0%) | 0 / 1 (0%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `provenance-dropped` (medium): 1
- `fresh-dependency` (medium): 1

<details><summary>The release (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `axios` | 1.14.1 | 1.14.0 | [MAL-2026-2307](https://osv.dev/vulnerability/MAL-2026-2307) | BLOCK (4) | no_risks_detected |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` asks [OSV](https://osv.dev) about every locked version, including transitive ones, so a lockfile that pins `axios@1.14.1` or `plain-crypto-js@4.2.1` fails even though npm deleted them. If either was installed, treat the machine as compromised and rotate the credentials it could read.

All incidents: [index](README.md).
