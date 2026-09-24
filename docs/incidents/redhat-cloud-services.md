# @redhat-cloud-services npm compromise (June 2026): detection results and how to check your lockfile

On 1 June 2026 16 packages under `@redhat-cloud-services` got malicious patch releases, starting with `@redhat-cloud-services/chrome` 2.3.1 ([MAL-2026-5111](https://osv.dev/vulnerability/MAL-2026-5111)). They carry valid build provenance: a provenance or signature check passes them. pkgdelta blocks all 16 with rules frozen before 2026. GuardDog flags all 15 it could scan.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

Each release added `"preinstall": "node index.js"` and an `index.js` that starts with an `eval` of a letter-rotation decoder. In `@redhat-cloud-services/chrome` that file went from 1 KB to 4 MB. 38 of the 44 [Miasma](node-gyp-miasma.md) releases two days later start with the same loader, but run it through `binding.gyp` instead of an install script.

## What changed compared with the previous release

pkgdelta's findings for `@redhat-cloud-services/chrome` 2.3.0 → 2.3.1 (from `results/v2_test.jsonl`):

```
BLOCK @redhat-cloud-services/chrome 2.3.0 -> 2.3.1  (score 6)
        HIGH install-hook: preinstall script added: node index.js [package.json]
      MEDIUM injected-growth: index.js grew from 1054 to 4056544 bytes in a patch release [index.js]
         LOW new-capability:dynamic_code: code starts using dynamic code (previous version never did) [index.js]
             try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<="…
```

pkgdelta doesn't decode the payload. It doesn't need to: a 1 KB file growing to 4 MB in a patch release, run by a brand-new preinstall hook, is enough. The build provenance is real, and pkgdelta does not treat it as a reason to trust the content.

## Detection results

These releases are in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 16 | 16 / 16 (100%) | 16 / 16 (100%) | 15 / 15 (100%) | 15 / 15 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 16
- `injected-growth` (medium): 11

<details><summary>All 16 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@redhat-cloud-services/chrome` | 2.3.1 | 2.3.0 | [MAL-2026-5111](https://osv.dev/vulnerability/MAL-2026-5111) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/config-manager-client` | 5.0.4 | 5.0.3 | [MAL-2026-5134](https://osv.dev/vulnerability/MAL-2026-5134) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/entitlements-client` | 4.0.11 | 4.0.10 | [MAL-2026-5125](https://osv.dev/vulnerability/MAL-2026-5125) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/eslint-config-redhat-cloud-services` | 3.2.1 | 3.2.0 | [MAL-2026-5112](https://osv.dev/vulnerability/MAL-2026-5112) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/frontend-components-config` | 6.11.3 | 6.11.2 | [MAL-2026-5126](https://osv.dev/vulnerability/MAL-2026-5126) | BLOCK (4) | high_risk |
| `@redhat-cloud-services/frontend-components-config-utilities` | 4.11.2 | 4.11.1 | [MAL-2026-5114](https://osv.dev/vulnerability/MAL-2026-5114) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/frontend-components-remediations` | 4.9.2 | 4.9.1 | [MAL-2026-5127](https://osv.dev/vulnerability/MAL-2026-5127) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/frontend-components-testing` | 1.2.1 | 1.2.0 | [MAL-2026-5128](https://osv.dev/vulnerability/MAL-2026-5128) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/hcc-feo-mcp` | 0.3.1 | 0.3.0 | [MAL-2026-5129](https://osv.dev/vulnerability/MAL-2026-5129) | BLOCK (4) | not scanned |
| `@redhat-cloud-services/hcc-kessel-mcp` | 0.3.1 | 0.3.0 | [MAL-2026-5139](https://osv.dev/vulnerability/MAL-2026-5139) | BLOCK (4) | high_risk |
| `@redhat-cloud-services/hcc-pf-mcp` | 0.6.1 | 0.6.0 | [MAL-2026-5140](https://osv.dev/vulnerability/MAL-2026-5140) | BLOCK (4) | high_risk |
| `@redhat-cloud-services/integrations-client` | 6.0.4 | 6.0.3 | [MAL-2026-5130](https://osv.dev/vulnerability/MAL-2026-5130) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/javascript-clients-shared` | 2.0.8 | 2.0.7 | [MAL-2026-5143](https://osv.dev/vulnerability/MAL-2026-5143) | BLOCK (4) | high_risk |
| `@redhat-cloud-services/quickstarts-client` | 4.0.11 | 4.0.10 | [MAL-2026-5115](https://osv.dev/vulnerability/MAL-2026-5115) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/tsc-transform-imports` | 1.2.2 | 1.2.1 | [MAL-2026-5147](https://osv.dev/vulnerability/MAL-2026-5147) | BLOCK (6) | high_risk |
| `@redhat-cloud-services/types` | 3.6.1 | 3.6.0 | [MAL-2026-5119](https://osv.dev/vulnerability/MAL-2026-5119) | BLOCK (6) | high_risk |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` asks [OSV](https://osv.dev) about every locked version, so versions npm removed still fail. If one was installed, the preinstall hook ran: rotate the credentials that machine or CI job could read.

All incidents: [index](README.md).
