# Miasma: npm malware hidden in binding.gyp (June 2026, @vapi-ai/server-sdk, leo-logger and 26 more packages): detection results and how to check your lockfile

On 3 and 4 June 2026 27 packages, among them `@vapi-ai/server-sdk` ([MAL-2026-5209](https://osv.dev/vulnerability/MAL-2026-5209)) and several `autotel-*` and `awaitly-*` packages, got 43 malicious releases with **no install script at all**. On 25 June `leo-logger` 1.0.8 ([MAL-2026-6429](https://osv.dev/vulnerability/MAL-2026-6429)) did the same. pkgdelta blocks all 44 with rules frozen before 2026. GuardDog's own verdict flags 36.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

If a package contains a `binding.gyp` file and no `install` script, npm assumes it has a native addon and runs `node-gyp rebuild` at install time on its own. `node-gyp` reads `binding.gyp` through GYP, and GYP expands `<!(command)` by running the command. So this file:

```
{ "targets": [ { "target_name": "nothing", "type": "none",
    "sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"] } ] }
```

runs `index.js` during `npm install`, while `package.json` shows no `preinstall`, `install` or `postinstall`. A tool or policy that looks for install scripts in `package.json` sees nothing. (`npm install --ignore-scripts` does stop it, because npm skips the implicit `node-gyp rebuild` too.)

In 38 of the 44 releases, `index.js` starts with the same `eval` letter-rotation loader (`try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,…`) as all 16 [Red Hat](redhat-cloud-services.md) releases two days earlier.

## What changed compared with the previous release

pkgdelta's findings for `leo-logger` 1.0.7 → 1.0.8 (from `results/v2_test.jsonl`):

```
BLOCK leo-logger 1.0.7 -> 1.0.8  (score 6)
        HIGH implicit-install: binding.gyp added: npm will run node-gyp at install time [binding.gyp]
             { "targets": [ { "target_name": "nothing", "type": "none", "sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"] } ] }
      MEDIUM injected-growth: index.js grew from 4973 to 5188291 bytes in a patch release [index.js]
         LOW new-capability:dynamic_code: code starts using dynamic code (previous version never did) [index.js]
```

The `implicit-install` rule fires when `binding.gyp` appears in a package whose previous release had none. It fired on all 44 releases and on none of the 6,707 normal updates in the benign set. Packages that really ship a native addon have had `binding.gyp` for many releases, so for them it is not new.

## Detection results

These releases are in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 44 | 44 / 44 (100%) | 44 / 44 (100%) | 36 / 44 (82%) | 44 / 44 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `implicit-install` (high): 44
- `injected-growth` (medium): 1

<details><summary>All 44 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@vapi-ai/server-sdk` | 0.11.2 | 0.11.0 | [MAL-2026-5209](https://osv.dev/vulnerability/MAL-2026-5209) | BLOCK (3) | high_risk |
| `@vapi-ai/server-sdk` | 1.2.1 | 1.2.0 | [MAL-2026-5209](https://osv.dev/vulnerability/MAL-2026-5209) | BLOCK (3) | high_risk |
| `@vapi-ai/server-sdk` | 1.2.2 | 1.2.0 | [MAL-2026-5209](https://osv.dev/vulnerability/MAL-2026-5209) | BLOCK (3) | high_risk |
| `autotel` | 2.26.4 | 2.26.3 | [MAL-2026-5211](https://osv.dev/vulnerability/MAL-2026-5211) | BLOCK (4) | high_risk |
| `autotel-devtools` | 3.0.2 | 3.0.1 | [MAL-2026-5218](https://osv.dev/vulnerability/MAL-2026-5218) | BLOCK (4) | high_risk |
| `autotel-eventcatalog` | 3.0.1 | 3.0.0 | [MAL-2026-5221](https://osv.dev/vulnerability/MAL-2026-5221) | BLOCK (4) | high_risk |
| `autotel-mcp` | 20.0.1 | 20.0.0 | [MAL-2026-5223](https://osv.dev/vulnerability/MAL-2026-5223) | BLOCK (4) | high_risk |
| `autotel-mcp` | 4.0.1 | 4.0.0 | [MAL-2026-5223](https://osv.dev/vulnerability/MAL-2026-5223) | BLOCK (4) | high_risk |
| `autotel-mcp-instrumentation` | 32.0.1 | 32.0.0 | [MAL-2026-5224](https://osv.dev/vulnerability/MAL-2026-5224) | BLOCK (4) | high_risk |
| `autotel-mongoose` | 6.0.1 | 6.0.0 | [MAL-2026-5225](https://osv.dev/vulnerability/MAL-2026-5225) | BLOCK (4) | high_risk |
| `autotel-pact` | 1.0.3 | 1.0.2 | [MAL-2026-5226](https://osv.dev/vulnerability/MAL-2026-5226) | BLOCK (4) | suspicious |
| `autotel-subscribers` | 17.0.1 | 17.0.0 | [MAL-2026-5230](https://osv.dev/vulnerability/MAL-2026-5230) | BLOCK (4) | suspicious |
| `autotel-subscribers` | 31.1.4 | 31.1.3 | [MAL-2026-5230](https://osv.dev/vulnerability/MAL-2026-5230) | BLOCK (4) | suspicious |
| `autotel-subscribers` | 4.1.1 | 4.1.0 | [MAL-2026-5230](https://osv.dev/vulnerability/MAL-2026-5230) | BLOCK (4) | suspicious |
| `autotel-terminal` | 22.0.2 | 22.0.1 | [MAL-2026-5186](https://osv.dev/vulnerability/MAL-2026-5186) | BLOCK (4) | suspicious |
| `autotel-terminal` | 23.0.3 | 23.0.2 | [MAL-2026-5186](https://osv.dev/vulnerability/MAL-2026-5186) | BLOCK (4) | suspicious |
| `autotel-terminal` | 8.0.1 | 8.0.0 | [MAL-2026-5186](https://osv.dev/vulnerability/MAL-2026-5186) | BLOCK (4) | high_risk |
| `awaitly` | 1.33.3 | 1.33.2 | [MAL-2026-5234](https://osv.dev/vulnerability/MAL-2026-5234) | BLOCK (4) | high_risk |
| `awaitly-analyze` | 1.1.1 | 1.1.0 | [MAL-2026-5235](https://osv.dev/vulnerability/MAL-2026-5235) | BLOCK (4) | high_risk |
| `awaitly-analyze` | 8.0.1 | 8.0.0 | [MAL-2026-5235](https://osv.dev/vulnerability/MAL-2026-5235) | BLOCK (4) | high_risk |
| `awaitly-libsql` | 1.0.1 | 1.0.0 | [MAL-2026-5236](https://osv.dev/vulnerability/MAL-2026-5236) | BLOCK (4) | high_risk |
| `awaitly-libsql` | 12.0.1 | 12.0.0 | [MAL-2026-5236](https://osv.dev/vulnerability/MAL-2026-5236) | BLOCK (4) | high_risk |
| `awaitly-libsql` | 22.0.1 | 22.0.0 | [MAL-2026-5236](https://osv.dev/vulnerability/MAL-2026-5236) | BLOCK (4) | high_risk |
| `awaitly-mongo` | 0.1.1 | 0.1.0 | [MAL-2026-5237](https://osv.dev/vulnerability/MAL-2026-5237) | BLOCK (4) | high_risk |
| `awaitly-mongo` | 12.0.1 | 12.0.0 | [MAL-2026-5237](https://osv.dev/vulnerability/MAL-2026-5237) | BLOCK (4) | high_risk |
| `awaitly-mongo` | 23.0.1 | 23.0.0 | [MAL-2026-5237](https://osv.dev/vulnerability/MAL-2026-5237) | BLOCK (4) | high_risk |
| `awaitly-postgres` | 1.0.1 | 1.0.0 | [MAL-2026-5238](https://osv.dev/vulnerability/MAL-2026-5238) | BLOCK (4) | high_risk |
| `awaitly-postgres` | 13.0.1 | 13.0.0 | [MAL-2026-5238](https://osv.dev/vulnerability/MAL-2026-5238) | BLOCK (4) | high_risk |
| `awaitly-postgres` | 23.0.1 | 23.0.0 | [MAL-2026-5238](https://osv.dev/vulnerability/MAL-2026-5238) | BLOCK (4) | high_risk |
| `awaitly-visualizer` | 13.0.1 | 13.0.0 | [MAL-2026-5239](https://osv.dev/vulnerability/MAL-2026-5239) | BLOCK (3) | high_risk |
| `awaitly-visualizer` | 2.0.2 | 2.0.1 | [MAL-2026-5239](https://osv.dev/vulnerability/MAL-2026-5239) | BLOCK (3) | high_risk |
| `awaitly-visualizer` | 22.0.2 | 22.0.1 | [MAL-2026-5239](https://osv.dev/vulnerability/MAL-2026-5239) | BLOCK (3) | high_risk |
| `effect-analyzer` | 0.3.1 | 0.3.0 | [MAL-2026-5245](https://osv.dev/vulnerability/MAL-2026-5245) | BLOCK (4) | suspicious |
| `eslint-plugin-awaitly` | 1.0.1 | 1.0.0 | [MAL-2026-5246](https://osv.dev/vulnerability/MAL-2026-5246) | BLOCK (4) | high_risk |
| `eslint-plugin-executable-stories-jest` | 2.1.8 | 2.1.7 | [MAL-2026-5247](https://osv.dev/vulnerability/MAL-2026-5247) | BLOCK (4) | high_risk |
| `eslint-plugin-executable-stories-playwright` | 2.1.8 | 2.1.7 | [MAL-2026-5248](https://osv.dev/vulnerability/MAL-2026-5248) | BLOCK (4) | high_risk |
| `eslint-plugin-executable-stories-vitest` | 2.1.8 | 2.1.7 | [MAL-2026-5249](https://osv.dev/vulnerability/MAL-2026-5249) | BLOCK (4) | high_risk |
| `executable-stories-cypress` | 6.1.1 | 6.1.0 | [MAL-2026-5250](https://osv.dev/vulnerability/MAL-2026-5250) | BLOCK (4) | high_risk |
| `executable-stories-jest` | 6.1.1 | 6.1.0 | [MAL-2026-5254](https://osv.dev/vulnerability/MAL-2026-5254) | BLOCK (4) | high_risk |
| `executable-stories-playwright` | 7.0.3 | 7.0.2 | [MAL-2026-5256](https://osv.dev/vulnerability/MAL-2026-5256) | BLOCK (4) | high_risk |
| `executable-stories-vitest` | 7.0.3 | 7.0.2 | [MAL-2026-5258](https://osv.dev/vulnerability/MAL-2026-5258) | BLOCK (4) | high_risk |
| `leo-logger` | 1.0.8 | 1.0.7 | [MAL-2026-6429](https://osv.dev/vulnerability/MAL-2026-6429) | BLOCK (6) | high_risk |
| `node-env-resolver` | 6.5.1 | 6.5.0 | [MAL-2026-5262](https://osv.dev/vulnerability/MAL-2026-5262) | BLOCK (4) | suspicious |
| `node-env-resolver-aws` | 12.0.1 | 12.0.0 | [MAL-2026-5263](https://osv.dev/vulnerability/MAL-2026-5263) | BLOCK (4) | high_risk |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` asks [OSV](https://osv.dev) about every locked version, so versions npm removed still fail. Searching your lockfile for install scripts will not find these. If one was installed without `--ignore-scripts`, the code ran: rotate the credentials that machine or CI job could read.

All incidents: [index](README.md).
