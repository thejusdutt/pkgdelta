# Mastra npm compromise and easy-day-js (June 2026): detection results and how to check your lockfile

On 17 June 2026 119 packages of the Mastra AI framework (`@mastra/*`, `mastra`, `create-mastra`) got releases that added one new dependency: `easy-day-js`, a copy of `dayjs` published by an unrelated account. The dependency is where the malware was. pkgdelta blocks 111 of the 119 with rules frozen before 2026, and passes 8. GuardDog's own verdict flags 4.

This is the case pkgdelta handles worst of all the 2026 attacks, and the reason is worth knowing before you rely on it.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results) · [The 8 that passed](#the-8-that-passed)

## What happened

`easy-day-js` was published clean on 16 June, then version 1.11.22 the next night with an install script that downloads and runs a second program ([MAL-2026-5979](https://osv.dev/vulnerability/MAL-2026-5979)). The Mastra releases depended on it, so installing any of them pulled it in. npm removed the malicious `easy-day-js` within hours. The clean decoy version is still on the registry, and the Mastra tarballs themselves contain no malicious code.

## What changed compared with the previous release

pkgdelta's findings for `@mastra/acp` 0.2.1 → 0.2.2 (from `results/v2_test.jsonl`):

```
BLOCK @mastra/acp 0.2.1 -> 0.2.2  (score 5)
      MEDIUM provenance-dropped: previous version had build provenance, this one does not
      MEDIUM fresh-dependency: new dependency easy-day-js was first published 0.8 days before this release
             by sergey2016, who does not maintain this package [package.json]
         LOW new-publisher: …
```

No code finding. The block comes from two pieces of metadata: the dependency is less than a day old and belongs to a stranger, and the release lost the build provenance the package used to have. `fresh-dependency` fired on all 119 releases. `provenance-dropped` fired on 106.

## Detection results

These releases are in the held-out 2026 split: the v1 rules were committed before anyone ran them on this data.

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 119 | 111 / 119 (93%) | 111 / 119 (93%) | 4 / 119 (3%) | 49 / 119 (41%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `fresh-dependency` (medium): 119
- `provenance-dropped` (medium): 106
- `new-endpoint` (medium): 3
- `injected-growth` (medium): 1
- `new-capability:env_dump` (medium): 1

<details><summary>All 119 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@mastra/acp` | 0.2.2 | 0.2.1 | – | BLOCK (5) | no_risks_detected |
| `@mastra/agent-browser` | 0.3.2 | 0.3.1 | [MAL-2026-5996](https://osv.dev/vulnerability/MAL-2026-5996) | BLOCK (5) | no_risks_detected |
| `@mastra/agentcore` | 0.2.2 | 0.2.1 | – | BLOCK (5) | no_risks_detected |
| `@mastra/agentfs` | 0.1.1 | 0.1.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/ai-sdk` | 1.4.6 | 1.4.5 | [MAL-2026-5939](https://osv.dev/vulnerability/MAL-2026-5939) | BLOCK (5) | low |
| `@mastra/arize` | 1.2.3 | 1.2.2 | [MAL-2026-5998](https://osv.dev/vulnerability/MAL-2026-5998) | BLOCK (5) | low |
| `@mastra/arthur` | 0.3.3 | 0.3.2 | – | BLOCK (5) | low |
| `@mastra/auth` | 1.0.3 | 1.0.2 | [MAL-2026-5940](https://osv.dev/vulnerability/MAL-2026-5940) | BLOCK (5) | low |
| `@mastra/auth-auth0` | 1.0.2 | 1.0.1 | [MAL-2026-5999](https://osv.dev/vulnerability/MAL-2026-5999) | BLOCK (5) | low |
| `@mastra/auth-better-auth` | 1.0.4 | 1.0.3 | [MAL-2026-6000](https://osv.dev/vulnerability/MAL-2026-6000) | BLOCK (5) | no_risks_detected |
| `@mastra/auth-clerk` | 1.0.3 | 1.0.2 | [MAL-2026-6001](https://osv.dev/vulnerability/MAL-2026-6001) | BLOCK (5) | low |
| `@mastra/auth-cloud` | 1.1.4 | 1.1.3 | – | BLOCK (5) | no_risks_detected |
| `@mastra/auth-firebase` | 1.0.1 | 1.0.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/auth-okta` | 0.0.5 | 0.0.4 | – | BLOCK (5) | low |
| `@mastra/auth-studio` | 1.2.4 | 1.2.3 | – | BLOCK (5) | no_risks_detected |
| `@mastra/auth-supabase` | 1.0.2 | 1.0.1 | [MAL-2026-6002](https://osv.dev/vulnerability/MAL-2026-6002) | BLOCK (5) | low |
| `@mastra/auth-workos` | 1.5.3 | 1.5.2 | [MAL-2026-6003](https://osv.dev/vulnerability/MAL-2026-6003) | BLOCK (5) | low |
| `@mastra/azure` | 0.2.3 | 0.2.2 | – | BLOCK (5) | no_risks_detected |
| `@mastra/braintrust` | 1.1.4 | 1.1.3 | [MAL-2026-5941](https://osv.dev/vulnerability/MAL-2026-5941) | BLOCK (5) | low |
| `@mastra/brightdata` | 0.2.2 | 0.2.1 | – | BLOCK (5) | low |
| `@mastra/browser-viewer` | 0.1.3 | 0.1.2 | – | BLOCK (5) | no_risks_detected |
| `@mastra/chroma` | 1.0.2 | 1.0.1 | [MAL-2026-6005](https://osv.dev/vulnerability/MAL-2026-6005) | BLOCK (5) | no_risks_detected |
| `@mastra/claude` | 1.0.3 | 1.0.2 | [MAL-2026-6006](https://osv.dev/vulnerability/MAL-2026-6006) | BLOCK (4) | no_risks_detected |
| `@mastra/clickhouse` | 1.10.1 | 1.10.0 | [MAL-2026-5942](https://osv.dev/vulnerability/MAL-2026-5942) | BLOCK (5) | no_risks_detected |
| `@mastra/client-js` | 1.24.1 | 1.24.0 | [MAL-2026-6007](https://osv.dev/vulnerability/MAL-2026-6007) | BLOCK (4) | no_risks_detected |
| `@mastra/cloud` | 0.1.24 | 0.1.23 | – | BLOCK (5) | low |
| `@mastra/cloudflare` | 1.4.2 | 1.4.1 | [MAL-2026-6008](https://osv.dev/vulnerability/MAL-2026-6008) | BLOCK (5) | no_risks_detected |
| `@mastra/cloudflare-d1` | 1.0.7 | 1.0.6 | [MAL-2026-6009](https://osv.dev/vulnerability/MAL-2026-6009) | BLOCK (5) | no_risks_detected |
| `@mastra/codemod` | 1.0.4 | 1.0.3 | – | BLOCK (5) | no_risks_detected |
| `@mastra/convex` | 1.2.2 | 1.2.1 | [MAL-2026-6010](https://osv.dev/vulnerability/MAL-2026-6010) | BLOCK (5) | no_risks_detected |
| `@mastra/core` | 1.42.1 | 1.42.0 | [MAL-2026-6011](https://osv.dev/vulnerability/MAL-2026-6011) | BLOCK (4) | high_risk |
| `@mastra/couchbase` | 1.0.4 | 1.0.3 | [MAL-2026-6012](https://osv.dev/vulnerability/MAL-2026-6012) | BLOCK (5) | no_risks_detected |
| `@mastra/cursor` | 0.2.1 | 0.2.0 | [MAL-2026-6013](https://osv.dev/vulnerability/MAL-2026-6013) | BLOCK (5) | no_risks_detected |
| `@mastra/dane` | 1.0.2 | 1.0.1 | – | BLOCK (4) | no_risks_detected |
| `@mastra/daytona` | 0.4.2 | 0.4.1 | [MAL-2026-6014](https://osv.dev/vulnerability/MAL-2026-6014) | BLOCK (5) | no_risks_detected |
| `@mastra/deployer` | 1.42.1 | 1.42.0 | [MAL-2026-6015](https://osv.dev/vulnerability/MAL-2026-6015) | BLOCK (4) | low |
| `@mastra/deployer-cloud` | 1.42.1 | 1.42.0 | – | BLOCK (5) | high_risk |
| `@mastra/deployer-cloudflare` | 1.1.44 | 1.1.43 | [MAL-2026-6016](https://osv.dev/vulnerability/MAL-2026-6016) | BLOCK (4) | no_risks_detected |
| `@mastra/deployer-netlify` | 1.1.20 | 1.1.19 | [MAL-2026-6017](https://osv.dev/vulnerability/MAL-2026-6017) | BLOCK (4) | no_risks_detected |
| `@mastra/deployer-vercel` | 1.1.38 | 1.1.37 | [MAL-2026-6018](https://osv.dev/vulnerability/MAL-2026-6018) | BLOCK (4) | high_risk |
| `@mastra/docker` | 0.3.1 | 0.3.0 | [MAL-2026-6019](https://osv.dev/vulnerability/MAL-2026-6019) | BLOCK (5) | no_risks_detected |
| `@mastra/duckdb` | 1.4.3 | 1.4.2 | [MAL-2026-5944](https://osv.dev/vulnerability/MAL-2026-5944) | BLOCK (5) | no_risks_detected |
| `@mastra/dynamodb` | 1.0.9 | 1.0.8 | [MAL-2026-5945](https://osv.dev/vulnerability/MAL-2026-5945) | BLOCK (5) | no_risks_detected |
| `@mastra/e2b` | 0.3.4 | 0.3.3 | [MAL-2026-6021](https://osv.dev/vulnerability/MAL-2026-6021) | BLOCK (5) | no_risks_detected |
| `@mastra/editor` | 0.11.3 | 0.11.2 | [MAL-2026-5946](https://osv.dev/vulnerability/MAL-2026-5946) | BLOCK (5) | no_risks_detected |
| `@mastra/elasticsearch` | 1.2.1 | 1.2.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/engine` | 0.1.1 | 0.0.4 | – | pass (2) | no_risks_detected |
| `@mastra/express` | 1.3.31 | 1.3.30 | [MAL-2026-6022](https://osv.dev/vulnerability/MAL-2026-6022) | BLOCK (5) | no_risks_detected |
| `@mastra/files-sdk` | 0.2.1 | 0.2.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/gcs` | 0.2.3 | 0.2.2 | [MAL-2026-6023](https://osv.dev/vulnerability/MAL-2026-6023) | BLOCK (5) | no_risks_detected |
| `@mastra/github-signals` | 0.1.2 | 0.1.1 | [MAL-2026-6052](https://osv.dev/vulnerability/MAL-2026-6052) | BLOCK (5) | no_risks_detected |
| `@mastra/google-drive` | 0.1.1 | 0.1.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/hono` | 1.4.26 | 1.4.25 | [MAL-2026-5950](https://osv.dev/vulnerability/MAL-2026-5950) | BLOCK (5) | no_risks_detected |
| `@mastra/inngest` | 1.5.2 | 1.5.1 | [MAL-2026-5951](https://osv.dev/vulnerability/MAL-2026-5951) | BLOCK (5) | no_risks_detected |
| `@mastra/koa` | 1.5.14 | 1.5.13 | [MAL-2026-6025](https://osv.dev/vulnerability/MAL-2026-6025) | BLOCK (5) | no_risks_detected |
| `@mastra/laminar` | 1.2.3 | 1.2.2 | – | BLOCK (5) | low |
| `@mastra/libsql` | 1.13.1 | 1.13.0 | [MAL-2026-5954](https://osv.dev/vulnerability/MAL-2026-5954) | BLOCK (5) | no_risks_detected |
| `@mastra/mcp` | 1.10.1 | 1.10.0 | [MAL-2026-5955](https://osv.dev/vulnerability/MAL-2026-5955) | BLOCK (4) | no_risks_detected |
| `@mastra/mcp-docs-server` | 1.1.47 | 1.1.46 | [MAL-2026-5956](https://osv.dev/vulnerability/MAL-2026-5956) | BLOCK (5) | no_risks_detected |
| `@mastra/memory` | 1.20.4 | 1.20.3 | [MAL-2026-6028](https://osv.dev/vulnerability/MAL-2026-6028) | BLOCK (4) | low |
| `@mastra/modal` | 0.2.2 | 0.2.1 | – | BLOCK (5) | no_risks_detected |
| `@mastra/mongodb` | 1.9.3 | 1.9.2 | [MAL-2026-5957](https://osv.dev/vulnerability/MAL-2026-5957) | BLOCK (5) | no_risks_detected |
| `@mastra/mysql` | 0.1.1 | 0.1.0 | – | BLOCK (5) | no_risks_detected |
| `@mastra/nestjs` | 0.1.15 | 0.1.14 | [MAL-2026-6030](https://osv.dev/vulnerability/MAL-2026-6030) | BLOCK (5) | no_risks_detected |
| `@mastra/node-audio` | 0.1.8 | 0.1.7 | [MAL-2026-6054](https://osv.dev/vulnerability/MAL-2026-6054) | BLOCK (3) | no_risks_detected |
| `@mastra/node-speaker` | 0.1.1 | 0.1.0 | [MAL-2026-6055](https://osv.dev/vulnerability/MAL-2026-6055) | BLOCK (3) | no_risks_detected |
| `@mastra/openai` | 1.0.2 | 1.0.0 | – | pass (2) | no_risks_detected |
| `@mastra/opencode` | 0.0.47 | 0.0.46 | – | BLOCK (5) | no_risks_detected |
| `@mastra/opensearch` | 1.0.3 | 1.0.2 | – | BLOCK (5) | no_risks_detected |
| `@mastra/otel-bridge` | 1.2.3 | 1.2.2 | [MAL-2026-5958](https://osv.dev/vulnerability/MAL-2026-5958) | BLOCK (5) | no_risks_detected |
| `@mastra/otel-exporter` | 1.2.3 | 1.2.2 | [MAL-2026-6031](https://osv.dev/vulnerability/MAL-2026-6031) | BLOCK (5) | low |
| `@mastra/perplexity` | 0.1.1 | 0.1.0 | – | BLOCK (5) | low |
| `@mastra/pg` | 1.13.1 | 1.13.0 | [MAL-2026-5959](https://osv.dev/vulnerability/MAL-2026-5959) | BLOCK (5) | no_risks_detected |
| `@mastra/pinecone` | 1.0.2 | 1.0.1 | [MAL-2026-6032](https://osv.dev/vulnerability/MAL-2026-6032) | BLOCK (5) | no_risks_detected |
| `@mastra/playground-ui` | 33.0.1 | 33.0.0 | [MAL-2026-6033](https://osv.dev/vulnerability/MAL-2026-6033) | BLOCK (5) | no_risks_detected |
| `@mastra/posthog` | 1.0.29 | 1.0.28 | [MAL-2026-5960](https://osv.dev/vulnerability/MAL-2026-5960) | BLOCK (5) | low |
| `@mastra/qdrant` | 1.0.3 | 1.0.2 | [MAL-2026-6034](https://osv.dev/vulnerability/MAL-2026-6034) | BLOCK (5) | no_risks_detected |
| `@mastra/rag` | 2.2.2 | 2.2.1 | [MAL-2026-5961](https://osv.dev/vulnerability/MAL-2026-5961) | BLOCK (4) | low |
| `@mastra/railway` | 0.1.1 | 0.1.0 | – | BLOCK (5) | low |
| `@mastra/react` | 1.0.1 | 0.6.0 | [MAL-2026-6056](https://osv.dev/vulnerability/MAL-2026-6056) | BLOCK (5) | no_risks_detected |
| `@mastra/redis` | 1.1.3 | 1.1.2 | [MAL-2026-6074](https://osv.dev/vulnerability/MAL-2026-6074) | BLOCK (5) | no_risks_detected |
| `@mastra/redis-streams` | 0.0.4 | 0.0.3 | – | BLOCK (5) | no_risks_detected |
| `@mastra/s3` | 0.5.3 | 0.5.2 | [MAL-2026-5962](https://osv.dev/vulnerability/MAL-2026-5962) | BLOCK (5) | no_risks_detected |
| `@mastra/s3vectors` | 1.0.7 | 1.0.6 | [MAL-2026-6035](https://osv.dev/vulnerability/MAL-2026-6035) | BLOCK (5) | no_risks_detected |
| `@mastra/schema-compat` | 1.2.12 | 1.2.11 | [MAL-2026-5963](https://osv.dev/vulnerability/MAL-2026-5963) | BLOCK (5) | no_risks_detected |
| `@mastra/sentry` | 1.1.4 | 1.1.3 | [MAL-2026-5964](https://osv.dev/vulnerability/MAL-2026-5964) | BLOCK (5) | no_risks_detected |
| `@mastra/server` | 2.1.1 | 2.0.4 | [MAL-2026-6036](https://osv.dev/vulnerability/MAL-2026-6036) | BLOCK (13) | low |
| `@mastra/slack` | 1.3.1 | 1.3.0 | – | BLOCK (5) | low |
| `@mastra/spanner` | 1.1.2 | 1.1.1 | – | BLOCK (5) | no_risks_detected |
| `@mastra/speech-azure` | 0.2.1 | 0.1.23 | – | pass (2) | low |
| `@mastra/speech-elevenlabs` | 0.2.1 | 0.1.22 | – | pass (2) | low |
| `@mastra/speech-google` | 0.2.1 | 0.1.23 | – | pass (2) | low |
| `@mastra/speech-murf` | 0.2.1 | 0.1.23 | – | pass (2) | low |
| `@mastra/speech-replicate` | 0.2.1 | 0.1.23 | – | pass (2) | low |
| `@mastra/stagehand` | 0.2.5 | 0.2.4 | [MAL-2026-6037](https://osv.dev/vulnerability/MAL-2026-6037) | BLOCK (5) | no_risks_detected |
| `@mastra/tavily` | 1.0.3 | 1.0.2 | [MAL-2026-6038](https://osv.dev/vulnerability/MAL-2026-6038) | BLOCK (5) | low |
| `@mastra/temporal` | 0.1.14 | 0.1.13 | [MAL-2026-6039](https://osv.dev/vulnerability/MAL-2026-6039) | BLOCK (5) | no_risks_detected |
| `@mastra/turbopuffer` | 1.0.3 | 1.0.2 | [MAL-2026-6040](https://osv.dev/vulnerability/MAL-2026-6040) | BLOCK (5) | no_risks_detected |
| `@mastra/twilio` | 1.0.2 | 1.0.0 | – | pass (2) | low |
| `@mastra/upstash` | 1.1.3 | 1.1.2 | [MAL-2026-6041](https://osv.dev/vulnerability/MAL-2026-6041) | BLOCK (5) | no_risks_detected |
| `@mastra/vectorize` | 1.0.3 | 1.0.2 | [MAL-2026-6042](https://osv.dev/vulnerability/MAL-2026-6042) | BLOCK (5) | no_risks_detected |
| `@mastra/vercel` | 1.0.1 | 1.0.0 | – | BLOCK (4) | low |
| `@mastra/voice-cloudflare` | 0.12.3 | 0.12.2 | – | BLOCK (5) | low |
| `@mastra/voice-deepgram` | 0.12.2 | 0.12.1 | [MAL-2026-6044](https://osv.dev/vulnerability/MAL-2026-6044) | BLOCK (5) | low |
| `@mastra/voice-elevenlabs` | 0.12.2 | 0.12.1 | [MAL-2026-6045](https://osv.dev/vulnerability/MAL-2026-6045) | BLOCK (5) | low |
| `@mastra/voice-gladia` | 0.12.2 | 0.12.1 | – | BLOCK (5) | low |
| `@mastra/voice-google` | 0.12.3 | 0.12.2 | [MAL-2026-6046](https://osv.dev/vulnerability/MAL-2026-6046) | BLOCK (5) | low |
| `@mastra/voice-google-gemini-live` | 0.12.2 | 0.12.1 | [MAL-2026-6047](https://osv.dev/vulnerability/MAL-2026-6047) | BLOCK (5) | no_risks_detected |
| `@mastra/voice-inworld` | 0.3.1 | 0.3.0 | – | BLOCK (5) | low |
| `@mastra/voice-modelslab` | 0.1.2 | 0.1.1 | – | BLOCK (5) | low |
| `@mastra/voice-murf` | 0.12.3 | 0.12.2 | – | BLOCK (5) | low |
| `@mastra/voice-openai` | 0.12.3 | 0.12.2 | [MAL-2026-6048](https://osv.dev/vulnerability/MAL-2026-6048) | BLOCK (5) | low |
| `@mastra/voice-openai-realtime` | 0.12.6 | 0.12.5 | [MAL-2026-6049](https://osv.dev/vulnerability/MAL-2026-6049) | BLOCK (5) | low |
| `@mastra/voice-playai` | 0.12.2 | 0.12.1 | [MAL-2026-6057](https://osv.dev/vulnerability/MAL-2026-6057) | BLOCK (5) | low |
| `@mastra/voice-sarvam` | 1.0.2 | 1.0.1 | – | BLOCK (5) | low |
| `@mastra/voice-speechify` | 0.12.2 | 0.12.1 | – | BLOCK (5) | low |
| `@mastra/voice-xai-realtime` | 0.1.2 | 0.1.1 | – | BLOCK (5) | low |
| `create-mastra` | 1.13.1 | 1.13.0 | [MAL-2026-6050](https://osv.dev/vulnerability/MAL-2026-6050) | BLOCK (5) | suspicious |
| `mastra` | 1.13.1 | 1.13.0 | [MAL-2026-5965](https://osv.dev/vulnerability/MAL-2026-5965) | BLOCK (4) | high_risk |

</details>
<!-- numbers:end -->

## The 8 that passed

`@mastra/engine` 0.1.1, `@mastra/openai` 1.0.2, `@mastra/twilio` 1.0.2, and `@mastra/speech-azure`, `-elevenlabs`, `-google`, `-murf`, `-replicate` 0.2.1 had no build provenance on the previous release either, so nothing was dropped. They got `fresh-dependency` alone: score 2, under the blocking line of 3.

`fresh-dependency` is medium on purpose. It fires on 3 of the 6,707 normal updates in the benign set (for example `fast-levenshtein` 3.0.0 switching to `fastest-levenshtein`). Making it high would block those too. It becomes high only if the fresh dependency already has an install script, and here the malicious `easy-day-js` version was deleted before anyone could scan it after the fact.

What would have caught all 119: scanning the new dependency itself at install time. pkgdelta's `diff` does check every version a lockfile change brings in, including new transitive ones like `easy-day-js`, and asks OSV about each. Whether it catches the dependency depends on whether the malicious version is still on the registry, or already in OSV, at the moment you run it.

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

Look for `easy-day-js` in your lockfile. If it is pinned at 1.11.22, `audit` fails with the OSV id. If a Mastra version from the list below was installed while that version was live, the install script ran: rotate the credentials that machine or CI job could read.

Related: [axios / plain-crypto-js](axios-plain-crypto-js.md) used the same fresh-dependency trick. All incidents: [index](README.md).
