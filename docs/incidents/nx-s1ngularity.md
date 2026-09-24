# Nx "s1ngularity" npm compromise (August 2025, @nx/* 21.5.0): detection results and how to check your lockfile

On 26 August 2025 malicious versions of `nx` and its plugins were published with an npm token stolen from the Nx project's CI: `@nx/devkit`, `@nx/js`, `@nx/workspace`, `@nx/node`, `@nx/eslint` 21.5.0, `@nx/key` and `@nx/enterprise-cloud` 3.2.0, and others. The DataDog dataset has 7 of them. pkgdelta blocks all 7. GuardDog's own verdict passes all 7 (it calls them `suspicious`, not `high_risk`); its individual threat rules fire on all 7.

This is training data: pkgdelta's rules were written while looking at it.

[Am I affected?](#am-i-affected) · [What changed](#what-changed-compared-with-the-previous-release) · [Numbers](#detection-results)

## What happened

A GitHub Actions workflow in the Nx repository could be made to run attacker code, which leaked the npm publish token. The attacker published new versions with `"postinstall": "node telemetry.js"`. `telemetry.js` searched the machine for secrets and wallet files, including by asking locally installed AI command-line tools (Claude Code, Gemini CLI, Amazon Q) to look for them, then uploaded what it found to a new public GitHub repository named `s1ngularity-repository` in the victim's own account. It also appended a shutdown command to `~/.bashrc` and `~/.zshrc`.

## What changed compared with the previous release

pkgdelta's findings for `@nx/eslint` 21.4.1 → 21.5.0 (from `results/v2_train.jsonl`):

```
BLOCK @nx/eslint 21.4.1 -> 21.5.0  (score 8)
        HIGH install-hook: postinstall script added: node telemetry.js [package.json]
      MEDIUM new-capability:credential_paths: code starts using credential paths (previous version never did) [telemetry.js]
             const npmrcPath = path.join(home, '.npmrc'); try { if (fs.existsSync(npmrcPath)) {
      MEDIUM provenance-dropped: previous version had build provenance, this one does not
         LOW new-capability:child_process: code starts using child process (previous version never did) [telemetry.js]
```

`provenance-dropped` fired on 5 of the 7. The clean releases came out of Nx's CI with build provenance; the malicious ones were published with the stolen token from somewhere else. That signal is weak on its own (5 of 6,707 normal updates also drop provenance), which is why it is only medium.

## Detection results

<!-- numbers:start -->
| | Releases | pkgdelta v1 (frozen) | pkgdelta v2 | GuardDog `high_risk` | GuardDog, any `threat-*` rule |
|---|---|---|---|---|---|
| Blocked | 7 | 7 / 7 (100%) | 7 / 7 (100%) | 0 / 7 (0%) | 7 / 7 (100%) |

Findings in these releases (pkgdelta v2, medium and high only; count = releases):

- `install-hook` (high): 7
- `new-capability:credential_paths` (medium): 5
- `provenance-dropped` (medium): 5

<details><summary>All 7 releases (baseline = the clean release it was compared with)</summary>

| Package | Bad version | Baseline | OSV | pkgdelta v2 | GuardDog |
|---|---|---|---|---|---|
| `@nx/devkit` | 21.5.0 | 21.4.1 | [MAL-2025-41436](https://osv.dev/vulnerability/MAL-2025-41436) | BLOCK (7) | suspicious |
| `@nx/enterprise-cloud` | 3.2.0 | 3.1.0 | [MAL-2025-41437](https://osv.dev/vulnerability/MAL-2025-41437) | BLOCK (6) | suspicious |
| `@nx/eslint` | 21.5.0 | 21.4.1 | [MAL-2025-41438](https://osv.dev/vulnerability/MAL-2025-41438) | BLOCK (8) | suspicious |
| `@nx/js` | 21.5.0 | 21.4.1 | [MAL-2025-41439](https://osv.dev/vulnerability/MAL-2025-41439) | BLOCK (5) | suspicious |
| `@nx/key` | 3.2.0 | 3.1.0 | – | BLOCK (5) | suspicious |
| `@nx/node` | 21.5.0 | 21.4.1 | [MAL-2025-41441](https://osv.dev/vulnerability/MAL-2025-41441) | BLOCK (8) | suspicious |
| `@nx/workspace` | 21.5.0 | 21.4.1 | [MAL-2025-41442](https://osv.dev/vulnerability/MAL-2025-41442) | BLOCK (5) | suspicious |

</details>
<!-- numbers:end -->

## Am I affected?

```
pip install git+https://github.com/thejusdutt/pkgdelta
pkgdelta audit package-lock.json      # or pnpm-lock.yaml / yarn.lock
```

`audit` asks [OSV](https://osv.dev) about every locked version, so the `nx` versions npm removed still fail. If one was installed: look for a `s1ngularity-repository` repository in your GitHub account, check the end of `~/.bashrc` and `~/.zshrc` for a `sudo shutdown` line, and rotate the npm, GitHub and cloud credentials on that machine.

The token was stolen from CI, but the malicious versions were published from outside it (that is what the missing provenance shows). A pre-publish check inside the Nx pipeline would not have run. The check has to happen on the installing side.

All incidents: [index](README.md).
