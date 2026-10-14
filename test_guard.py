"""Tests for AI Stack Guard. Standard library only: python3 -m unittest -v test_guard.py

A small fake scanner stands in for ai-stack-advisories, with the same CLI and JSON shape, so the
tests need no network and fixed advisory data.
"""
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "guard"))
import guard  # noqa: E402

FAKE_SCANNER = textwrap.dedent('''
    import argparse, json, re
    from pathlib import Path

    DB = {
        "vllm/vllm-openai": ("vLLM", [["GHSA-aaaa", "high", "0.31.0"], ["GHSA-bbbb", "moderate", "0.31.0"]]),
        "open-webui/open-webui": ("Open WebUI", [["GHSA-cccc", "critical", "0.11.4"]]),
        "flowiseai/flowise": ("Flowise", [["GHSA-dddd", "high", None]]),
    }
    IMAGE = re.compile(r'^\\s*-?\\s*image:\\s*["\\']?(?:ghcr\\.io/)?([^:\\s"\\']+):v?([0-9.]+)')

    def vt(v):
        return tuple(int(x) for x in v.split("."))

    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=["."])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on")
    args = parser.parse_args()
    findings = []
    for root in args.paths:
        for path in sorted(Path(root).rglob("*.yaml")):
            for n, text in enumerate(path.read_text().splitlines(), 1):
                m = IMAGE.match(text)
                if not m or m.group(1) not in DB:
                    continue
                name, advs = DB[m.group(1)]
                hits = [{"id": i, "aliases": ["CVE-" + i[5:]], "severity": s, "fixedIn": f, "summary": "test",
                         "url": "https://example.test/" + i, "notInPublicDatabases": False,
                         "onlyIfFeatureUsed": None} for i, s, f in advs if f is None or vt(m.group(2)) < vt(f)]
                fixes = [a["fixedIn"] for a in hits if a["fixedIn"]]
                findings.append({"file": path.as_posix(), "line": n, "kind": "image", "ref": text.split("image:")[1].strip(),
                                 "product": m.group(1), "name": name, "version": m.group(2), "range": False,
                                 "status": "affected" if hits else "ok", "advisories": hits,
                                 "upgradeTo": max(fixes, key=vt) if fixes else None,
                                 "noFixedRelease": sum(1 for a in hits if not a["fixedIn"])})
    print(json.dumps({"curatedDataAsOf": "2026-10-13", "findings": findings}))
''')

COMPOSE = textwrap.dedent('''\
    services:
      vllm:
        image: vllm/vllm-openai:v0.30.0
      open-webui:
        image: ghcr.io/open-webui/open-webui:v0.11.3
      flowise:
        image: flowiseai/flowise:3.1.4
''')

TODAY = "2026-10-14"


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        Path("scanner.py").write_text(FAKE_SCANNER)
        Path("demo").mkdir()
        Path("demo/compose.yaml").write_text(COMPOSE)
        self.policy = dict(guard.DEFAULT_POLICY)

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def report(self, policy=None):
        policy = policy or self.policy
        return guard.build_report(guard.run_scanner("scanner.py", policy["paths"]), policy, TODAY)

    def test_blocking_skips_unfixable_and_low_severity(self):
        blocked = guard.blocking(self.report(), self.policy)
        self.assertEqual(sorted(f["name"] for f in blocked), ["Open WebUI", "vLLM"])
        strict = {**self.policy, "unfixable_blocks": True}
        self.assertEqual(len(guard.blocking(self.report(strict), strict)), 3)
        self.assertEqual(guard.blocking(self.report(), {**self.policy, "block_on": "never"}), [])
        only_critical = {**self.policy, "block_on": "critical"}
        self.assertEqual([f["name"] for f in guard.blocking(self.report(), only_critical)], ["Open WebUI"])

    def test_blocking_on_changed_lines_only(self):
        changed = {("demo/compose.yaml", 5)}
        self.assertEqual([f["name"] for f in guard.blocking(self.report(), self.policy, changed)], ["Open WebUI"])

    def test_ignore_rules_expire(self):
        live = {**self.policy, "ignore": [{"id": "CVE-cccc", "until": "2026-12-31"}]}
        statuses = {f["name"]: f["status"] for f in self.report(live)["findings"]}
        self.assertEqual(statuses["Open WebUI"], "ignored")
        expired = {**self.policy, "ignore": [{"id": "GHSA-cccc", "until": "2026-10-01"}]}
        statuses = {f["name"]: f["status"] for f in self.report(expired)["findings"]}
        self.assertEqual(statuses["Open WebUI"], "affected")

    def test_plan_groups_by_bump_size(self):
        planned = guard.plan(self.report(), self.policy)
        groups = {a["name"]: (a["bump"], a["group"]) for a in planned["actions"]}
        self.assertEqual(groups, {"vLLM": ("major", "review"), "Open WebUI": ("patch", "auto")})
        self.assertEqual([u["id"] for u in planned["unfixable"]], ["GHSA-dddd"])
        none = guard.plan(self.report(), {**self.policy, "auto_merge": "none"})
        self.assertEqual({a["group"] for a in none["actions"]}, {"review"})

    def test_patch_verify_notes_and_issues(self):
        before = self.report()
        planned = guard.plan(before, self.policy)
        patched = guard.apply_actions(planned["actions"])
        self.assertEqual(len(patched["applied"]), 2)
        text = Path("demo/compose.yaml").read_text()
        self.assertIn("vllm/vllm-openai:v0.31.0", text)
        self.assertIn("open-webui:v0.11.4", text)
        self.assertIn("flowiseai/flowise:3.1.4", text)
        verified = guard.verify(patched["applied"], before, self.report())
        self.assertTrue(verified["passed"], verified)
        doc = guard.notes(planned, patched, verified, self.policy, before, TODAY)
        self.assertEqual([g["group"] for g in doc["groups"]], ["auto", "review"])
        auto = doc["groups"][0]
        self.assertTrue(auto["branch"].startswith("ai-stack-guard/2026-10-14-auto-"))
        self.assertIn("Open WebUI 0.11.3 to 0.11.4", auto["title"])
        self.assertIn("GHSA-cccc", auto["description"])
        self.assertIn("major bump", doc["groups"][1]["description"])
        found = guard.issues(planned, TODAY)
        self.assertEqual(found[0]["title"], "AI Stack Guard: Flowise 3.1.4 has no fixed release for GHSA-dddd")
        self.assertIn("severity::high", found[0]["labels"])

    def test_verify_fails_when_fix_is_not_enough(self):
        before = self.report()
        planned = guard.plan(before, self.policy)
        for a in planned["actions"]:
            if a["name"] == "vLLM":
                a["to"] = "0.30.5"
        patched = guard.apply_actions(planned["actions"])
        verified = guard.verify(patched["applied"], before, self.report())
        self.assertFalse(verified["passed"])
        self.assertIn("still fixable", [r for r in verified["rows"] if r["name"] == "vLLM"][0]["why"])

    def test_run_command_writes_work_files(self):
        Path("ai-stack-guard.json").write_text(json.dumps({"paths": ["demo"]}))
        self.assertEqual(guard.main(["scan", "--scanner", "scanner.py", "--today", TODAY]), 1)
        code = guard.main(["run", "--scanner", "scanner.py", "--today", TODAY])
        self.assertEqual(code, 0)
        for name in ("report.json", "plan.json", "verify.json", "notes.json", "issues.json"):
            self.assertTrue(Path(".ai-stack-guard", name).is_file(), name)
        self.assertTrue(Path("gl-code-quality-report.json").is_file())
        quality = json.loads(Path("gl-code-quality-report.json").read_text())
        self.assertIn("blocker", {q["severity"] for q in quality})
        # Outside a git checkout the patched files stay patched, so only the unfixable Flowise pin is left.
        self.assertEqual(guard.main(["scan", "--scanner", "scanner.py", "--today", TODAY]), 0)

    def test_ship_dry_run_commands(self):
        before = self.report()
        planned = guard.plan(before, self.policy)
        patched = guard.apply_actions(planned["actions"])
        doc = guard.notes(planned, patched, guard.verify(patched["applied"], before, self.report()),
                          self.policy, before, TODAY)
        result = guard.ship(doc, dry_run=True)
        cmd = result["mergeRequests"][0]["command"]
        self.assertIn("merge_request.create", cmd)
        self.assertIn("merge_request.target=main", cmd)
        self.assertNotIn("merge_request.merge_when_pipeline_succeeds", cmd)
        armed = guard.push_command(doc["groups"][0], "main", arm=True)
        self.assertEqual(armed[-1], "merge_request.merge_when_pipeline_succeeds")


class LineTest(unittest.TestCase):
    def test_patch_line(self):
        self.assertEqual(guard.patch_line("  image: vllm/vllm-openai:v0.30.0\n", "0.30.0", "0.31.0"),
                         ("  image: vllm/vllm-openai:v0.31.0\n", None))
        self.assertEqual(guard.patch_line("image: x:${TAG:-v0.30.0}", "0.30.0", "v0.31.0")[0], "image: x:${TAG:-v0.31.0}")
        self.assertEqual(guard.patch_line('"n8n": "^1.2.3",', "1.2.3", "1.2.9")[0], '"n8n": "^1.2.9",')
        self.assertIsNone(guard.patch_line("image: x:10.30.0", "0.30.0", "0.31.0")[0])
        self.assertIsNone(guard.patch_line("image: x:0.30.0.1", "0.30.0", "0.31.0")[0])
        self.assertIn("digest", guard.patch_line("image: x:0.30.0@sha256:abc", "0.30.0", "0.31.0")[1])
        self.assertIn("2 times", guard.patch_line("x:0.30.0 # was 0.30.0", "0.30.0", "0.31.0")[1])

    def test_bump_and_suffix(self):
        self.assertEqual(guard.bump("0.11.3", "0.11.4"), "patch")
        self.assertEqual(guard.bump("0.30.0", "0.31.0"), "major")
        self.assertEqual(guard.bump("1.2.3", "1.4.0"), "minor")
        self.assertEqual(guard.bump("1.2.3", "2.0.0"), "major")
        self.assertEqual(guard.bump("1.2.3", "1.2.3"), "none")
        self.assertTrue(guard.has_tag_suffix("image", "vllm/vllm-openai:v0.30.0-cu128", "0.30.0"))
        self.assertFalse(guard.has_tag_suffix("image", "x:${TAG:-0.30.0}", "0.30.0"))

    def test_severity(self):
        self.assertEqual(guard.severity("Moderate"), "medium")
        self.assertEqual(guard.severity(9.9), "critical")
        self.assertEqual(guard.severity(None), "unknown")

    def test_parse_diff(self):
        diff = textwrap.dedent('''\
            diff --git a/demo/compose.yaml b/demo/compose.yaml
            --- a/demo/compose.yaml
            +++ b/demo/compose.yaml
            @@ -5 +5 @@ services:
            -    image: ghcr.io/open-webui/open-webui:v0.11.3
            +    image: ghcr.io/open-webui/open-webui:v0.11.4
            diff --git a/stack-changes/x.md b/stack-changes/x.md
            --- /dev/null
            +++ b/stack-changes/x.md
            @@ -0,0 +1,2 @@
            +# x
            +y
        ''')
        self.assertEqual(guard.parse_diff(diff),
                         {("demo/compose.yaml", 5), ("stack-changes/x.md", 1), ("stack-changes/x.md", 2)})


if __name__ == "__main__":
    unittest.main()
