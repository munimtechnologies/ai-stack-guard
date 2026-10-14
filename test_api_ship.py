import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
if not (HERE / "guard" / "guard.py").is_file():
    # The publish check runs only the changed files in a scratch folder; test them against guard.py on main.
    url = "https://raw.githubusercontent.com/munimtechnologies/ai-stack-guard/main/guard/guard.py"
    (HERE / "guard").mkdir(exist_ok=True)
    with urllib.request.urlopen(url, timeout=30) as resp:
        (HERE / "guard" / "guard.py").write_bytes(resp.read())
sys.path.insert(0, str(HERE / "guard"))
import api_ship  # noqa: E402
import guard  # noqa: E402

TODAY = "2026-10-14"
COMPOSE = ("services:\r\n"
           "  vllm:\r\n"
           "    image: vllm/vllm-openai:v0.30.0\r\n"
           "  open-webui:\r\n"
           "    image: ghcr.io/open-webui/open-webui:v0.11.3\r\n"
           "  flowise:\r\n"
           "    image: flowiseai/flowise:3.1.4\r\n"
           "  ollama:\r\n"
           "    image: ollama/ollama:0.12.6\r\n")
# Reads the compose file, so a patched line really comes back clean on the rescan.
FAKE_SCANNER = '''import json
from pathlib import Path


def adv(i, sev, fixed):
    return {"id": i, "aliases": [], "severity": sev, "fixedIn": fixed, "summary": "test advisory",
            "url": "https://example.test/" + i, "onlyIfFeatureUsed": None}


KNOWN = {
    "vllm/vllm-openai": ("vLLM", {"0.30.0": ("0.31.0", [adv("GHSA-aaaa", "high", "0.31.0")])}),
    "ghcr.io/open-webui/open-webui": ("Open WebUI", {"0.11.3": ("0.11.4", [adv("GHSA-cccc", "critical", "0.11.4")])}),
    "flowiseai/flowise": ("Flowise", {"3.1.4": (None, [adv("GHSA-dddd", "high", None)])}),
    "ollama/ollama": ("Ollama", {}),
}
findings = []
with open("demo/compose.yaml", encoding="utf-8", newline="") as fh:
    lines = fh.read().splitlines()
for number, text in enumerate(lines, 1):
    if "image:" not in text:
        continue
    ref = text.split("image:", 1)[1].strip()
    image, tag = ref.rsplit(":", 1)
    version = tag.lstrip("v")
    name, bad = KNOWN[image]
    upgrade, advisories = bad.get(version, (None, []))
    findings.append({"file": "demo/compose.yaml", "line": number, "kind": "image", "ref": ref, "name": name,
                     "version": version, "status": "affected" if advisories else "ok", "upgradeTo": upgrade,
                     "advisories": advisories})
print(json.dumps({"curatedDataAsOf": "2026-10-13", "findings": findings}))
'''


def write_exact(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def read_exact(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


class ApiShipTest(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        Path("scanner.py").write_text(FAKE_SCANNER)
        Path("demo").mkdir()
        write_exact("demo/compose.yaml", COMPOSE)
        Path("ai-stack-guard.json").write_text(json.dumps({"paths": ["demo"]}))
        with contextlib.redirect_stdout(io.StringIO()):
            code = guard.main(["run", "--scanner", "scanner.py", "--today", TODAY])
        self.assertEqual(code, 0)
        self.assertTrue(guard.read("verify.json")["passed"])
        # Outside a git checkout, run leaves its edits in place; ship would start from the clean base.
        write_exact("demo/compose.yaml", COMPOSE)

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def prepare(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(api_ship.main([]), 0)
        return json.loads(out.getvalue())

    def plan(self, group):
        return json.loads(Path(".ai-stack-guard/api", f"{group}.json").read_text(encoding="utf-8"))

    def test_one_plan_per_group_with_exact_files(self):
        result = self.prepare()
        self.assertEqual(result["targetBranch"], "main")
        self.assertEqual([g["group"] for g in result["groups"]], ["auto", "review"])
        self.assertTrue(all(g["status"] == "prepared" for g in result["groups"]))
        auto = self.plan("auto")
        compose = next(f for f in auto["files"] if f["filePath"] == "demo/compose.yaml")
        self.assertEqual(compose["action"], "update")
        patched = read_exact(compose["readFrom"])
        self.assertEqual(patched, COMPOSE.replace("open-webui:v0.11.3", "open-webui:v0.11.4"))
        review = self.plan("review")
        patched = read_exact(next(f for f in review["files"] if f["filePath"] == "demo/compose.yaml")["readFrom"])
        self.assertEqual(patched, COMPOSE.replace("vllm-openai:v0.30.0", "vllm-openai:v0.31.0"))
        self.assertEqual(read_exact("demo/compose.yaml"), COMPOSE)  # the checkout is never touched

    def test_matches_what_ship_would_push(self):
        self.prepare()
        notes = guard.read("notes.json")
        for g in notes["groups"]:
            doc = self.plan(g["group"])
            self.assertEqual(doc["branch"], g["branch"])
            self.assertEqual((doc["startBranch"], doc["targetBranch"]), ("main", "main"))
            self.assertEqual(doc["autoMerge"], g["group"] == "auto")
            options = guard.push_command(g, "main")
            self.assertIn(f"merge_request.title={doc['mergeRequest']['title']}", options)
            self.assertIn(f"merge_request.description={doc['mergeRequest']['description']}", options)
            self.assertEqual(doc["mergeRequest"]["labels"], [guard.LABEL])
            self.assertTrue(doc["commitMessage"].startswith(g["title"] + "\n\n"))
            self.assertIn("made with AI agents", doc["commitMessage"])
            changelog = next(f for f in doc["files"] if f["filePath"] == g["changelogPath"])
            self.assertEqual(changelog["action"], "create")
            self.assertTrue(g["changelogPath"].startswith(guard.CHANGES_DIR + "/"))
            self.assertEqual(read_exact(changelog["readFrom"]), g["changelog"])
            self.assertEqual(Path(doc["notePath"]).read_text(encoding="utf-8"), g["description"])
            self.assertIn("|", g["description"])  # the evidence table travels as the first comment

    def test_refuses_unverified_changes(self):
        verify = guard.read("verify.json")
        guard.write("verify.json", {**verify, "passed": False})
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()):
            api_ship.main([])
        self.assertIn("verification failed", str(ctx.exception))
        self.assertFalse(Path(".ai-stack-guard/api").exists())

    def test_line_that_moved_is_skipped_not_guessed(self):
        write_exact("demo/compose.yaml", COMPOSE.replace("open-webui:v0.11.3", "open-webui:v0.11.9"))
        result = self.prepare()
        auto = next(g for g in result["groups"] if g["group"] == "auto")
        self.assertEqual(auto["status"], "nothing to change")
        self.assertIn("demo/compose.yaml:5", auto["skipped"][0])
        self.assertFalse(Path(".ai-stack-guard/api/auto.json").exists())
        self.assertEqual(next(g for g in result["groups"] if g["group"] == "review")["status"], "prepared")

    def test_flow_falls_back_to_api_tools(self):
        flow = HERE / ".gitlab" / "duo" / "flows" / "ai-stack-guard.yaml"
        if not flow.is_file():
            self.skipTest("flow file not in this checkout")
        text = flow.read_text(encoding="utf-8")
        for tool in ("create_branch", "create_commit", "create_merge_request", "gitlab_merge_request_search"):
            self.assertIn(f"      - {tool}\n", text)
        self.assertIn("python3 guard/api_ship.py", text)
        self.assertIn("python3 guard/guard.py review --arm", text)
        for line in text.splitlines():  # template variables belong in the user blocks only
            if "{{" in line:
                self.assertRegex(line.strip(), r"^(Project ID|Trigger context|Guard report): \{\{ \w+ \}\}$")


if __name__ == "__main__":
    unittest.main()
