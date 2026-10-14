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
    url = "https://raw.githubusercontent.com/munimv2/ai-stack-guard/main/guard/guard.py"
    (HERE / "guard").mkdir(exist_ok=True)
    with urllib.request.urlopen(url, timeout=30) as resp:
        (HERE / "guard" / "guard.py").write_bytes(resp.read())
sys.path.insert(0, str(HERE / "guard"))
import mcp_server  # noqa: E402

TODAY = "2026-10-14"
COMPOSE = """services:
  vllm:
    image: vllm/vllm-openai:v0.30.0
  open-webui:
    image: ghcr.io/open-webui/open-webui:v0.11.3
  flowise:
    image: flowiseai/flowise:3.1.4
  ollama:
    image: ollama/ollama:0.12.6
"""
FAKE_SCANNER = '''import json


def adv(i, sev, fixed):
    return {"id": i, "aliases": ["CVE-" + i[5:]], "severity": sev, "fixedIn": fixed, "summary": "test advisory",
            "url": "https://example.test/" + i, "onlyIfFeatureUsed": None}


findings = [
    {"file": "demo/compose.yaml", "line": 3, "kind": "image", "ref": "vllm/vllm-openai:v0.30.0", "name": "vLLM",
     "version": "0.30.0", "status": "affected", "upgradeTo": "0.31.0",
     "advisories": [adv("GHSA-aaaa", "high", "0.31.0"), adv("GHSA-bbbb", "moderate", "0.31.0")]},
    {"file": "demo/compose.yaml", "line": 5, "kind": "image", "ref": "ghcr.io/open-webui/open-webui:v0.11.3",
     "name": "Open WebUI", "version": "0.11.3", "status": "affected", "upgradeTo": "0.11.4",
     "advisories": [adv("GHSA-cccc", "critical", "0.11.4")]},
    {"file": "demo/compose.yaml", "line": 7, "kind": "image", "ref": "flowiseai/flowise:3.1.4", "name": "Flowise",
     "version": "3.1.4", "status": "affected", "upgradeTo": None, "advisories": [adv("GHSA-dddd", "high", None)]},
    {"file": "demo/compose.yaml", "line": 9, "kind": "image", "ref": "ollama/ollama:0.12.6", "name": "Ollama",
     "version": "0.12.6", "status": "ok", "upgradeTo": None, "advisories": []},
]
print(json.dumps({"curatedDataAsOf": "2026-10-13", "findings": findings}))
'''


class McpServerTest(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        Path("scanner.py").write_text(FAKE_SCANNER)
        Path("demo").mkdir()
        Path("demo/compose.yaml").write_text(COMPOSE)
        Path("ai-stack-guard.json").write_text(json.dumps({"paths": ["demo"]}))
        self.server = mcp_server.Server(scanner="scanner.py", today=TODAY)

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def call(self, name, arguments=None, mid=7):
        reply = self.server.handle({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                                    "params": {"name": name, "arguments": arguments or {}}})
        self.assertEqual(reply["id"], mid)
        return reply["result"]

    def text(self, name, arguments=None):
        res = self.call(name, arguments)
        self.assertFalse(res["isError"], res["content"][0]["text"])
        return res["content"][0]["text"]

    def test_initialize_and_list_tools(self):
        init = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2025-03-26", "capabilities": {}}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("tools", init["result"]["capabilities"])
        self.assertEqual(init["result"]["serverInfo"]["name"], "ai-stack-guard")
        odd = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                  "params": {"protocolVersion": "1999-01-01"}})
        self.assertEqual(odd["result"]["protocolVersion"], mcp_server.PROTOCOL)
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(self.server.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"})["result"], {})
        tools = self.server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, {"scan_stack", "plan_upgrades", "component_advisories"})
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"])

    def test_scan_stack(self):
        text = self.text("scan_stack")
        for name in ("vLLM", "Open WebUI", "Flowise"):
            self.assertIn(f"| {name} |", text)
        self.assertNotIn("| Ollama |", text)
        self.assertIn("2 component(s) would fail the pipeline (policy block_on: high)", text)
        Path("ai-stack-guard.json").write_text(json.dumps({"paths": ["demo"], "block_on": "never"}))
        self.assertIn("Nothing fails the pipeline", self.text("scan_stack"))

    def test_plan_upgrades_changes_nothing(self):
        text = self.text("plan_upgrades")
        self.assertIn("policy auto_merge: patch", text)
        self.assertLess(text.index("Auto group"), text.index("Open WebUI"))
        self.assertLess(text.index("Open WebUI"), text.index("Review group"))
        self.assertLess(text.index("Review group"), text.index("vLLM"))
        self.assertIn("0.11.3 -> 0.11.4 (patch bump", text)
        self.assertIn("0.30.0 -> 0.31.0 (major bump", text)
        self.assertIn("GHSA-dddd (high)", text)
        self.assertEqual(Path("demo/compose.yaml").read_text(), COMPOSE)
        self.assertFalse(Path(".ai-stack-guard").exists())
        Path("ai-stack-guard.json").write_text(json.dumps({"paths": ["demo"], "auto_merge": "none"}))
        self.assertNotIn("Auto group", self.text("plan_upgrades"))

    def test_component_advisories(self):
        text = self.text("component_advisories", {"name": "vllm"})
        self.assertIn("## vLLM 0.30.0 at `demo/compose.yaml:3` (affected)", text)
        self.assertIn("Upgrade to: 0.31.0", text)
        self.assertIn("GHSA-aaaa (high)", text)
        self.assertIn("GHSA-bbbb (medium)", text)
        self.assertIn("no fixed release yet", self.text("component_advisories", {"name": "Flowise"}))
        self.assertIn("No known advisory", self.text("component_advisories", {"name": "ollama"}))
        missing = self.text("component_advisories", {"name": "zzz"})
        self.assertIn("No pinned component matching 'zzz'", missing)
        self.assertIn("Ollama", missing)
        self.assertTrue(self.call("component_advisories", {})["isError"])

    def test_errors_are_reported_not_raised(self):
        res = mcp_server.Server(scanner="missing.py", today=TODAY).call("scan_stack", {})
        self.assertTrue(res["isError"])
        self.assertIn("scanner not found", res["content"][0]["text"])
        Path("ai-stack-guard.json").write_text(json.dumps({"auto_merge": "sometimes"}))
        self.assertTrue(self.call("plan_upgrades")["isError"])
        unknown = self.server.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                      "params": {"name": "rm_rf", "arguments": {}}})
        self.assertEqual(unknown["error"]["code"], -32602)

    def test_serve_loop(self):
        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "test", "version": "0"}}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            "",
            "not json",
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "scan_stack", "arguments": {}}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
        ]
        out = io.StringIO()
        mcp_server.serve(self.server, io.StringIO("\n".join(lines) + "\n"), out)
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r["id"] for r in replies], [1, None, 2, 3])
        self.assertEqual(replies[1]["error"]["code"], -32700)
        self.assertFalse(replies[2]["result"]["isError"])
        self.assertIn("| vLLM |", replies[2]["result"]["content"][0]["text"])
        self.assertEqual(replies[3]["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
