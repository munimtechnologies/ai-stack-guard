import contextlib
import io
import json
import os
import re
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
import guard  # noqa: E402
import sbom  # noqa: E402

TODAY = "2026-10-14"


def adv(i, sev, fixed, aliases=()):
    return {"id": i, "aliases": list(aliases), "severity": sev, "fixedIn": fixed, "summary": "test advisory " + i,
            "url": "https://example.test/" + i, "notInPublicDatabases": False, "onlyIfFeatureUsed": None}


def finding(file, line, kind, ref, name, version, advisories, upgrade=None, status=None):
    return {"file": file, "line": line, "kind": kind, "ref": ref, "product": name.lower(), "name": name,
            "version": version, "range": False, "status": status or ("affected" if advisories else "ok"),
            "advisories": advisories, "upgradeTo": upgrade,
            "noFixedRelease": sum(1 for a in advisories if not a["fixedIn"])}


RAW = {"curatedDataAsOf": "2026-10-13", "findings": [
    finding("demo/compose.yaml", 3, "image", "vllm/vllm-openai:v0.30.0", "vLLM", "0.30.0",
            [adv("GHSA-aaaa", "high", "0.31.0", ["CVE-2026-0001"])], "0.31.0"),
    finding("demo/compose.yaml", 5, "image", "ghcr.io/open-webui/open-webui:v0.11.3", "Open WebUI", "0.11.3",
            [adv("GHSA-cccc", "critical", ["0.11.4"]), adv("GHSA-eeee", "low", "0.11.4")], "0.11.4"),
    finding("demo/compose.yaml", 7, "image", "flowiseai/flowise:3.1.4", "Flowise", "3.1.4",
            [adv("GHSA-dddd", "moderate", None)]),
    finding("deploy/compose.prod.yaml", 9, "image", '"vllm/vllm-openai:v0.30.0"', "vLLM", "0.30.0",
            [adv("GHSA-aaaa", "high", "0.31.0", ["CVE-2026-0001"])], "0.31.0"),
    finding("requirements.txt", 2, "pypi", "LiteLLM==1.74.0", "LiteLLM", "1.74.0", []),
    finding("package.json", 12, "npm", "@scope/flow-sdk@^2.1.0", "Flow SDK", "2.1.0", []),
    finding("demo/compose.yaml", 9, "image", "ollama/ollama:latest", "Ollama", None, [], status="unpinned"),
]}


class FakeResponse:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class SbomTest(unittest.TestCase):
    def setUp(self):
        policy = {**guard.DEFAULT_POLICY, "ignore": [{"id": "GHSA-eeee", "until": "2026-12-31"}]}
        self.report = guard.build_report(RAW, policy, TODAY)
        self.bom = sbom.build(self.report, "munim/ai-stack-guard", now="2026-10-14T06:00:00Z")
        self.components = {c["bom-ref"]: c for c in self.bom["components"]}
        self.vulns = {v["id"]: v for v in self.bom["vulnerabilities"]}

    def props(self, ref, name):
        return [p["value"] for p in self.components[ref]["properties"] if p["name"] == "ai-stack-guard:" + name]

    def test_parse_image(self):
        self.assertEqual(sbom.parse_image("vllm/vllm-openai:v0.30.0"), (None, "vllm/vllm-openai", "v0.30.0"))
        self.assertEqual(sbom.parse_image("ghcr.io/open-webui/open-webui:v0.11.3"),
                         ("ghcr.io", "open-webui/open-webui", "v0.11.3"))
        self.assertEqual(sbom.parse_image("localhost:5000/team/x:1.2"), ("localhost:5000", "team/x", "1.2"))
        self.assertEqual(sbom.parse_image("docker.io/library/redis:7.2"), (None, "redis", "7.2"))
        self.assertEqual(sbom.parse_image("'ollama/ollama:0.12.6'  # pinned"), (None, "ollama/ollama", "0.12.6"))
        self.assertEqual(sbom.parse_image("x:1.0@sha256:abc"), (None, "x", "1.0"))
        self.assertEqual(sbom.parse_image("x:${TAG:-v0.30.0}"), (None, "x", "${TAG:-v0.30.0}"))
        self.assertEqual(sbom.parse_image("ollama/ollama"), (None, "ollama/ollama", None))

    def test_document_shape(self):
        self.assertEqual((self.bom["bomFormat"], self.bom["specVersion"], self.bom["version"]), ("CycloneDX", "1.5", 1))
        self.assertRegex(self.bom["serialNumber"], r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        meta = self.bom["metadata"]
        self.assertEqual(meta["timestamp"], "2026-10-14T06:00:00Z")
        self.assertEqual(meta["component"]["name"], "munim/ai-stack-guard")
        self.assertEqual(meta["tools"]["components"][0]["version"], sbom.VERSION)
        self.assertIn({"name": "ai-stack-guard:advisoryDataAsOf", "value": "2026-10-13"}, meta["properties"])
        json.dumps(self.bom)  # serialisable as is
        refs = set(self.components)
        self.assertEqual(set(self.bom["dependencies"][0]["dependsOn"]), refs)
        for v in self.bom["vulnerabilities"]:
            for a in v["affects"]:
                self.assertIn(a["ref"], refs)

    def test_components_and_purls(self):
        self.assertEqual(sorted(self.components), sorted([
            "pkg:docker/vllm/vllm-openai@v0.30.0",
            "pkg:docker/open-webui/open-webui@v0.11.3?repository_url=ghcr.io",
            "pkg:docker/flowiseai/flowise@3.1.4",
            "pkg:pypi/litellm@1.74.0",
            "pkg:npm/%40scope/flow-sdk@2.1.0",
            "pkg:docker/ollama/ollama@latest",
        ]))
        webui = self.components["pkg:docker/open-webui/open-webui@v0.11.3?repository_url=ghcr.io"]
        self.assertEqual((webui["type"], webui["name"], webui["version"]), ("container", "ghcr.io/open-webui/open-webui", "v0.11.3"))
        self.assertEqual(self.components["pkg:pypi/litellm@1.74.0"]["type"], "library")
        # The same image pinned in two files is one component with both locations.
        vllm = "pkg:docker/vllm/vllm-openai@v0.30.0"
        self.assertEqual(self.props(vllm, "location"), ["demo/compose.yaml:3", "deploy/compose.prod.yaml:9"])
        self.assertEqual(self.props(vllm, "upgradeTo"), ["0.31.0"])
        self.assertEqual(self.props("pkg:docker/ollama/ollama@latest", "status"), ["unpinned"])

    def test_vulnerabilities(self):
        self.assertEqual(sorted(self.vulns), ["GHSA-aaaa", "GHSA-cccc", "GHSA-dddd"])
        aaaa = self.vulns["GHSA-aaaa"]
        self.assertEqual([a["ref"] for a in aaaa["affects"]], ["pkg:docker/vllm/vllm-openai@v0.30.0"])
        self.assertEqual(aaaa["ratings"], [{"severity": "high", "method": "other"}])
        self.assertEqual(aaaa["references"], [{"id": "CVE-2026-0001",
                                               "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}}])
        self.assertEqual(aaaa["recommendation"], "Upgrade to 0.31.0 or later.")
        self.assertEqual(self.vulns["GHSA-cccc"]["ratings"][0]["severity"], "critical")
        dddd = self.vulns["GHSA-dddd"]
        self.assertEqual(dddd["ratings"][0]["severity"], "medium")
        self.assertTrue(dddd["recommendation"].startswith("No fixed release yet"))
        # An ignored advisory is not reported as open, but the component still records the decision.
        self.assertEqual(self.props("pkg:docker/open-webui/open-webui@v0.11.3?repository_url=ghcr.io", "ignored"),
                         ["GHSA-eeee"])

    def test_build_command(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                guard.write("report.json", self.report)
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(sbom.main(["build"]), 0)
                self.assertIn("6 components, 3 open advisories", out.getvalue())
                bom = json.loads(Path(sbom.SBOM_FILE).read_text(encoding="utf-8"))
                self.assertEqual(len(bom["components"]), 6)
            finally:
                os.chdir(old)

    def test_publish_uploads_with_job_token(self):
        sent = []

        def opener(req, timeout):
            sent.append(req)
            return FakeResponse()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "bom.json")
            path.write_text("{}", encoding="utf-8")
            env = {"CI_API_V4_URL": "https://gitlab.com/api/v4", "CI_PROJECT_ID": "123", "CI_JOB_TOKEN": "t"}
            result = sbom.publish({str(path): sbom.SBOM_FILE}, "stack-42", env=env, opener=opener)
            self.assertEqual(sent[0].get_method(), "PUT")
            self.assertEqual(sent[0].full_url, "https://gitlab.com/api/v4/projects/123/packages/generic/"
                                               "ai-stack-sbom/stack-42/gl-sbom-ai-stack.cdx.json")
            self.assertEqual(sent[0].get_header("Job-token"), "t")
            self.assertEqual(result["files"][0]["status"], 201)
            with self.assertRaises(SystemExit):
                sbom.publish({str(path): sbom.SBOM_FILE}, "stack..42", env=env, opener=opener)
            with self.assertRaises(SystemExit) as ctx:
                sbom.publish({str(path): sbom.SBOM_FILE}, "stack-42", env={}, opener=opener)
            self.assertIn("CI_JOB_TOKEN", str(ctx.exception))
            self.assertEqual(len(sent), 1)

    def test_pipeline_runs_the_package_stage(self):
        ci = HERE / ".gitlab-ci.yml"
        if not ci.is_file():
            self.skipTest("pipeline file not in this checkout")
        text = ci.read_text(encoding="utf-8")
        self.assertIn("stages: [secure, verify, package, release]", text)
        self.assertIn('python3 guard/sbom.py publish --package-version "stack-$CI_PIPELINE_IID"', text)
        self.assertIn("cyclonedx: gl-sbom-ai-stack.cdx.json", text)
        self.assertIn("packages/generic/ai-stack-sbom/stack-$CI_PIPELINE_IID/gl-sbom-ai-stack.cdx.json", text)
        tests = re.search(r"python3 -m unittest -v (.+)", text).group(1).split()
        self.assertEqual(sorted(tests), ["test_api_ship.py", "test_guard.py", "test_mcp_server.py", "test_sbom.py"])


if __name__ == "__main__":
    unittest.main()
