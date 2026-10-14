#!/usr/bin/env python3
"""AI Stack Guard MCP server: ask GitLab Duo Agentic Chat about your AI stack from the IDE or Duo CLI.

Standard library only. Speaks the Model Context Protocol over stdio (one JSON-RPC 2.0 message per
line). Read-only: it runs the scanner and the planner, but never edits files, runs git or pushes.
Merge requests stay the flow's job. Configure it in .gitlab/duo/mcp.json.

  scan_stack            every pinned component with a known advisory, and what fails the pipeline
  plan_upgrades         the exact version edits the flow would make, sorted into auto and review groups
  component_advisories  each advisory for one component: severity, fixed versions, link
"""
import argparse
import contextlib
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guard  # noqa: E402

VERSION = "0.2.0"
PROTOCOL = "2025-06-18"
SUPPORTED = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
NO_ARGS = {"type": "object", "properties": {}, "additionalProperties": False}
TOOLS = [
    {"name": "scan_stack",
     "description": "Scan this project's pinned AI images and packages (Ollama, vLLM, Open WebUI, LiteLLM, n8n, "
                    "Flowise, Dify and more) against curated advisories plus OSV. Returns a table of affected "
                    "components and says which ones fail the pipeline under ai-stack-guard.json.",
     "inputSchema": NO_ARGS},
    {"name": "plan_upgrades",
     "description": "List the exact version edits AI Stack Guard would make (file, line, from, to, semver size) "
                    "and whether each goes to the auto-merge group or the human-review group, plus advisories "
                    "with no fixed release. Changes no files.",
     "inputSchema": NO_ARGS},
    {"name": "component_advisories",
     "description": "Show every advisory for one pinned component, for example 'vLLM' or 'open webui': "
                    "severity, fixed versions, summary and link.",
     "inputSchema": {"type": "object",
                     "properties": {"name": {"type": "string",
                                             "description": "Component name, case-insensitive; part of it is enough."}},
                     "required": ["name"], "additionalProperties": False}},
]
INSTRUCTIONS = ("Use scan_stack to see what is vulnerable, plan_upgrades to see the fix the AI Stack Guard flow "
                "would ship, and component_advisories for details on one component. Every fact comes from the "
                "scanner; quote it, never guess versions.")


class ToolError(Exception):
    pass


def result(mid, value):
    return {"jsonrpc": "2.0", "id": mid, "result": value}


def error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class Server:
    def __init__(self, scanner=guard.SCANNER_DEFAULT, policy=guard.POLICY_FILE, today=None):
        self.scanner, self.policy_path, self.today = scanner, policy, today

    def load(self):
        policy = guard.load_policy(self.policy_path)
        if self.scanner == guard.SCANNER_DEFAULT and not Path(self.scanner).is_file():
            fetch = subprocess.run([sys.executable, str(HERE / "fetch_scanner.py"), "--if-missing"],
                                   capture_output=True, text=True)
            if fetch.returncode != 0:
                raise ToolError((fetch.stderr or fetch.stdout).strip() or "could not fetch the scanner")
        today = self.today or datetime.date.today().isoformat()
        return policy, guard.build_report(guard.run_scanner(self.scanner, policy["paths"]), policy, today)

    def scan_stack(self, args):
        policy, report = self.load()
        blocked = guard.blocking(report, policy)
        text = guard.report_markdown(report, blocked)
        if blocked:
            return text + f"\n{len(blocked)} component(s) would fail the pipeline (policy block_on: {policy['block_on']}).\n"
        return text + f"\nNothing fails the pipeline (policy block_on: {policy['block_on']}).\n"

    def plan_upgrades(self, args):
        policy, report = self.load()
        planned = guard.plan(report, policy)
        lines = [f"Upgrade plan (policy auto_merge: {policy['auto_merge']}). No files were changed.", ""]
        if not planned["actions"]:
            lines += ["No upgrade can fix a known advisory right now.", ""]
        for group, heading in (("auto", "Auto group (merges itself once the second review passes):"),
                               ("review", "Review group (waits for a human):")):
            actions = [a for a in planned["actions"] if a["group"] == group]
            if not actions:
                continue
            lines.append(heading)
            for a in actions:
                note = "; the tag has a suffix, so a human checks it exists" if a["tagSuffix"] else ""
                lines.append(f"- {a['name']} `{a['file']}:{a['line']}`: {a['from']} -> {a['to']} ({a['bump']} bump, "
                             f"worst {a['severity']}; fixes {', '.join(str(i) for i in a['fixes'])}{note})")
            lines.append("")
        if planned["unfixable"]:
            lines.append("No fixed release yet (the flow opens one issue for each):")
            for u in planned["unfixable"]:
                lines.append(f"- {u['name']} {u['version']} `{u['file']}:{u['line']}`: {u['id']} ({u['severity']}) "
                             f"{u['url'] or ''}".rstrip())
            lines.append("")
        for s in planned["skipped"]:
            lines.append(f"Skipped {s['name']} `{s['file']}:{s['line']}`: {s['reason']}")
        return "\n".join(lines).rstrip() + "\n"

    def component_advisories(self, args):
        wanted = str(args.get("name") or "").strip()
        if not wanted:
            raise ToolError("give a component name, for example vLLM")
        _, report = self.load()
        found = [f for f in report["findings"] if wanted.lower() in str(f.get("name") or "").lower()]
        if not found:
            names = sorted({str(f["name"]) for f in report["findings"] if f.get("name")})
            return f"No pinned component matching '{wanted}'. Pinned components: {', '.join(names) or 'none'}.\n"
        lines = []
        for f in found:
            lines.append(f"## {f.get('name')} {f.get('version')} at `{f.get('file')}:{f.get('line')}` ({f['status']})")
            if f.get("upgradeTo"):
                lines.append(f"Upgrade to: {f['upgradeTo']}")
            if f["ignored"]:
                lines.append("Ignored by policy: " + ", ".join(str(i) for i in f["ignored"]))
            for a in f["advisories"]:
                fixed = a.get("fixedIn")
                fixed = ", ".join(str(x) for x in fixed if x) if isinstance(fixed, list) else fixed
                lines.append(f"- {a.get('id')} ({guard.severity(a.get('severity'))}): {a.get('summary') or ''} "
                             f"Fixed in: {fixed or 'no fixed release yet'}. {a.get('url') or ''}".rstrip())
            if not f["advisories"]:
                lines.append("No known advisory for this version.")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def call(self, name, args):
        tool = {"scan_stack": self.scan_stack, "plan_upgrades": self.plan_upgrades,
                "component_advisories": self.component_advisories}.get(name)
        if tool is None:
            return None
        try:
            with contextlib.redirect_stdout(sys.stderr):  # stdout carries protocol messages only
                text, failed = tool(args if isinstance(args, dict) else {}), False
        except (SystemExit, Exception) as exc:
            text, failed = f"AI Stack Guard could not answer: {exc}", True
        return {"content": [{"type": "text", "text": text}], "isError": failed}

    def handle(self, msg):
        if not isinstance(msg, dict):
            return error(None, -32600, "invalid request")
        if "method" not in msg or "id" not in msg:
            return None  # notifications and stray responses get no reply
        mid, method = msg["id"], msg["method"]
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            return result(mid, {"protocolVersion": asked if asked in SUPPORTED else PROTOCOL,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "ai-stack-guard", "version": VERSION},
                                "instructions": INSTRUCTIONS})
        if method == "ping":
            return result(mid, {})
        if method == "tools/list":
            return result(mid, {"tools": TOOLS})
        if method == "tools/call":
            reply = self.call(params.get("name"), params.get("arguments"))
            if reply is None:
                return error(mid, -32602, f"unknown tool: {params.get('name')}")
            return result(mid, reply)
        return error(mid, -32601, f"method not found: {method}")


def serve(server, stdin, stdout):
    for line in stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = error(None, -32700, "parse error")
        else:
            reply = server.handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(HERE.parent), help="project to scan (default: this checkout)")
    parser.add_argument("--scanner", default=os.environ.get("AI_STACK_SCANNER", guard.SCANNER_DEFAULT))
    parser.add_argument("--policy", default=guard.POLICY_FILE)
    args = parser.parse_args(argv)
    os.chdir(args.root)
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    serve(Server(args.scanner, args.policy), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
