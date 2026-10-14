#!/usr/bin/env python3
"""AI Stack Guard: scan, patch, verify and ship upgrades for self-hosted AI images and pins.

Wraps the ai-stack-advisories scanner (github.com/munimv2/ai-stack-advisories, MIT). Standard
library only, so it runs in GitLab's default Duo flow image and in any python CI image.

  guard.py scan     report JSON + Markdown + GitLab Code Quality report; exit 1 per policy
  guard.py run      scan, plan, patch, verify, notes and issues in one go (what the flow calls)
  guard.py ship     one branch and merge request per group, through git push options
  guard.py review   independent second check of a shipped branch; arms auto-merge if allowed

Work files go to .ai-stack-guard/ (git-ignored).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_POLICY = {
    "paths": ["."],
    "exclude": [],
    "block_on": "high",
    "unfixable_blocks": False,
    "auto_merge": "patch",
    "target_branch": "main",
    "ignore": [],
}
SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BUMP_RANK = {"none": 0, "patch": 1, "minor": 2, "major": 3}
CODE_QUALITY = {"unknown": "info", "low": "minor", "medium": "major", "high": "critical", "critical": "blocker"}
WORK = Path(".ai-stack-guard")
POLICY_FILE = "ai-stack-guard.json"
SCANNER_DEFAULT = ".ai-stack-advisories/scan_stack.py"
CHANGES_DIR = "stack-changes"
LABEL = "ai-stack-guard"
FOOTER = ("Opened by AI Stack Guard, a GitLab Duo Agent Platform flow by MV2 of Munim, Inc. "
          "The flow and this text were made with AI agents; every number above comes from the scanner.")
MR_URL_RE = re.compile(r"https?://\S+/-/merge_requests/(\d+)")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# ---------- policy and severities ----------

def load_policy(path=POLICY_FILE):
    policy = dict(DEFAULT_POLICY)
    if Path(path).is_file():
        policy.update(json.loads(Path(path).read_text(encoding="utf-8")))
    if policy["block_on"] not in ("never", "affected", *SEVERITY_RANK):
        raise SystemExit(f"{path}: block_on must be never, affected or a severity")
    if policy["auto_merge"] not in BUMP_RANK:
        raise SystemExit(f"{path}: auto_merge must be none, patch, minor or major")
    return policy


def severity(value):
    if isinstance(value, (int, float)):
        score = float(value)
        return ("critical" if score >= 9 else "high" if score >= 7 else
                "medium" if score >= 4 else "low" if score > 0 else "unknown")
    text = str(value or "").strip().lower()
    text = "medium" if text == "moderate" else text
    return text if text in SEVERITY_RANK else "unknown"


def worst(advisories):
    levels = [severity(a.get("severity")) for a in advisories]
    return max(levels, key=SEVERITY_RANK.get) if levels else None


def has_fix(advisory):
    fixed = advisory.get("fixedIn")
    return any(fixed) if isinstance(fixed, list) else bool(fixed)


def is_ignored(advisory, policy, today):
    ids = {advisory.get("id")} | set(advisory.get("aliases") or [])
    for rule in policy["ignore"]:
        if rule.get("id") in ids and (not rule.get("until") or rule["until"] >= today):
            return True
    return False


def excluded(path, prefixes):
    return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in prefixes)


# ---------- versions and line edits ----------

def version_tuple(version):
    parts = [int(x) for x in re.findall(r"\d+", str(version))[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def bump(old, new):
    """Semver size of an upgrade; on 0.x a minor change counts as major."""
    o, n = version_tuple(old), version_tuple(new)
    if n <= o:
        return "none"
    if n[0] != o[0] or (o[0] == 0 and n[1] != o[1]):
        return "major"
    return "minor" if n[1] != o[1] else "patch"


def patch_line(text, old, new):
    """Swap exactly one version token on a line. Returns (new_text, None) or (None, reason)."""
    if "@sha256:" in text:
        return None, "pinned by digest; a new digest is needed"
    pattern = re.compile(r"(?<![0-9.])" + re.escape(old) + r"(?![0-9]|\.[0-9])")
    hits = pattern.findall(text)
    if len(hits) != 1:
        return None, f"version {old} appears {len(hits)} times on the line, expected once"
    if new[:1] in "vV" and old[:1] not in "vV":
        new = new[1:]
    return pattern.sub(lambda _: new, text, count=1), None


def has_tag_suffix(kind, ref, old):
    """True for tags like v0.30.0-cu128, where the bumped tag may not exist upstream."""
    return kind == "image" and bool(re.search(re.escape(old) + r"[^\s\"'}]", ref or ""))


# ---------- scanner ----------

def run_scanner(scanner, paths, cwd=None):
    if not Path(cwd or ".", scanner).is_file() and not Path(scanner).is_file():
        raise SystemExit(f"scanner not found at {scanner}; run guard/fetch_scanner.py first")
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    proc = subprocess.run([sys.executable, str(Path(scanner).resolve()), *paths, "--json", "--fail-on", "never"],
                          capture_output=True, text=True, cwd=cwd, env=env)
    if proc.returncode != 0:
        raise SystemExit(f"scanner failed ({proc.returncode}): {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def build_report(raw, policy, today):
    findings = []
    for f in raw.get("findings", []):
        if excluded(f.get("file", ""), policy["exclude"]):
            continue
        kept, ignored = [], []
        for adv in f.get("advisories") or []:
            (ignored if is_ignored(adv, policy, today) else kept).append(adv)
        status = f.get("status", "ok")
        if status == "affected" and not kept:
            status = "ignored"
        findings.append({**f, "status": status, "advisories": kept, "severity": worst(kept),
                         "ignored": [a.get("id") for a in ignored],
                         "fixable": [a.get("id") for a in kept if has_fix(a)],
                         "unfixed": [a.get("id") for a in kept if not has_fix(a)]})
    return {"curatedDataAsOf": raw.get("curatedDataAsOf"), "date": today, "findings": findings}


def blocking(report, policy, changed=None):
    """Affected findings that fail the pipeline. `changed` limits it to {(file, line)} of an MR diff."""
    level = policy["block_on"]
    if level == "never":
        return []
    out = []
    for f in report["findings"]:
        if f["status"] != "affected" or (changed is not None and (f["file"], f["line"]) not in changed):
            continue
        ids = set(f["fixable"]) | (set(f["unfixed"]) if policy["unfixable_blocks"] else set())
        advs = [a for a in f["advisories"] if a.get("id") in ids]
        if level != "affected":
            advs = [a for a in advs if SEVERITY_RANK[severity(a.get("severity"))] >= SEVERITY_RANK[level]]
        if advs:
            out.append(f)
    return out


def code_quality(report):
    entries = []
    for f in report["findings"]:
        for a in f["advisories"]:
            fixed = a.get("fixedIn")
            fixed = ", ".join(fixed) if isinstance(fixed, list) else fixed
            entries.append({
                "description": f"{f.get('name')} {f.get('version')}: {a.get('id')} ({severity(a.get('severity'))}), "
                               + (f"fixed in {fixed}" if fixed else "no fixed release yet"),
                "check_name": "ai-stack-advisory",
                "fingerprint": hashlib.sha1(f"{f['file']}:{f['line']}:{a.get('id')}".encode()).hexdigest(),
                "severity": CODE_QUALITY[severity(a.get("severity"))],
                "location": {"path": f["file"], "lines": {"begin": f["line"]}},
            })
    return entries


def report_markdown(report, blocked):
    affected = [f for f in report["findings"] if f["status"] == "affected"]
    lines = [f"## AI Stack Guard scan ({report['date']}, advisory data as of {report['curatedDataAsOf']})", ""]
    if not affected:
        lines.append("No pinned component has a known advisory.")
    else:
        lines += ["| Component | Where | Version | Worst | Fixable | No fix yet | Upgrade to | Blocks |",
                  "|---|---|---|---|---|---|---|---|"]
        for f in affected:
            lines.append(f"| {f.get('name')} | `{f['file']}:{f['line']}` | {f.get('version')} | {f['severity']} | "
                         f"{len(f['fixable'])} | {len(f['unfixed'])} | {f.get('upgradeTo') or '-'} | "
                         f"{'yes' if f in blocked else 'no'} |")
    unpinned = [f for f in report["findings"] if f["status"] == "unpinned"]
    if unpinned:
        lines += ["", "Unpinned (cannot be checked): " + ", ".join(f"`{f['file']}:{f['line']}`" for f in unpinned)]
    return "\n".join(lines) + "\n"


# ---------- plan, patch, verify ----------

def plan(report, policy):
    actions, unfixable, skipped = [], [], []
    for f in report["findings"]:
        if f["status"] != "affected":
            continue
        for a in f["advisories"]:
            if a.get("id") in f["unfixed"]:
                unfixable.append({"file": f["file"], "line": f["line"], "name": f.get("name"),
                                  "version": f.get("version"), "id": a.get("id"),
                                  "severity": severity(a.get("severity")), "summary": a.get("summary"),
                                  "url": a.get("url"), "onlyIfFeatureUsed": a.get("onlyIfFeatureUsed")})
        if not f["fixable"]:
            continue
        target = f.get("upgradeTo")
        size = bump(f.get("version"), target) if target else "none"
        if size == "none":
            skipped.append({"file": f["file"], "line": f["line"], "name": f.get("name"),
                            "reason": "the scanner gave no newer fixed version"})
            continue
        suffix = has_tag_suffix(f.get("kind"), f.get("ref"), f.get("version"))
        auto = BUMP_RANK[size] <= BUMP_RANK[policy["auto_merge"]] and not suffix
        actions.append({"file": f["file"], "line": f["line"], "kind": f.get("kind"), "name": f.get("name"),
                        "ref": f.get("ref"), "from": f.get("version"), "to": target, "bump": size,
                        "tagSuffix": suffix, "group": "auto" if auto else "review",
                        "severity": worst([a for a in f["advisories"] if a.get("id") in f["fixable"]]),
                        "fixes": f["fixable"], "stillOpen": f["unfixed"]})
    return {"actions": actions, "unfixable": unfixable, "skipped": skipped}


def apply_actions(actions, root="."):
    applied, skipped = [], []
    by_file = {}
    for a in actions:
        by_file.setdefault(a["file"], []).append(a)
    for name, items in by_file.items():
        path = Path(root, name)
        with open(path, encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines(keepends=True)
        changed = False
        for a in items:
            if not 0 < a["line"] <= len(lines):
                skipped.append({**a, "reason": "line no longer exists"})
                continue
            new, reason = patch_line(lines[a["line"] - 1], a["from"], a["to"])
            if reason:
                skipped.append({**a, "reason": reason})
                continue
            lines[a["line"] - 1] = new
            applied.append(a)
            changed = True
        if changed:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write("".join(lines))
    return {"applied": applied, "skipped": skipped}


def verify(applied, before, after):
    """Every patched line must still be recognised and have no fixable advisory left."""
    now = {(f["file"], f["line"]): f for f in after["findings"]}
    was = {(f["file"], f["line"]) for f in before["findings"] if f["status"] == "affected"}
    rows, ok = [], True
    for a in applied:
        f = now.get((a["file"], a["line"]))
        passed = f is not None and not f["fixable"]
        ok &= passed
        rows.append({"file": a["file"], "line": a["line"], "name": a["name"], "from": a["from"],
                     "to": f.get("version") if f else None, "fixed": len(a["fixes"]),
                     "stillOpen": f["unfixed"] if f else [], "passed": passed,
                     "why": "" if passed else ("scanner no longer recognises the line" if f is None
                                               else "advisories still fixable: " + ", ".join(f["fixable"]))})
    new = [f"{f['file']}:{f['line']}" for f in after["findings"]
           if f["status"] == "affected" and (f["file"], f["line"]) not in was]
    return {"passed": ok and not new and bool(applied), "rows": rows, "newlyAffected": new}


# ---------- notes, issues ----------

def group_slug(actions):
    key = "|".join(sorted(f"{a['file']}:{a['line']}:{a['to']}" for a in actions))
    return hashlib.sha1(key.encode()).hexdigest()[:8]


def evidence_table(rows):
    out = ["| Component | Where | Before | After | Advisories fixed | Still open | Check |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['name']} | `{r['file']}:{r['line']}` | {r['from']} | {r['to']} | {r['fixed']} | "
                   f"{', '.join(r['stillOpen']) or '-'} | {'passed' if r['passed'] else 'FAILED: ' + r['why']} |")
    return "\n".join(out)


def notes(planned, patched, verified, policy, report, today):
    applied = {(a["file"], a["line"]) for a in patched["applied"]}
    rows = {(r["file"], r["line"]): r for r in verified["rows"]}
    groups = []
    for group in ("auto", "review"):
        actions = [a for a in planned["actions"] if a["group"] == group and (a["file"], a["line"]) in applied]
        if not actions:
            continue
        slug = group_slug(actions)
        count = sum(len(a["fixes"]) for a in actions)
        fixed = f"{count} {'advisory' if count == 1 else 'advisories'}"
        if len(actions) == 1:
            a = actions[0]
            title = f"Upgrade {a['name']} {a['from']} to {a['to']} ({fixed})"
        else:
            title = f"Upgrade {len(actions)} AI stack components ({fixed})"
        if group == "auto":
            control = (f"Auto-merge: armed only after the second review passes, because every bump here is "
                       f"within the policy limit (`auto_merge: {policy['auto_merge']}`).")
        else:
            reasons = sorted({f"{a['name']} {a['from']} to {a['to']} is a {a['bump']} bump"
                              + (" with a tag suffix that may not exist upstream" if a["tagSuffix"] else "")
                              for a in actions})
            control = (f"Needs a human merge: {'; '.join(reasons)}, and the policy auto-merges up to "
                       f"`{policy['auto_merge']}` bumps.")
        body = [f"### {title}", "",
                f"Advisory data as of {report['curatedDataAsOf']}. Scanned {today}.", "",
                evidence_table([rows[(a["file"], a["line"])] for a in actions]), "", control, ""]
        fixes = "\n".join(f"- {a['name']}: " + ", ".join(a["fixes"]) for a in actions)
        body += ["Advisories fixed:", fixes, "", FOOTER]
        changelog = "\n".join([f"# {title}", "", f"Date: {today}", "",
                               evidence_table([rows[(a["file"], a["line"])] for a in actions]), "",
                               "Advisories fixed:", fixes, ""])
        groups.append({"group": group, "title": title, "branch": f"{LABEL}/{today}-{group}-{slug}",
                       "changelogPath": f"{CHANGES_DIR}/{today}-{group}-{slug}.md", "changelog": changelog,
                       "description": "\n".join(body) + "\n", "autoMerge": group == "auto",
                       "actions": actions})
    return {"targetBranch": policy["target_branch"], "groups": groups}


def issues(planned, today):
    out = []
    for u in planned["unfixable"]:
        lines = [f"`{u['file']}:{u['line']}` pins {u['name']} {u['version']}, which is affected by "
                 f"[{u['id']}]({u['url']}) (severity: {u['severity']}). No release fixes it yet, so an "
                 "upgrade cannot help.", "", f"Summary: {u['summary'] or 'see the advisory'}", ""]
        if u.get("onlyIfFeatureUsed"):
            lines += [f"Only matters if you use: {u['onlyIfFeatureUsed']}", ""]
        lines += ["What to do now:",
                  "- Keep the service off public networks and behind authentication.",
                  "- Turn off the affected feature if you do not need it.",
                  f"- Once mitigated, record it in `{POLICY_FILE}` under `ignore` with an `until` date, "
                  "so the decision expires and comes back for review.", "",
                  f"AI Stack Guard will propose the upgrade as soon as a fixed release appears. Found {today}.",
                  "", FOOTER]
        out.append({"title": f"AI Stack Guard: {u['name']} {u['version']} has no fixed release for {u['id']}",
                    "description": "\n".join(lines) + "\n",
                    "labels": [LABEL, f"severity::{u['severity']}"]})
    return out


# ---------- git ----------

def git(*args, cwd=None, check=True):
    proc = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd)
    if check and proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def identity_args():
    if git("config", "user.email", check=False).stdout.strip():
        return []
    return ["-c", "user.name=AI Stack Guard", "-c", "user.email=ai-stack-guard@users.noreply.gitlab.com"]


def push_command(group, target, arm=False):
    cmd = ["git", "push", "origin", f"HEAD:refs/heads/{group['branch']}"]
    if arm:
        return cmd + ["-o", "merge_request.merge_when_pipeline_succeeds"]
    summary = f"{group['title']}. Evidence is in the first comment."
    return cmd + ["-o", "merge_request.create", "-o", f"merge_request.target={target}",
                  "-o", f"merge_request.title={group['title']}", "-o", f"merge_request.description={summary}",
                  "-o", f"merge_request.label={LABEL}", "-o", "merge_request.remove_source_branch"]


def diff_lines(base, head="HEAD", cwd=None):
    """{(file, new_line)} added or changed between base and head."""
    out = git("diff", "--unified=0", "--no-color", f"{base}...{head}", cwd=cwd).stdout
    return parse_diff(out)


def parse_diff(text):
    changed, current = set(), None
    for line in text.splitlines():
        if line.startswith("+++ "):
            current = None if line[4:] == "/dev/null" else line[4:].split("/", 1)[-1]
        m = HUNK_RE.match(line)
        if m and current:
            start, count = int(m.group(3)), int(m.group(4) or 1)
            changed |= {(current, n) for n in range(start, start + count)}
    return changed


def ship(notes_doc, dry_run=False):
    target = notes_doc["targetBranch"]
    results = []
    base = None if dry_run else git("rev-parse", "HEAD").stdout.strip()
    for g in notes_doc["groups"]:
        cmd = push_command(g, target)
        if dry_run:
            results.append({"group": g["group"], "branch": g["branch"], "command": cmd})
            continue
        if git("ls-remote", "--exit-code", "--heads", "origin", g["branch"], check=False).returncode == 0:
            results.append({"group": g["group"], "branch": g["branch"], "status": "already proposed"})
            continue
        git("checkout", "--quiet", "-B", g["branch"], base)
        git("checkout", "--quiet", base, "--", *sorted({a["file"] for a in g["actions"]}))
        done = apply_actions(g["actions"])
        Path(g["changelogPath"]).parent.mkdir(parents=True, exist_ok=True)
        Path(g["changelogPath"]).write_text(g["changelog"], encoding="utf-8")
        git("add", "--", *sorted({a["file"] for a in done["applied"]}), g["changelogPath"])
        git(*identity_args(), "commit", "--quiet", "-m", g["title"], "-m", FOOTER)
        proc = git(*cmd[1:])
        m = MR_URL_RE.search(proc.stderr + proc.stdout)
        Path(WORK, f"mr-{g['group']}.md").write_text(g["description"], encoding="utf-8")
        results.append({"group": g["group"], "branch": g["branch"], "status": "opened",
                        "mergeRequestUrl": m.group(0) if m else None, "mergeRequestIid": int(m.group(1)) if m else None,
                        "skipped": done["skipped"], "notePath": str(Path(WORK, f"mr-{g['group']}.md"))})
        git("checkout", "--quiet", "--detach", base)
    return {"targetBranch": target, "mergeRequests": results}


def review(group, notes_doc, scanner, policy, today, arm=False):
    """Check a pushed branch from scratch: only planned lines changed, each to the planned text, and fixed."""
    target, branch = notes_doc["targetBranch"], group["branch"]
    git("fetch", "--quiet", "origin", target, branch)
    expected, problems = {}, []
    def line_at(ref, file, line):
        lines = git("show", f"{ref}:{file}", check=False).stdout.splitlines()
        return lines[line - 1] if 0 < line <= len(lines) else None

    for a in group["actions"]:
        original = line_at(f"origin/{target}", a["file"], a["line"])
        new, reason = patch_line(original, a["from"], a["to"]) if original is not None else (None, "line missing")
        expected[(a["file"], a["line"])] = new
        if reason:
            problems.append(f"{a['file']}:{a['line']}: {reason}")
    for file, line in sorted(diff_lines(f"origin/{target}", f"origin/{branch}")):
        if file.startswith(CHANGES_DIR + "/"):
            continue
        if expected.get((file, line)) != line_at(f"origin/{branch}", file, line):
            problems.append(f"{file}:{line} changed but does not match the plan")
    workdir = tempfile.mkdtemp(prefix="ai-stack-review-")
    try:
        git("worktree", "add", "--quiet", "--detach", workdir, f"origin/{branch}")
        after = build_report(run_scanner(Path(scanner).resolve(), policy["paths"], cwd=workdir), policy, today)
    finally:
        git("worktree", "remove", "--force", workdir, check=False)
        shutil.rmtree(workdir, ignore_errors=True)
    before = {"findings": []}
    checked = verify(group["actions"], before, {"findings": after["findings"]})
    passed = not problems and all(r["passed"] for r in checked["rows"])
    armed = False
    if passed and arm and group["autoMerge"]:
        git("checkout", "--quiet", "-B", branch, f"origin/{branch}")
        git(*identity_args(), "commit", "--quiet", "--allow-empty", "-m",
            "Second review passed: arm auto-merge", "-m", FOOTER)
        git(*push_command(group, target, arm=True)[1:])
        armed = True
    text = [f"### Second review: {'passed' if passed else 'FAILED'}", "",
            "Checked from a fresh worktree of the pushed branch: only planned lines changed, each to the "
            "planned version, and a rescan finds no fixable advisory on them.", "",
            evidence_table(checked["rows"]), ""]
    if problems:
        text += ["Problems:"] + [f"- {p}" for p in problems] + ["", "Do not merge this as it stands.", ""]
    if group["autoMerge"]:
        text.append("Auto-merge armed: it merges when the pipeline passes." if armed else
                    "Auto-merge not armed.")
    text += ["", FOOTER]
    return {"group": group["group"], "branch": branch, "passed": passed, "armed": armed,
            "problems": problems, "note": "\n".join(text) + "\n"}


# ---------- commands ----------

def write(name, data):
    WORK.mkdir(exist_ok=True)
    path = WORK / name
    path.write_text(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def read(name):
    return json.loads((WORK / name).read_text(encoding="utf-8"))


def do_scan(args, policy, today):
    report = build_report(run_scanner(args.scanner, policy["paths"]), policy, today)
    changed = diff_lines(args.changed_since) if args.changed_since else None
    blocked = blocking(report, policy, changed)
    md = report_markdown(report, blocked)
    write("report.json", report)
    write("report.md", md)
    Path(args.code_quality).write_text(json.dumps(code_quality(report), indent=2) + "\n", encoding="utf-8")
    print(md)
    if blocked:
        print(f"{len(blocked)} component(s) block this pipeline (policy block_on: {policy['block_on']}).")
    return report, blocked


def do_run(args, policy, today):
    before, blocked = do_scan(args, policy, today)
    planned = plan(before, policy)
    patched = apply_actions(planned["actions"])
    after = build_report(run_scanner(args.scanner, policy["paths"]), policy, today)
    verified = verify(patched["applied"], before, after)
    doc = notes(planned, patched, verified, policy, before, today)
    found = issues(planned, today)
    for name, data in (("plan.json", planned), ("patch.json", patched), ("verify.json", verified),
                       ("notes.json", doc), ("issues.json", found)):
        write(name, data)
    files = sorted({a["file"] for a in patched["applied"]})
    if files and Path(".git").exists():
        git("checkout", "--quiet", "--", *files, check=False)  # ship re-applies each group from a clean base
    if not planned["actions"]:
        nxt = "nothing to do"
    elif not verified["passed"]:
        nxt = "verify failed: see .ai-stack-guard/verify.json"
    else:
        nxt = "ship"
    summary = {"blocking": len(blocked), "actions": len(planned["actions"]), "applied": len(patched["applied"]),
               "skipped": [f"{s['file']}:{s['line']} {s['reason']}" for s in patched["skipped"] + planned["skipped"]],
               "verified": verified["passed"], "groups": [{"group": g["group"], "title": g["title"],
                                                            "branch": g["branch"]} for g in doc["groups"]],
               "issues": [i["title"] for i in found], "next": nxt}
    print(json.dumps(summary, indent=2))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["scan", "run", "ship", "review"])
    parser.add_argument("--scanner", default=os.environ.get("AI_STACK_SCANNER", SCANNER_DEFAULT))
    parser.add_argument("--policy", default=POLICY_FILE)
    parser.add_argument("--changed-since", help="scan: block only on lines changed since this commit (MR pipelines)")
    parser.add_argument("--code-quality", default="gl-code-quality-report.json")
    parser.add_argument("--group", choices=["auto", "review"], help="review: which shipped group")
    parser.add_argument("--arm", action="store_true", help="review: arm auto-merge if the review passes")
    parser.add_argument("--dry-run", action="store_true", help="ship: print the git commands only")
    parser.add_argument("--today", default=datetime.date.today().isoformat())
    args = parser.parse_args(argv)
    policy = load_policy(args.policy)

    if args.command == "scan":
        _, blocked = do_scan(args, policy, args.today)
        return 1 if blocked else 0
    if args.command == "run":
        return 1 if do_run(args, policy, args.today)["next"].startswith("verify failed") else 0
    if args.command == "ship":
        result = ship(read("notes.json"), dry_run=args.dry_run)
        write("ship.json", result)
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "review":
        doc = read("notes.json")
        groups = [g for g in doc["groups"] if args.group in (None, g["group"])]
        results = [review(g, doc, args.scanner, policy, args.today, arm=args.arm) for g in groups]
        for r in results:
            write(f"review-{r['group']}.md", r["note"])
        write("review.json", results)
        print(json.dumps([{k: v for k, v in r.items() if k != "note"} for r in results], indent=2))
        return 0 if all(r["passed"] for r in results) else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
