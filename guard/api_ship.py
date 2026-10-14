#!/usr/bin/env python3
"""AI Stack Guard API fallback: open the same merge requests with GitLab's own tools, no git push.

`guard.py ship` pushes each group with git push options. If that push is refused inside the flow's
session, or GitLab ignores the push options, the guard agent opens the merge requests with the
create_branch, create_commit and create_merge_request tools instead. This script prepares exactly
what those tools need, from the files `guard.py run` wrote:

  .ai-stack-guard/api/<group>/files/<repo path>   each changed file in full, plus the changelog entry
  .ai-stack-guard/api/<group>.json                branch, target, commit message, MR title and description
  .ai-stack-guard/mr-<group>.md                   the evidence comment, the same text ship posts

Every file is built with the same edit function and the same verified plan as ship, so the reviewer
can check an API-made branch exactly like a pushed one. It never edits the checkout, runs git or calls
GitLab, and it prepares nothing that failed verification.
"""
import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guard  # noqa: E402

API_DIR = guard.WORK / "api"


def push_option(group, target, key):
    """The value ship would send as a push option, so both paths open identical merge requests."""
    prefix = f"merge_request.{key}="
    return next(o[len(prefix):] for o in guard.push_command(group, target) if o.startswith(prefix))


def read_exact(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write_exact(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def prepare(notes_doc, verified, root=".", out=API_DIR):
    if not verified.get("passed"):
        raise SystemExit("verification failed; nothing prepared (see .ai-stack-guard/verify.json)")
    target = notes_doc["targetBranch"]
    shutil.rmtree(out, ignore_errors=True)
    results = []
    for g in notes_doc["groups"]:
        names = sorted({a["file"] for a in g["actions"]})
        with tempfile.TemporaryDirectory(prefix="ai-stack-api-") as tmp:
            for name in names:
                write_exact(Path(tmp, name), read_exact(Path(root, name)))
            done = guard.apply_actions(g["actions"], root=tmp)
            changed = sorted({a["file"] for a in done["applied"]})
            contents = {name: read_exact(Path(tmp, name)) for name in changed}
        entry = {"group": g["group"], "branch": g["branch"],
                 "skipped": [f"{s['file']}:{s['line']} {s['reason']}" for s in done["skipped"]]}
        if not changed:
            results.append({**entry, "status": "nothing to change"})
            continue
        files = []
        for name in changed:
            write_exact(Path(out, g["group"], "files", name), contents[name])
            files.append({"action": "update", "filePath": name,
                          "readFrom": Path(out, g["group"], "files", name).as_posix()})
        write_exact(Path(out, g["group"], "files", g["changelogPath"]), g["changelog"])
        files.append({"action": "create", "filePath": g["changelogPath"],
                      "readFrom": Path(out, g["group"], "files", g["changelogPath"]).as_posix()})
        note = guard.write(f"mr-{g['group']}.md", g["description"])
        doc = {**entry, "status": "prepared", "startBranch": target, "targetBranch": target,
               "commitMessage": f"{g['title']}\n\n{guard.FOOTER}", "files": files,
               "mergeRequest": {"title": push_option(g, target, "title"),
                                "description": push_option(g, target, "description"),
                                "labels": [guard.LABEL], "removeSourceBranch": True},
               "autoMerge": g["autoMerge"], "notePath": note.as_posix()}
        write_exact(Path(out, f"{g['group']}.json"), json.dumps(doc, indent=2) + "\n")
        results.append({**entry, "status": "prepared", "plan": Path(out, f"{g['group']}.json").as_posix(),
                        "files": [f["filePath"] for f in files], "notePath": note.as_posix()})
    return {"targetBranch": target, "groups": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="checkout to read the unpatched files from")
    args = parser.parse_args(argv)
    result = prepare(guard.read("notes.json"), guard.read("verify.json"), root=args.root)
    guard.write("api.json", result)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
