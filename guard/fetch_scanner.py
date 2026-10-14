#!/usr/bin/env python3
"""Fetch the ai-stack-advisories scanner and its curated data (MIT, github.com/munimv2/ai-stack-advisories).

Tries GitHub first. Duo flow sandboxes can only reach the GitLab instance, so it falls back to the
copy the ai-stack-scan CI job keeps as an artifact of this public project.
"""
import argparse
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

GITHUB = "https://raw.githubusercontent.com/munimv2/ai-stack-advisories/{ref}/{name}"
ARTIFACT = "{base}/api/v4/projects/{project}/jobs/artifacts/{branch}/raw/{path}?job=ai-stack-scan"
FILES = ("scan_stack.py", "advisories.json", "LICENSE")


def download(url):
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default=os.environ.get("AI_STACK_ADVISORIES_REF", "main"))
    parser.add_argument("--dest", default=os.environ.get("AI_STACK_ADVISORIES_DIR", ".ai-stack-advisories"))
    parser.add_argument("--if-missing", action="store_true", help="do nothing if the scanner is already there")
    parser.add_argument("--gitlab-project-id", help="fallback: project whose ai-stack-scan artifacts hold a copy")
    parser.add_argument("--gitlab-branch", default="main")
    args = parser.parse_args(argv)

    dest = Path(args.dest)
    if args.if_missing and all((dest / name).is_file() for name in FILES):
        print(f"scanner already in {dest}/")
        return 0
    dest.mkdir(parents=True, exist_ok=True)
    base = os.environ.get("GITLAB_BASE_URL") or os.environ.get("CI_SERVER_URL") or "https://gitlab.com"
    errors = []
    for source in ("github", "gitlab"):
        if source == "gitlab" and not args.gitlab_project_id:
            break
        try:
            for name in FILES:
                if source == "github":
                    url = GITHUB.format(ref=args.ref, name=name)
                else:
                    url = ARTIFACT.format(base=base.rstrip("/"), project=urllib.parse.quote(args.gitlab_project_id, safe=""),
                                          branch=args.gitlab_branch, path=f"{dest.as_posix()}/{name}")
                (dest / name).write_bytes(download(url))
            print(f"scanner fetched from {source} into {dest}/")
            return 0
        except OSError as exc:
            errors.append(f"{source}: {exc}")
    print("could not fetch the scanner: " + "; ".join(errors), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
