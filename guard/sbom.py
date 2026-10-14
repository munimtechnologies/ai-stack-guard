#!/usr/bin/env python3
"""AI Stack Guard package step: the scanned AI stack as a CycloneDX SBOM in GitLab's package registry.

  sbom.py build                          .ai-stack-guard/report.json -> gl-sbom-ai-stack.cdx.json
  sbom.py publish --package-version V    upload the SBOM and the scan report as generic package V

The SBOM (CycloneDX 1.5) lists every AI component the scanner recognised: images as containers,
PyPI and npm pins as libraries, each with a purl, where it is pinned, and the advisories still open on
it with their fixed versions. `build` runs after `guard.py scan`. `publish` runs in GitLab CI and
uses the job token (CI_API_V4_URL, CI_PROJECT_ID, CI_JOB_TOKEN). Standard library only.
"""
import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guard  # noqa: E402

VERSION = "0.4.0"
SBOM_FILE = "gl-sbom-ai-stack.cdx.json"
PACKAGE = "ai-stack-sbom"
PROP = "ai-stack-guard:"
TAG_RE = re.compile(r"[\w][\w.+-]*")
PACKAGE_VERSION_RE = re.compile(r"[\w][\w.+-]*")
DOCKER_HUB = ("docker.io", "index.docker.io", "registry-1.docker.io")
ALIAS_URLS = {"CVE-": "https://nvd.nist.gov/vuln/detail/", "GHSA-": "https://github.com/advisories/"}


# ---------- components ----------

def parse_image(ref):
    """(registry or None, name, tag or None) of an image reference as written in a compose file."""
    ref = (ref or "").strip().strip("\"'").split("@sha256:", 1)[0]
    ref = ref.split(" #", 1)[0].strip().strip("\"'")
    parts = ref.split("/")
    registry = None
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts.pop(0)
    tag = None
    if ":" in parts[-1]:
        parts[-1], tag = parts[-1].split(":", 1)
    if registry in DOCKER_HUB:
        registry = None
    if registry is None and len(parts) == 2 and parts[0] == "library":
        parts.pop(0)
    return registry, "/".join(parts), tag


def component_for(finding):
    """CycloneDX component fields for one scanner finding (bom-ref and purl may be None)."""
    kind, ref, version = finding.get("kind"), finding.get("ref") or "", finding.get("version")
    if kind == "image":
        registry, name, tag = parse_image(ref)
        version = tag if tag and TAG_RE.fullmatch(tag) else version
        purl = f"pkg:docker/{quote(name, safe='/')}" + (f"@{quote(version, safe='')}" if version else "")
        if registry:
            purl += f"?repository_url={quote(registry, safe='')}"
        return {"type": "container", "name": f"{registry}/{name}" if registry else name,
                "version": version, "purl": purl}
    if kind == "pypi":
        m = re.match(r"[A-Za-z0-9._-]+", ref)
        name = re.sub(r"[-_.]+", "-", m.group(0)).lower() if m else finding.get("product")
        return {"type": "library", "name": name, "version": version,
                "purl": f"pkg:pypi/{name}" + (f"@{quote(version, safe='')}" if version else "")}
    if kind == "npm":
        name = ref.rsplit("@", 1)[0] if ref.rfind("@") > 0 else ref
        return {"type": "library", "name": name, "version": version,
                "purl": f"pkg:npm/{quote(name, safe='/')}" + (f"@{quote(version, safe='')}" if version else "")}
    return {"type": "library", "name": finding.get("name") or ref, "version": version, "purl": None}


def prop(name, value):
    return {"name": PROP + name, "value": str(value)}


# ---------- vulnerabilities ----------

def fixed_versions(advisory):
    fixed = advisory.get("fixedIn")
    return [v for v in fixed if v] if isinstance(fixed, list) else [fixed] if fixed else []


def references(advisory):
    out = []
    for alias in advisory.get("aliases") or []:
        base = next((url for prefix, url in ALIAS_URLS.items() if alias.startswith(prefix)), None)
        if base and alias != advisory.get("id"):
            out.append({"id": alias, "source": {"url": base + alias}})
    return out


def vulnerability(advisory):
    fixed = fixed_versions(advisory)
    entry = {"bom-ref": f"advisory:{advisory.get('id')}", "id": advisory.get("id"),
             "ratings": [{"severity": guard.severity(advisory.get("severity")), "method": "other"}],
             "description": advisory.get("summary") or "",
             "recommendation": (f"Upgrade to {' or '.join(fixed)} or later." if fixed else
                                "No fixed release yet. Keep the service off public networks and behind "
                                "authentication, and turn off the affected feature if you do not need it."),
             "affects": []}
    if advisory.get("url"):
        entry["source"] = {"url": advisory["url"]}
    if references(advisory):
        entry["references"] = references(advisory)
    props = [prop("fixedIn", v) for v in fixed]
    if advisory.get("onlyIfFeatureUsed"):
        props.append(prop("onlyIfFeatureUsed", advisory["onlyIfFeatureUsed"]))
    if advisory.get("notInPublicDatabases"):
        props.append(prop("notInPublicDatabases", "true"))
    if props:
        entry["properties"] = props
    return entry


# ---------- the document ----------

def build(report, project, now=None):
    """CycloneDX 1.5 document for a guard report (the output of build_report)."""
    components, vulns = {}, {}
    for f in report["findings"]:
        fields = component_for(f)
        key = fields["purl"] or f"{f.get('kind')}:{f['file']}:{f['line']}"
        comp = components.get(key)
        if comp is None:
            comp = {"type": fields["type"], "bom-ref": key, "name": fields["name"]}
            if fields["version"]:
                comp["version"] = fields["version"]
            if fields["purl"]:
                comp["purl"] = fields["purl"]
            comp["properties"] = [prop("product", f.get("name")), prop("status", f.get("status"))]
            if f.get("upgradeTo"):
                comp["properties"].append(prop("upgradeTo", f["upgradeTo"]))
            components[key] = comp
        comp["properties"].append(prop("location", f"{f['file']}:{f['line']}"))
        comp["properties"] += [prop("ignored", i) for i in f.get("ignored") or []]
        for a in f.get("advisories") or []:
            entry = vulns.setdefault(a.get("id"), vulnerability(a))
            if not any(x["ref"] == key for x in entry["affects"]):
                entry["affects"].append({"ref": key, "versions": [{"version": f.get("version") or "unknown",
                                                                   "status": "affected"}]})
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {"timestamp": now,
                "tools": {"components": [{"type": "application", "name": "AI Stack Guard", "version": VERSION,
                                          "externalReferences": [{"type": "vcs",
                                                                  "url": "https://github.com/munimtechnologies/ai-stack-guard"}]}]},
                "component": {"type": "application", "bom-ref": "project", "name": project},
                "properties": [prop("scanDate", report.get("date"))]}
    if report.get("curatedDataAsOf"):
        metadata["properties"].append(prop("advisoryDataAsOf", report["curatedDataAsOf"]))
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1, "metadata": metadata,
            "components": [components[k] for k in sorted(components)],
            "dependencies": [{"ref": "project", "dependsOn": sorted(components)}],
            "vulnerabilities": [vulns[k] for k in sorted(vulns)]}


# ---------- package registry ----------

def package_url(api, project_id, version, file_name):
    return (f"{api.rstrip('/')}/projects/{quote(str(project_id), safe='')}/packages/generic/"
            f"{PACKAGE}/{quote(version, safe='')}/{quote(file_name, safe='')}")


def publish(files, version, env=None, opener=urllib.request.urlopen):
    """Upload {local path: file name} to the project's generic package registry with the job token."""
    env = os.environ if env is None else env
    if not PACKAGE_VERSION_RE.fullmatch(version) or ".." in version:
        raise SystemExit(f"package version {version!r} may use only letters, digits, '.', '_', '+' and '-'")
    missing = [k for k in ("CI_API_V4_URL", "CI_PROJECT_ID", "CI_JOB_TOKEN") if not env.get(k)]
    if missing:
        raise SystemExit("publish runs in GitLab CI; missing " + ", ".join(missing))
    uploaded = []
    for path, name in files.items():
        url = package_url(env["CI_API_V4_URL"], env["CI_PROJECT_ID"], version, name)
        req = urllib.request.Request(url, data=Path(path).read_bytes(), method="PUT",
                                     headers={"JOB-TOKEN": env["CI_JOB_TOKEN"],
                                              "Content-Type": "application/octet-stream"})
        try:
            with opener(req, timeout=60) as resp:
                status = resp.status
        except urllib.error.HTTPError as err:
            raise SystemExit(f"upload of {name} failed: HTTP {err.code} {err.read()[:300]!r}")
        uploaded.append({"file": name, "status": status, "url": url})
    return {"package": PACKAGE, "version": version, "files": uploaded}


# ---------- commands ----------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["build", "publish"])
    parser.add_argument("--report", default=str(guard.WORK / "report.json"))
    parser.add_argument("--out", default=SBOM_FILE)
    parser.add_argument("--package-version", help="publish: e.g. stack-$CI_PIPELINE_IID")
    args = parser.parse_args(argv)

    if args.command == "build":
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        bom = build(report, os.environ.get("CI_PROJECT_PATH") or Path.cwd().name)
        Path(args.out).write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
        print(f"{args.out}: {len(bom['components'])} components, {len(bom['vulnerabilities'])} open advisories")
        return 0
    if not args.package_version:
        parser.error("publish needs --package-version")
    files = {args.out: SBOM_FILE}
    for local, name in ((guard.WORK / "report.md", "ai-stack-report.md"),
                        (guard.WORK / "report.json", "ai-stack-report.json")):
        if local.is_file():
            files[str(local)] = name
    result = publish(files, args.package_version)
    guard.write("package.json", result)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
