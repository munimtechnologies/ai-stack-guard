# AI Stack Guard

**A hands-off GitLab Duo Agent Platform flow that keeps a self-hosted AI stack patched.** It covers
Ollama, vLLM, Open WebUI, LiteLLM, n8n, Flowise, Dify, RAGFlow, Langflow, ComfyUI and more.

Self-hosted AI servers ship security fixes every few weeks, and many of those advisories never reach
the public databases that Dependabot and Renovate read. Many projects ship only as Docker images, so a
pin like `vllm/vllm-openai:v0.30.0` in a compose file is invisible to ordinary dependency bots.
AI Stack Guard finds those pins, fixes what can be fixed, proves the fix, and tracks what cannot be
fixed yet, without a human in the loop unless your policy asks for one.

Built for GitLab's *Life After Code* hackathon (Path A: Start Fresh), aiming at the **Hands-off** autonomy level.

## What happens, stage by stage

| Stage | What AI Stack Guard does |
|---|---|
| Secure | The `ai-stack-scan` CI job matches every pinned image and package against curated advisories plus OSV ([ai-stack-advisories](https://github.com/munimv2/ai-stack-advisories)). Findings appear in the merge request Code Quality widget. |
| Monitor | A weekly pipeline schedule rescans, so new advisories fail the pipeline even when nothing in the repo changed. |
| Plan | A failed pipeline fires the flow. `guard.py run` turns the findings into an upgrade plan: one exact version edit per line, sorted into an **auto** group and a **review** group by semver size. |
| Create | The guard agent opens one merge request per group through git push options. Its first comment carries an evidence table: component, file and line, before, after, advisories fixed, and what is still open. |
| Verify | Before anything is pushed, the patched files are rescanned. Every patched line must come back clean, and no new line may become affected. |
| Govern | A second agent, the reviewer, re-checks each pushed branch from a fresh worktree. It confirms that only the planned lines changed, each to the planned text, and that a rescan is clean. **Only a passed review arms auto-merge.** Advisories with no fixed release become issues with mitigations, and ignores in the policy must carry an expiry date. |
| Release | When a fix merges, its `stack-changes/` entry becomes a tagged GitLab release. |
| Configure | `ai-stack-guard.json` holds the policy; `.gitlab/duo/agent-config.yml` sets up the flow runtime. |
| Code | `.gitlab/duo/mcp.json` gives GitLab Duo Agentic Chat in your IDE (or the Duo CLI) three read-only MCP tools, so a developer can ask "is our AI stack safe, and what would the guard change?" before pushing. |

## The control dial (`ai-stack-guard.json`)

```json
{
  "paths": ["."],
  "exclude": [".ai-stack-advisories", ".ai-stack-guard"],
  "block_on": "high",
  "unfixable_blocks": false,
  "auto_merge": "patch",
  "target_branch": "main",
  "ignore": [{"id": "GHSA-xxxx-xxxx-xxxx", "until": "2026-12-31", "reason": "port closed, feature off"}]
}
```

- `block_on`: the lowest severity that fails the pipeline and wakes the flow: `affected`, `low`, `medium`, `high`, `critical` or `never`.
- `auto_merge`: the largest bump that may merge itself after review: `none`, `patch`, `minor` or `major`. On 0.x projects, a minor bump counts as major, because that is where 0.x software breaks.
- `unfixable_blocks`: whether advisories with no fixed release fail the pipeline. They become issues either way.
- In merge request pipelines, only lines the MR changes can block it. One upgrade MR is never held hostage by another component's pin.

Set `auto_merge` to `none` and every change waits for a human. Leave it at `patch` and routine fixes ship themselves.

## The demo

`demo/compose.yaml` pins three outdated images on purpose:
- **Open WebUI 0.11.3 → 0.11.4** is a patch bump. It goes to the auto group: reviewed, then auto-merged when the pipeline passes, then released.
- **vLLM v0.30.0 → v0.31.0** is a 0.x minor bump. It goes to the review group, and the MR explains why it needs a human.
- **Flowise 3.1.4** has advisories with no fixed release. AI Stack Guard opens one issue per advisory with mitigations, and keeps the pipeline green, because no upgrade can help.

The narration and shot list for the demo video are in [`docs/demo-script.md`](docs/demo-script.md).

## Set it up on your GitLab project

1. Copy `guard/`, `.gitlab/duo/`, `ai-stack-guard.json` and the `ai-stack-scan` job from `.gitlab-ci.yml`. Add `.ai-stack-guard/` and `.ai-stack-advisories/` to `.gitignore`.
2. **AI > Flows > New flow**: paste `.gitlab/duo/flows/ai-stack-guard.yaml` and enable it for the project.
3. **AI > Triggers > New flow trigger**: add the event *Pipeline events: Failed*, the flow's service account, and the AI Stack Guard flow. Optionally add *Mention*, so `@` the service account in an issue runs it on demand.
4. **Build > Pipeline schedules**: add a weekly schedule on the default branch.
5. In the project's merge request settings, allow *Auto-merge* (merge when the pipeline succeeds).

Run it locally with Python 3.9 or later and no dependencies:

```sh
python3 guard/fetch_scanner.py
python3 guard/guard.py scan      # exit 1 when policy says the pipeline should fail
python3 guard/guard.py run       # plan, patch, verify; prints what it would ship
python3 guard/guard.py ship --dry-run
python3 -m unittest -v test_guard.py test_mcp_server.py
```

## Ask about it from your IDE (MCP)

`guard/mcp_server.py` is a small Model Context Protocol server (stdio, standard library only).
`.gitlab/duo/mcp.json` registers it for GitLab Duo Agentic Chat in VS Code or JetBrains, and for the Duo CLI.

| Tool | What it answers |
|---|---|
| `scan_stack` | Which pinned components have known advisories, and which of them would fail the pipeline under your policy. |
| `plan_upgrades` | The exact edits the flow would make (file, line, from, to, semver size), split into the auto and review groups, plus advisories with no fixed release. |
| `component_advisories` | Every advisory for one component: severity, fixed versions, summary and link. |

The server is read-only. It never edits files, runs git or pushes; merge requests stay the flow's job.
It fetches the scanner on first use, the same way the CI job does.

To use it, open the project folder in your IDE. In the top-level group, turn on
**Settings > GitLab Duo > Allow external MCP tools**, then restart the IDE. If your system has
`python` but no `python3`, change `command` in `.gitlab/duo/mcp.json`.

## Limits, plainly

- It compares versions only; it never connects to your servers. To check exposed ports and settings, see [local-ai-checkup](https://github.com/munimv2/local-ai-checkup).
- A bumped tag keeps any suffix (such as `-cu128`), and suffixed tags never auto-merge, because the new tag may not exist upstream. Digest-pinned lines are skipped and reported.
- GitLab only lets humans fire flow triggers. Pipelines started by the flow's own pushes never start it again, so it cannot loop.
- The MCP tools run where your IDE runs. GitLab documents MCP for the IDE and the Duo CLI, so the flow itself uses the scanner directly.

## Credits

Made by MV2 of Munim, Inc. The code, flow and text were made with AI agents (Claude) working in his name, and every change it proposes carries the scanner evidence so a reviewer can check it. Advisory data comes from [ai-stack-advisories](https://github.com/munimv2/ai-stack-advisories) and OSV.dev. MIT licensed.
