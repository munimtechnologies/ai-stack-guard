# Demo video script (under 3 minutes)

One slide per row: a screenshot from the real GitLab project, plus one narration line.
`demo-narration.txt` holds the same lines, one per slide, for a voice track. About 330 words, roughly 2:20 spoken.
Record only what really happened in the project. If a step fails on GitLab, show the failure and the fix rather than a mock-up.

| # | Screenshot | Narration |
|---|---|---|
| 1 | README header in the GitLab project | Self-hosted AI servers like vLLM, Open WebUI and Flowise ship security fixes every few weeks, and most dependency bots never see them, because they are pinned as Docker images. AI Stack Guard keeps that stack patched, hands-off. |
| 2 | `demo/compose.yaml` with the three pins | This demo stack pins three outdated images: Open WebUI 0.11.3, vLLM 0.30.0 and Flowise 3.1.4. |
| 3 | Failed `ai-stack-scan` job log with the findings table | On every push and on a weekly schedule, the ai-stack-scan job checks each pin against curated advisories plus OSV. Here it finds a critical and a high advisory, so the pipeline fails. |
| 4 | Merge request Code Quality widget | The same findings show up in the Code Quality widget. |
| 5 | AI > Triggers page: Pipeline events: Failed | That failure is the trigger. GitLab starts the AI Stack Guard flow on the Duo Agent Platform, with no human involved. |
| 6 | Flow session log: guard agent running `guard.py run` | The guard agent plans one exact edit per line, applies it, and rescans the patched files before anything is pushed. Every number comes from the scanner, not from the model. |
| 7 | Two merge requests: auto group and review group | It opens two merge requests. The Open WebUI patch bump goes to the auto group. The vLLM bump is a minor version on 0.x software, where things break, so it goes to the review group and waits for a person. |
| 8 | First MR comment with the evidence table | Each merge request starts with an evidence table: file and line, before and after, which advisories it fixes, and what is still open. |
| 9 | Reviewer agent note: review passed, auto-merge armed | A second agent, the reviewer, checks each branch from a fresh worktree: only the planned lines changed, and the rescan is clean. Only a passed review arms auto-merge. |
| 10 | Issue for the Flowise advisory with mitigations | Flowise has no fixed release yet, so no upgrade can help. The guard opens one issue per advisory, with mitigations, and keeps the pipeline green. |
| 11 | Merged MR, then the tagged release from `stack-changes/` | When the patch merges, its change note becomes a tagged release. Plan, create, verify, secure, release and monitor are all covered by one flow. |
| 12 | IDE: Duo Agentic Chat answering with the `plan_upgrades` MCP tool | Developers can ask the same questions from their IDE. A small MCP server gives Duo Chat read-only tools to scan the stack and preview the guard's plan. |
| 13 | `ai-stack-guard.json` | One policy file is the control dial: what fails the pipeline, and how big a bump may merge itself. Set auto-merge to none and every change waits for a human. |
| 14 | Project page with the Apache-2.0 license | AI Stack Guard is Apache-2.0 licensed. It is by MV2 of Munim, Inc., made with AI agents. Thanks for watching. |
