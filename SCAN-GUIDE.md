# Scanning NetNewsWire with the Visa Vulnerability Agentic Harness (Claude backend)

## What this tool is

VVAH is Visa's open-source "agentic SAST" harness. It points frontier AI models at a source
repo and runs an 11-stage pipeline: attack-surface mapping and threat modeling (S1–S3),
multi-lens analysis and adversarial verification (S4–S6), deduplication and reporting to
Markdown + SARIF (S7–S9), then automated remediation (S10) and validation of those fixes
(S11). Findings are **LLM-generated triage candidates, not confirmed vulnerabilities** — they
need human review.

You picked: run on **your Mac**, authenticate with your **Claude Code login**, and do the
**full 11-stage run**. The one thing to internalize before you start: the full run edits code.

## The one big warning

The default profile runs stage S10 in **fix mode, which edits source files in the target
repo**. That is why the script scans a **fresh throwaway clone** of NetNewsWire at
`~/vvah-netnewswire/NetNewsWire` rather than any copy you care about. Review every change with
`git diff` before trusting it; VVAH does not compile, build, or test the patched code.

If you'd rather find issues without touching code, use detection-only instead:
`vvaharness scan --repo <path> --stop-after s9`.

## Prerequisites

- **macOS with Python 3.10+** and **git** (git ships with the Xcode command line tools:
  `xcode-select --install`).
- **Claude Code CLI installed and logged in.** This is what "Claude as the backend" means here
  — the default profile drives every stage through the `claude` CLI using your existing Claude
  subscription, so **no API key is required**. Install Claude Code, then run `claude` once and
  type `/login`.

## How Claude is used as the backend

The harness ships three backends (Claude CLI, Anthropic SDK, OpenAI). The default profile sets
every role to `via: cli`, meaning it shells out to your logged-in `claude` CLI. Nothing else to
configure — the `.env` file can stay empty. (If you ever wanted pay-per-token API access or
majority-vote false-positive filtering instead, you'd switch roles to `via: sdk` and set
`ANTHROPIC_SDK_API_KEY`, but that's not needed for your setup.)

## What the script does, step by step

1. Checks Python 3.10+, git, and the `claude` CLI are present.
2. Clones the harness to `~/vvah-netnewswire/visa-vulnerability-agentic-harness`.
3. Creates a Python venv and `pip install .` — this puts the `vvaharness` command on PATH.
4. Copies `.env.example` to `.env` (left empty; the Claude login is enough).
5. Runs `vvaharness setup --install-agents` and `vvaharness doctor` (a live check that the
   backend is reachable — if this fails it's almost always because you haven't run `/login`).
6. Clones a fresh, disposable copy of NetNewsWire as the scan target.
7. Runs `vvaharness estimate` (free — shows rough scope/cost).
8. Asks you to confirm, then runs the full `vvaharness scan`.

## Running it

```bash
chmod +x scan-netnewswire.sh
./scan-netnewswire.sh
```

You can change where things live by setting `WORK`, e.g. `WORK=~/scans ./scan-netnewswire.sh`.

## Where the results land

Under the NetNewsWire clone (`~/vvah-netnewswire/NetNewsWire`):

- `security-scan/*_report.md` — findings plus a dropped-findings appendix
- `security-scan/*_report.sarif` — SARIF 2.1.0 (open in VS Code's SARIF viewer, or upload to a
  code-scanning dashboard)
- `security-remediation/<NN_slug>/remediate_report.json` — per-finding fix reports
- the **applied fixes themselves** — inspect with `git -C ~/vvah-netnewswire/NetNewsWire diff`
- `run_manifest.json` (in the harness dir) — tool version, model roles, config hash, target SHA

## Things to expect

- **Cost / time.** The pipeline is token-hungry; caps are per-stage, not global. `estimate`
  gives you a rough number before you commit. On a subscription login you're spending against
  your plan's usage rather than a per-token bill.
- **Non-determinism.** Two runs can produce different findings. The CLI backend runs single-pass
  (no majority-vote FP filtering — that's SDK/OpenAI only).
- **Authorized use.** NetNewsWire is MIT-licensed open source, so scanning it is fine. The tool
  runs with elevated privilege and native file tools inside the target dir, so only ever run it
  against code you trust.

## Handy commands

```bash
# activate the tool later
source ~/vvah-netnewswire/visa-vulnerability-agentic-harness/.venv/bin/activate

vvaharness doctor                                   # re-check backend/creds
vvaharness estimate --repo ~/vvah-netnewswire/NetNewsWire
vvaharness scan --repo ~/vvah-netnewswire/NetNewsWire --stop-after s9   # detection only
vvaharness scan --repo ~/vvah-netnewswire/NetNewsWire                   # full run (edits code)
vvaharness --help
```

Source: [visa/visa-vulnerability-agentic-harness](https://github.com/visa/visa-vulnerability-agentic-harness) ·
[SETUP_GUIDE](https://github.com/visa/visa-vulnerability-agentic-harness/blob/main/docs/SETUP_GUIDE.md)
