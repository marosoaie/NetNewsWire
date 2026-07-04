#!/usr/bin/env bash
#
# scan-netnewswire.sh
# ---------------------------------------------------------------------------
# Sets up Visa's Vulnerability Agentic Harness (VVAH) with Claude as the
# backend and runs a security scan of NetNewsWire on your Mac.
#
# Backend:  Claude Code login (default `via: cli` profile — no API key needed)
# Target:   a throwaway clone of NetNewsWire (the full scan EDITS this clone)
#
# Run:  chmod +x scan-netnewswire.sh && ./scan-netnewswire.sh
# ---------------------------------------------------------------------------
set -euo pipefail

# --- Where everything lives (change if you like) ---------------------------
WORK="${WORK:-$HOME/vvah-netnewswire}"
HARNESS_DIR="$WORK/visa-vulnerability-agentic-harness"
TARGET_DIR="${TARGET_DIR:-$HOME/projects/NetNewsWire}"   # your existing clone — the full scan EDITS this
HARNESS_REPO="https://github.com/visa/visa-vulnerability-agentic-harness.git"

msg()  { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
die()  { printf "\n\033[1;31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }

# --- 1. Prerequisite checks ------------------------------------------------
msg "Checking prerequisites"

command -v git >/dev/null 2>&1 || die "git not found. Install Xcode command line tools: xcode-select --install"

# Python >= 3.10
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "python3 not found. Install Python 3.10+ (e.g. 'brew install python')."
PYV="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)' \
  || die "Python 3.10+ required, found $PYV. Install a newer Python (e.g. 'brew install python@3.12')."
msg "Python $PYV OK"

# Claude Code CLI (the default profile drives every stage through it)
if ! command -v claude >/dev/null 2>&1; then
  die "The 'claude' CLI is not installed. Install Claude Code (https://claude.com/product/claude-code), then run 'claude' and type /login before re-running this script."
fi
msg "claude CLI found. Make sure you have logged in at least once (run 'claude' then /login)."

# --- 2. Fetch the harness --------------------------------------------------
mkdir -p "$WORK"
if [ -d "$HARNESS_DIR/.git" ]; then
  msg "Harness already cloned — pulling latest"
  git -C "$HARNESS_DIR" pull --ff-only || true
else
  msg "Cloning the Visa harness"
  git clone --depth 1 "$HARNESS_REPO" "$HARNESS_DIR"
fi

# --- 3. Install vvaharness into an isolated venv ---------------------------
msg "Installing vvaharness into a virtual environment"
cd "$HARNESS_DIR"
if [ ! -d ".venv" ]; then
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet .
command -v vvaharness >/dev/null 2>&1 || die "vvaharness did not install onto PATH inside the venv."
msg "vvaharness installed: $(vvaharness --version 2>/dev/null || echo 'ok')"

# --- 4. Configure credentials (.env) ---------------------------------------
# The default profile reuses your Claude Code login, so .env can stay empty.
# We still create it so vvaharness has one to auto-load.
[ -f .env ] || cp .env.example .env
msg "Using default profile (all stages via the Claude CLI / your Claude Code login)."

# --- 5. Wire up agent operating instructions (optional but recommended) ----
vvaharness setup --install-agents || true

# --- 6. Sanity check: credentials + backend reachability -------------------
msg "Running 'vvaharness doctor' (live connectivity probe)"
vvaharness doctor || die "doctor failed — fix the reported issue (usually: run 'claude' then /login) and re-run."

# --- 7. Use your existing NetNewsWire clone --------------------------------
# IMPORTANT: the full 11-stage scan runs remediation (S10) in FIX MODE, which
# EDITS source files in $TARGET_DIR. Because this is your own clone, we require
# a CLEAN git working tree first, so every change the tool makes is reviewable
# with 'git diff' and fully revertible with 'git reset --hard'.
[ -d "$TARGET_DIR/.git" ] || die "$TARGET_DIR is not a git clone. Set TARGET_DIR to your NetNewsWire checkout."
if [ -n "$(git -C "$TARGET_DIR" status --porcelain --untracked-files=no)" ]; then
  die "Your NetNewsWire working tree has uncommitted changes to tracked files. Commit or stash them first (git -C \"$TARGET_DIR\" stash) so the scan's edits stay separate and revertible — then re-run."
fi
msg "Target: $TARGET_DIR (clean working tree confirmed; the scan's edits will be reviewable via 'git diff')"

# --- 8. Estimate scope/cost (spends nothing) -------------------------------
msg "Estimating scope (no tokens spent)"
vvaharness estimate --repo "$TARGET_DIR" || true

# --- 9. Run the scan -------------------------------------------------------
# Full 11-stage run: detection (S1-S9) + remediation (S10, edits the clone)
# + validation (S11). To do DETECTION ONLY with no code edits, replace the
# line below with:   vvaharness scan --repo "$TARGET_DIR" --stop-after s9
msg "Starting FULL 11-stage scan (this will EDIT the NetNewsWire clone and can take a while + consume significant tokens)"
read -r -p "Proceed with the code-editing full scan? [y/N] " ans
case "$ans" in
  [yY]|[yY][eE][sS]) ;;
  *) die "Aborted by user. Re-run and choose 'y', or run detection-only:  vvaharness scan --repo \"$TARGET_DIR\" --stop-after s9" ;;
esac

vvaharness scan --repo "$TARGET_DIR"

# --- 10. Where to look -----------------------------------------------------
msg "Done. Outputs:"
echo "  Findings (Markdown + SARIF): $TARGET_DIR/security-scan/"
echo "  Remediation reports:         $TARGET_DIR/security-remediation/"
echo "  Applied fixes:               inspect with 'git -C \"$TARGET_DIR\" diff'"
echo "  Run manifest:                $HARNESS_DIR/run_manifest.json"
