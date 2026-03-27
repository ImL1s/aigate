#!/usr/bin/env zsh
# Claude Code PreToolUse hook for aigate
# Intercepts pip install / npm install commands and scans packages with aigate.
#
# Usage in .claude/settings.json:
#   "PreToolUse": [{
#     "matcher": "Bash",
#     "hooks": [{
#       "type": "command",
#       "command": "/path/to/aigate/scripts/pretool-hook.sh",
#       "timeout": 30
#     }]
#   }]

set -euo pipefail

# --- Configuration ---
AIGATE_BIN="${AIGATE_BIN:-/Users/iml1s/Documents/mine/aigate/.venv/bin/aigate}"

# --- Read stdin first (before any heredoc consumes it) ---
HOOK_INPUT=$(cat)

# --- Extract packages via Python (reliable cross-platform) ---
# Pass input via env var, not stdin. Output: "ecosystem pkg1 pkg2 ..." or empty.
PARSED=$(HOOK_INPUT="$HOOK_INPUT" python3 -c '
import json, re, os, sys

SYSTEM_PACKAGES = {"pip", "setuptools", "wheel", "pkg-resources", "distribute"}
VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "--find-links", "-f",
    "--target", "-t", "--prefix", "--root", "--src", "--registry",
}

try:
    data = json.loads(os.environ.get("HOOK_INPUT", ""))
    cmd = data.get("tool_input", {}).get("command", "")
except Exception:
    sys.exit(0)

if not cmd:
    sys.exit(0)

ecosystem = None
raw_args = None

# --- Detect pip install ---
pip_m = re.search(
    r"(?:^|[;\s&|]+)(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s+install\s+(.*)", cmd
)
if pip_m:
    raw_args = pip_m.group(1).strip()
    # Skip: -r requirements.txt
    if re.search(r"(?:^|\s)-r\s", " " + raw_args):
        sys.exit(0)
    # Skip: pip install . or pip install -e .
    tokens_quick = raw_args.split()
    non_flag = [t for t in tokens_quick if not t.startswith("-")]
    if non_flag and all(
        t in (".", "./") or t.startswith("./") or t.startswith("/") for t in non_flag
    ):
        sys.exit(0)
    ecosystem = "pypi"

# --- Detect npm/yarn/pnpm install ---
if not ecosystem:
    npm_m = re.search(
        r"(?:^|[;\s&|]+)(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s+(.*)",
        cmd,
    )
    if npm_m:
        raw_args = npm_m.group(1).strip()
        if raw_args:
            ecosystem = "npm"

if not ecosystem or not raw_args:
    sys.exit(0)

# --- Parse tokens to extract package names ---
tokens = raw_args.split()
packages = []
skip_next = False

for tok in tokens:
    if skip_next:
        skip_next = False
        continue
    if tok in VALUE_FLAGS:
        skip_next = True
        continue
    if tok.startswith("-"):
        continue

    # Extract package name
    if tok.startswith("@") and "/" in tok:
        # Scoped npm: @scope/name@version -> @scope/name
        m = re.match(r"(@[^/]+/[^@]+)", tok)
        name = m.group(1) if m else tok
    else:
        # Strip version specifiers: requests==2.31.0 -> requests
        name = re.split(r"[=<>!~@]", tok)[0]

    # Skip empty, dot, local paths, URLs
    if not name or name in (".",) or "/" in name or "://" in tok:
        continue
    # Skip system packages
    if name.lower() in SYSTEM_PACKAGES:
        continue
    packages.append(name)

if not packages:
    sys.exit(0)

print(ecosystem + " " + " ".join(packages))
' 2>/dev/null || echo "")

if [[ -z "$PARSED" ]]; then
  exit 0
fi

# Split: first token = ecosystem, rest = packages
ECOSYSTEM="${PARSED%% *}"
PKG_LIST="${PARSED#* }"

# Check each package with aigate
BLOCKED_NAMES=()
BLOCKED_REASONS=()

for pkg in ${(z)PKG_LIST}; do
  # Run aigate check (skip AI for speed)
  RESULT=$("$AIGATE_BIN" check "$pkg" -e "$ECOSYSTEM" --json --skip-ai 2>/dev/null || true)

  if [[ -z "$RESULT" ]]; then
    continue
  fi

  # Parse risk_level from JSON output
  RISK_LEVEL=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('prefilter', {}).get('risk_level', 'none'))
except Exception:
    print('none')
" 2>/dev/null || echo "none")

  if [[ "$RISK_LEVEL" == "critical" ]] || [[ "$RISK_LEVEL" == "high" ]]; then
    BLOCKED_NAMES+=("$pkg")
    REASON=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('prefilter', {}).get('reason', 'flagged by aigate'))
except Exception:
    print('flagged by aigate')
" 2>/dev/null || echo "flagged by aigate")
    BLOCKED_REASONS+=("$REASON")
  fi
done

# If nothing blocked, allow silently
if [[ ${#BLOCKED_NAMES[@]} -eq 0 ]]; then
  exit 0
fi

# Output JSON block decision (use Python for safe encoding)
python3 -c "
import json, sys
args = sys.argv[1:]
sep = args.index('--') if '--' in args else len(args)
names = args[:sep]
reasons = args[sep+1:]
reason_str = 'aigate: blocked ' + ', '.join(names) + ' \u2014 ' + '; '.join(reasons)
print(json.dumps({'decision': 'block', 'reason': reason_str}))
" "${BLOCKED_NAMES[@]}" "--" "${BLOCKED_REASONS[@]}"
