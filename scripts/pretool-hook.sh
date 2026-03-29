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

if [[ -z "${AIGATE_BIN:-}" ]]; then
  SCRIPT_DIR="${0:A:h}"
  if command -v aigate >/dev/null 2>&1; then
    AIGATE_BIN="$(command -v aigate)"
  elif [[ -x "$SCRIPT_DIR/../.venv/bin/aigate" ]]; then
    AIGATE_BIN="$SCRIPT_DIR/../.venv/bin/aigate"
  else
    exit 0
  fi
fi

HOOK_INPUT=$(cat)

PARSED=$(HOOK_INPUT="$HOOK_INPUT" python3 -c '
import json, os, pathlib, re, sys

SYSTEM_PACKAGES = {"pip", "setuptools", "wheel", "pkg-resources", "distribute"}
VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "--find-links", "-f",
    "--target", "-t", "--prefix", "--root", "--src", "--registry",
    "-w", "--workspace", "--tag",
}

def emit(payload):
    print(json.dumps(payload))
    sys.exit(0)

def is_local_path(token):
    return token in (".", "./") or token.startswith("./") or token.startswith("/") or token.startswith("../")

def parse_pip(raw_args):
    tokens = raw_args.split()
    if "--no-aigate" in tokens:
        sys.exit(0)

    for idx, tok in enumerate(tokens):
        if tok in ("-r", "--requirement") and idx + 1 < len(tokens):
            emit({"mode": "scan", "ecosystem": "pypi", "lockfile": tokens[idx + 1]})

    non_flag = [t for t in tokens if not t.startswith("-")]
    if non_flag and all(is_local_path(t) for t in non_flag):
        sys.exit(0)

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
        if is_local_path(tok) or "://" in tok:
            continue
        name = re.split(r"[=<>!~@]", tok)[0]
        if not name or name.lower() in SYSTEM_PACKAGES:
            continue
        packages.append(name)

    if packages:
        emit({"mode": "check", "ecosystem": "pypi", "packages": packages})
    sys.exit(0)

def parse_npm(pm, raw_args):
    tokens = raw_args.split()
    if "--no-aigate" in tokens:
        sys.exit(0)

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
        if tok.startswith("@") and "/" in tok:
            m = re.match(r"(@[^/]+/[^@]+)", tok)
            name = m.group(1) if m else tok
        else:
            name = tok.split("@", 1)[0]
        if not name or ("/" in name and not name.startswith("@")):
            continue
        packages.append(name)

    if packages:
        emit({"mode": "check", "ecosystem": "npm", "packages": packages})

    lockfile_candidates = {
        "npm": ["package-lock.json", "npm-shrinkwrap.json"],
        "yarn": ["yarn.lock"],
        "pnpm": ["pnpm-lock.yaml"],
    }
    for candidate in lockfile_candidates.get(pm, []):
        if pathlib.Path(candidate).exists():
            emit({"mode": "scan", "ecosystem": "npm", "lockfile": candidate})
    sys.exit(0)

try:
    data = json.loads(os.environ.get("HOOK_INPUT", ""))
    cmd = data.get("tool_input", {}).get("command", "")
except Exception:
    sys.exit(0)

if not cmd:
    sys.exit(0)

pip_m = re.search(
    r"(?:^|[;\s&|]+)(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s+install(?:\s+(.*))?$",
    cmd,
)
if pip_m:
    parse_pip((pip_m.group(1) or "").strip())

npm_m = re.search(
    r"(?:^|[;\s&|]+)(npm|yarn|pnpm)\s+(install|i|add)(?:\s+(.*))?$",
    cmd,
)
if npm_m:
    parse_npm(npm_m.group(1), (npm_m.group(3) or "").strip())

# fvm install — Flutter SDK version management, always safe → skip
fvm_m = re.search(r"(?:^|[;\s&|]+)fvm\s+install", cmd)
if fvm_m:
    sys.exit(0)

# Dart/Flutter: dart pub add <pkg>, flutter pub add <pkg>, dart pub get, flutter pub get
dart_m = re.search(
    r"(?:^|[;\s&|]+)(?:dart|flutter)\s+pub\s+(add|get)(?:\s+(.*))?$",
    cmd,
)
if dart_m:
    subcmd = dart_m.group(1)
    args = (dart_m.group(2) or "").strip()
    if subcmd == "add" and args:
        # `flutter pub add http` or `flutter pub add --dev mockito`
        packages = [a for a in args.split() if not a.startswith("-")]
        if packages:
            emit({"mode": "check", "ecosystem": "pub", "packages": packages})
    else:
        # bare `flutter pub get` / `dart pub get` — scan pubspec.lock if exists
        if pathlib.Path("pubspec.lock").exists():
            emit({"mode": "scan", "ecosystem": "pub", "lockfile": "pubspec.lock"})
    sys.exit(0)

# CocoaPods: pod install, pod update
pod_m = re.search(r"(?:^|[;\s&|]+)pod\s+(?:install|update)(?:\s|$)", cmd)
if pod_m:
    if pathlib.Path("Podfile.lock").exists():
        emit({"mode": "scan", "ecosystem": "pub", "lockfile": "Podfile.lock"})
    sys.exit(0)

# Cargo: cargo add <crate>, cargo install <crate>
cargo_m = re.search(
    r"(?:^|[;\s&|]+)cargo\s+(?:add|install)(?:\s+(.*))?$",
    cmd,
)
if cargo_m:
    args = (cargo_m.group(1) or "").strip()
    packages = []
    skip_next = False
    for tok in args.split():
        if skip_next:
            skip_next = False
            continue
        if tok in ("--git", "--path", "--registry", "--version", "--branch", "--tag", "--rev"):
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        packages.append(tok)
    if packages:
        emit({"mode": "check", "ecosystem": "cargo", "packages": packages})
    sys.exit(0)

sys.exit(0)
' 2>/dev/null || echo "")

if [[ -z "$PARSED" ]]; then
  exit 0
fi

MODE=$(echo "$PARSED" | python3 -c "import sys, json; print(json.load(sys.stdin).get('mode', ''))" 2>/dev/null || echo "")
ECOSYSTEM=$(echo "$PARSED" | python3 -c "import sys, json; print(json.load(sys.stdin).get('ecosystem', ''))" 2>/dev/null || echo "")
LOCKFILE=$(echo "$PARSED" | python3 -c "import sys, json; print(json.load(sys.stdin).get('lockfile', ''))" 2>/dev/null || echo "")
PKG_LIST=$(echo "$PARSED" | python3 -c "import sys, json; print(' '.join(json.load(sys.stdin).get('packages', [])))" 2>/dev/null || echo "")

if [[ -z "$MODE" ]] || [[ -z "$ECOSYSTEM" ]]; then
  exit 0
fi

should_block() {
  local result_json="$1"
  echo "$result_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    decision = data.get('decision', 'safe')
    should_block = data.get('should_block_install', False)
    exit_code = int(data.get('exit_code', 0))
    print('1' if should_block or decision == 'malicious' or exit_code == 2 else '0')
except Exception:
    print('0')
" 2>/dev/null || echo "0"
}

extract_reason() {
  local result_json="$1"
  echo "$result_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('reason') or data.get('summary') or 'flagged by aigate')
except Exception:
    print('flagged by aigate')
" 2>/dev/null || echo "flagged by aigate"
}

BLOCKED_NAMES=()
BLOCKED_REASONS=()

if [[ "$MODE" == "scan" ]] && [[ -n "$LOCKFILE" ]]; then
  RESULT=$("$AIGATE_BIN" scan "$LOCKFILE" --ecosystem "$ECOSYSTEM" --json --skip-ai 2>/dev/null || true)
  if [[ -n "$RESULT" ]] && [[ "$(should_block "$RESULT")" == "1" ]]; then
    BLOCKED_NAMES+=("$LOCKFILE")
    BLOCKED_REASONS+=("$(extract_reason "$RESULT")")
  fi
elif [[ "$MODE" == "check" ]] && [[ -n "$PKG_LIST" ]]; then
  for pkg in ${(z)PKG_LIST}; do
    RESULT=$("$AIGATE_BIN" check "$pkg" -e "$ECOSYSTEM" --json --skip-ai 2>/dev/null || true)
    if [[ -z "$RESULT" ]]; then
      continue
    fi
    if [[ "$(should_block "$RESULT")" == "1" ]]; then
      BLOCKED_NAMES+=("$pkg")
      BLOCKED_REASONS+=("$(extract_reason "$RESULT")")
    fi
  done
fi

if [[ ${#BLOCKED_NAMES[@]} -eq 0 ]]; then
  exit 0
fi

python3 -c "
import json, sys
args = sys.argv[1:]
sep = args.index('--') if '--' in args else len(args)
names = args[:sep]
reasons = args[sep+1:]
reason_str = 'aigate: blocked ' + ', '.join(names) + ' — ' + '; '.join(reasons)
print(json.dumps({'decision': 'block', 'reason': reason_str}))
" "${BLOCKED_NAMES[@]}" "--" "${BLOCKED_REASONS[@]}"
