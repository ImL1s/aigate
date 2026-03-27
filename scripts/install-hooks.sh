#!/usr/bin/env zsh
# Install aigate PreToolUse hook into Claude Code settings.json
# Usage:
#   ./scripts/install-hooks.sh              # project-level (.claude/settings.json)
#   ./scripts/install-hooks.sh --user       # user-level (~/.claude/settings.json)
#   ./scripts/install-hooks.sh --both       # both levels

set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
HOOK_SCRIPT="${PROJECT_DIR}/scripts/pretool-hook.sh"

# Ensure hook script is executable
chmod +x "$HOOK_SCRIPT"

# --- Parse args ---
INSTALL_PROJECT=false
INSTALL_USER=false

case "${1:-}" in
  --user)
    INSTALL_USER=true
    ;;
  --both)
    INSTALL_PROJECT=true
    INSTALL_USER=true
    ;;
  *)
    INSTALL_PROJECT=true
    ;;
esac

# --- The hook entry to inject ---
HOOK_JSON=$(cat <<HOOKEOF
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "${HOOK_SCRIPT}",
      "timeout": 30,
      "statusMessage": "Scanning packages with aigate..."
    }
  ]
}
HOOKEOF
)

# --- Merge hook into a settings file ---
merge_hook() {
  local settings_file="$1"
  local settings_dir
  settings_dir=$(dirname "$settings_file")

  # Create directory if it doesn't exist
  if [[ ! -d "$settings_dir" ]]; then
    mkdir -p "$settings_dir"
    echo "Created $settings_dir"
  fi

  # Create file if it doesn't exist
  if [[ ! -f "$settings_file" ]]; then
    echo '{}' > "$settings_file"
    echo "Created $settings_file"
  fi

  # Use python3 to merge (available on macOS by default)
  python3 - "$settings_file" "$HOOK_JSON" <<'PYEOF'
import json
import sys

settings_path = sys.argv[1]
hook_json = sys.argv[2]

with open(settings_path) as f:
    settings = json.load(f)

new_hook = json.loads(hook_json)

# Ensure hooks structure exists
if "hooks" not in settings:
    settings["hooks"] = {}

if "PreToolUse" not in settings["hooks"]:
    settings["hooks"]["PreToolUse"] = []

# Check if aigate hook already exists (by command path)
hook_command = new_hook["hooks"][0]["command"]
already_exists = False
for existing in settings["hooks"]["PreToolUse"]:
    for h in existing.get("hooks", []):
        if h.get("command", "") == hook_command:
            already_exists = True
            break

if already_exists:
    print(f"  aigate hook already exists in {settings_path}, skipping.")
    sys.exit(0)

# Append the new hook
settings["hooks"]["PreToolUse"].append(new_hook)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")

print(f"  Added aigate PreToolUse hook to {settings_path}")
PYEOF
}

# --- Install ---
if $INSTALL_PROJECT; then
  echo "Installing project-level hook..."
  PROJECT_SETTINGS="${PROJECT_DIR}/.claude/settings.json"
  merge_hook "$PROJECT_SETTINGS"
fi

if $INSTALL_USER; then
  echo "Installing user-level hook..."
  USER_SETTINGS="${HOME}/.claude/settings.json"
  merge_hook "$USER_SETTINGS"
fi

echo ""
echo "Done! The aigate PreToolUse hook will scan pip/npm install commands."
echo "Restart Claude Code for changes to take effect."
