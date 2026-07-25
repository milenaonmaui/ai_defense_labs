#!/usr/bin/env bash
set -euo pipefail

input=$(cat)
file_path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .file_path // empty')

if [[ -z "$file_path" ]]; then
  exit 0
fi

case "$file_path" in
  */rules/*.yaml|*/rules/*.yml|rules/*.yaml|rules/*.yml) ;;
  *) exit 0 ;;
esac

if [[ ! -f "$file_path" ]]; then
  echo "validate-rule: file not found: $file_path" >&2
  exit 2
fi

if output=$(python3 - "$file_path" <<'PYEOF'
import sys
import yaml

path = sys.argv[1]
errors = []

try:
    with open(path) as f:
        data = yaml.safe_load(f)
except yaml.YAMLError as e:
    print(f"invalid YAML: {e}")
    sys.exit(1)

if not isinstance(data, dict):
    print("rule file does not contain a YAML mapping")
    sys.exit(1)

if not data.get("title"):
    errors.append("missing required field: title")

if not data.get("description"):
    errors.append("missing required field: description")

tags = data.get("tags")
if not isinstance(tags, list) or not any(
    isinstance(t, str) and t.startswith("attack.t") for t in tags
):
    errors.append("tags must include at least one MITRE ATT&CK technique tag (e.g. 'attack.t1059')")

if errors:
    for e in errors:
        print(e)
    sys.exit(1)

sys.exit(0)
PYEOF
); then
  echo "validate-rule: $file_path is valid" >&2
  exit 2
else
  echo "validate-rule: $file_path is invalid:" >&2
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "  - $line" >&2
  done <<< "$output"
  exit 2
fi
