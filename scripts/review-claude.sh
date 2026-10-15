#!/usr/bin/env bash
set -euo pipefail
umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(dirname -- "$script_dir")
cd "$repo_dir"
if ! claude auth status >/dev/null 2>&1; then
  printf '%s\n' 'Claude is not signed in. Run claude auth login on this host, then retry.' >&2
  exit 1
fi
mkdir -p docs/reviews
review_date=$(date -u +%Y%m%dT%H%M%SZ)
result_file="docs/reviews/claude-$review_date.json"
review_file="docs/reviews/claude-$review_date.md"
claude --print --restricted --permission-mode dontAsk \
  --tools Read,Glob,Grep --allowedTools Read,Glob,Grep \
  --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
  --setting-sources '' --disable-slash-commands --no-session-persistence \
  --system-prompt "You are an independent security reviewer. Review only files inside $repo_dir using read-only file tools. Do not modify anything or access live credentials, external services, or files outside this repository. Follow the review request supplied on stdin and return your evidence-based security findings." \
  --output-format json < docs/security-review-request.md > "$result_file"
python3 - "$result_file" "$review_file" <<'PY'
import json
import sys
from pathlib import Path
result = json.loads(Path(sys.argv[1]).read_text())
if result.get('is_error') or not result.get('result'):
    raise SystemExit('Claude did not complete its review. Inspect the saved JSON result.')
Path(sys.argv[2]).write_text(result['result'] + '\n')
print('Claude review saved to ' + sys.argv[2])
PY
