#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "ERROR: Run this script from inside the cloned GitHub repository."
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI (gh) is not installed. Use the GitHub README editor and drag the MP4 into it, or install/update gh."
  exit 1
fi

GH_VERSION="$(gh --version | head -n 1 | awk '{print $3}')"
if ! python3 - "$GH_VERSION" <<'PY'
import re, sys
m = re.match(r'^(\d+)\.(\d+)\.(\d+)', sys.argv[1])
if not m or tuple(map(int, m.groups())) < (2, 99, 0):
    raise SystemExit(1)
PY
then
  echo "ERROR: gh 2.99.0 or newer is required for the --attach media upload option."
  echo "Installed version: $GH_VERSION"
  exit 1
fi

gh auth status >/dev/null

REMOTE="$(git -C "$REPO_ROOT" remote get-url origin)"
REPO="$(python3 - "$REMOTE" <<'PY'
import re, sys
remote = sys.argv[1]
m = re.search(r'github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$', remote)
if not m:
    raise SystemExit('Could not determine owner/repository from origin remote: ' + remote)
print(m.group(1))
PY
)"

VIDEO="$REPO_ROOT/docs/demo/cloudguard-ai-overview-demo.mp4"
README="$REPO_ROOT/README.md"
if [[ ! -f "$VIDEO" ]]; then
  echo "ERROR: Demo MP4 not found: $VIDEO"
  exit 1
fi
if ! grep -q 'GITHUB_INLINE_VIDEO_START' "$README" || ! grep -q 'GITHUB_INLINE_VIDEO_END' "$README"; then
  echo "ERROR: README inline-video markers are missing. Apply the CloudGuard update bundle first."
  exit 1
fi

cat <<'MSG'
This operation will:
- create a temporary GitHub issue in the repository,
- attach the MP4 as a GitHub-hosted video asset,
- insert the asset URL into README.md for inline playback,
- commit and push the README update,
- close the temporary issue after the asset is embedded.
MSG
read -r -p "Continue? [y/N] " ANSWER
if [[ ! "$ANSWER" =~ ^[Yy]$ ]]; then
  echo "Cancelled. No GitHub changes made."
  exit 0
fi

BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT
printf 'CloudGuard AI v2.0.1 short demo video.\n\n![](%s)\n' "$VIDEO" > "$BODY_FILE"

ISSUE_URL="$(gh issue create --repo "$REPO" --title 'CloudGuard AI v2.0.1 demo video asset' --body-file "$BODY_FILE" --attach "$VIDEO")"
ISSUE_BODY="$(gh issue view "$ISSUE_URL" --repo "$REPO" --json body --jq '.body')"
ASSET_URL="$(printf '%s\n' "$ISSUE_BODY" | grep -Eo 'https://github.com/user-attachments/assets/[A-Za-z0-9-]+' | head -n 1 || true)"

if [[ -z "$ASSET_URL" ]]; then
  echo "ERROR: GitHub issue was created, but the video asset URL could not be extracted."
  echo "Issue: $ISSUE_URL"
  echo "Open the issue, copy the video attachment URL, and replace the README marker manually."
  exit 1
fi

python3 - "$README" "$ASSET_URL" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
url = sys.argv[2]
s = p.read_text()
start = '<!-- GITHUB_INLINE_VIDEO_START -->'
end = '<!-- GITHUB_INLINE_VIDEO_END -->'
a = s.index(start) + len(start)
b = s.index(end, a)
s = s[:a] + '\n\n![](' + url + ')\n\n' + s[b:]
p.write_text(s)
PY

git -C "$REPO_ROOT" add README.md
git -C "$REPO_ROOT" diff --cached --check
git -C "$REPO_ROOT" commit -m "Embed CloudGuard AI demo video in README"
git -C "$REPO_ROOT" push origin HEAD

gh issue close "$ISSUE_URL" --repo "$REPO" --comment 'The demo video is now embedded in README.md. Closing this temporary media-upload issue.' >/dev/null

echo "Video uploaded and embedded in README: $ASSET_URL"
echo "Temporary media issue closed: $ISSUE_URL"
