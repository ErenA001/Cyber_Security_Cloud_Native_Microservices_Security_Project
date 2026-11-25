#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"

if [[ -z "$REPO_ROOT" ]]; then
  echo "ERROR: Run this script from inside the cloned GitHub repository."
  exit 1
fi

if [[ ! -f "$BUNDLE_ROOT/VERSION" ]] || [[ "$(cat "$BUNDLE_ROOT/VERSION")" != "2.0.1" ]]; then
  echo "ERROR: Update bundle is missing or is not CloudGuard AI 2.0.1."
  exit 1
fi

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  echo "ERROR: The repository has uncommitted changes. Commit or stash them first."
  git -C "$REPO_ROOT" status --short
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync is required (normally available on macOS)."
  exit 1
fi

echo "Repository: $REPO_ROOT"
echo "Update bundle: $BUNDLE_ROOT"
echo "Copying CloudGuard AI 2.0.1 files (excluding secrets and local data)..."

rsync -a \
  --exclude='.git/' \
  --exclude='.env' \
  --exclude='backups/' \
  --exclude='reports/' \
  --exclude='*.db' \
  --exclude='*.sqlite3' \
  --exclude='.DS_Store' \
  "$BUNDLE_ROOT/" "$REPO_ROOT/"

if [[ -f "$REPO_ROOT/.env" ]]; then
  echo "Preserved existing .env locally; it will not be copied from the bundle."
fi

git -C "$REPO_ROOT" diff --check

git -C "$REPO_ROOT" add -A

git -C "$REPO_ROOT" diff --cached --check

echo
echo "===== STAGED CHANGE SUMMARY ====="
git -C "$REPO_ROOT" status --short
git -C "$REPO_ROOT" diff --cached --stat

echo
echo "The update is staged. No commit or push has happened yet."
read -r -p "Commit and push this update to origin on the current branch? [y/N] " ANSWER
if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
  git -C "$REPO_ROOT" commit -m "Upgrade CloudGuard AI to v2.0.1 with demo evidence"
  git -C "$REPO_ROOT" push origin HEAD
  echo "Update pushed successfully."
else
  echo "No commit or push performed. Review the staged changes and commit when ready."
fi
