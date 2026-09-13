#!/usr/bin/env bash
# push_to_github.sh — sync WhoCord to github.com/sivnick/whocord
set -euo pipefail

PROJECT_DIR="/home/beejaay/whocord"
REPO_URL="git@github.com:sivnick/whocord.git"   # swap to https if you use a PAT
BRANCH="main"
COMMIT_MSG="${1:-chore: sync source $(date -u +%Y-%m-%dT%H:%MZ)}"

cd "$PROJECT_DIR"

# 1. Init repo if it does not exist yet
if [ ! -d .git ]; then
    echo "→ Initialising new git repository…"
    git init -b "$BRANCH"
fi

# 2. Make sure the remote is set (and correct)
if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

# 3. Ensure .gitignore exists (safety net)
[ -f .gitignore ] || { echo "✗ .gitignore missing — create it first"; exit 1; }

# 4. Stage everything that passes the ignore rules
git add -A

# 5. Bail out cleanly if there is nothing to commit
if git diff --cached --quiet; then
    echo "✓ Nothing to commit — repository already up to date."
    exit 0
fi

# 6. Commit
git commit -m "$COMMIT_MSG"

# 7. Push (creates the branch on the remote if needed)
echo "→ Pushing to origin/$BRANCH …"
git push -u origin "$BRANCH"

echo
echo "✓ Done.  View at: https://github.com/sivnick/whocord"