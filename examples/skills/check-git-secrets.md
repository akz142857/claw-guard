---
name: git-secrets
description: Check git repos for accidentally committed secrets
version: 1.0.0
tags: security, git, credential
category: credential
severity: critical
id: SK-GIT001
remediation: Remove secrets from git history using git filter-branch or BFG Repo Cleaner, then rotate the exposed credentials
timeout: 30
---

# Git Secrets Check

Scans recent git log for common secret patterns (API keys, tokens, passwords).

## Evaluate

```bash
if ! command -v git >/dev/null 2>&1; then
  echo '{"status":"skip","detail":"git not installed"}'
  exit 0
fi
FOUND=""
for dir in "$HOME/workspace" "$HOME/projects" "$HOME/src" "$HOME/code"; do
  [ -d "$dir" ] || continue
  for repo in "$dir"/*/; do
    [ -d "$repo/.git" ] || continue
    MATCHES=$(git -C "$repo" log --oneline -20 --diff-filter=A -p 2>/dev/null | grep -ciE '(AKIA[A-Z0-9]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|password\s*=\s*["\x27][^\s]{8,})' || true)
    if [ "$MATCHES" -gt 0 ] 2>/dev/null; then
      FOUND="$FOUND $(basename "$repo"):$MATCHES"
    fi
  done
done
if [ -n "$FOUND" ]; then
  echo "{\"status\":\"fail\",\"detail\":\"Secret patterns found in git history\",\"evidence\":\"repos=$FOUND\"}"
else
  echo '{"status":"pass","detail":"No secret patterns found in recent git commits"}'
fi
```
