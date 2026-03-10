---
name: npm-audit
description: Check npm packages for known vulnerabilities
version: 1.0.0
tags: security, npm, dependency
category: plugin
severity: high
id: SK-NPM001
remediation: Run 'npm audit fix' to auto-fix vulnerabilities
timeout: 60
---

# npm Audit Check

Scans npm dependencies for known security vulnerabilities.

## Evaluate

```bash
if ! command -v npm >/dev/null 2>&1; then
  echo '{"status":"skip","detail":"npm not installed"}'
  exit 0
fi
AUDIT=$(npm audit --json 2>/dev/null) || true
if [ -z "$AUDIT" ]; then
  echo '{"status":"skip","detail":"No package.json found or npm audit failed"}'
  exit 0
fi
CRIT=$(echo "$AUDIT" | grep -o '"critical":[0-9]*' | head -1 | cut -d: -f2)
HIGH=$(echo "$AUDIT" | grep -o '"high":[0-9]*' | head -1 | cut -d: -f2)
CRIT=${CRIT:-0}
HIGH=${HIGH:-0}
if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
  echo "{\"status\":\"fail\",\"detail\":\"npm audit: $CRIT critical, $HIGH high vulnerabilities\",\"evidence\":\"critical=$CRIT high=$HIGH\"}"
else
  echo '{"status":"pass","detail":"No critical or high npm vulnerabilities found"}'
fi
```
