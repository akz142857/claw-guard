---
name: open-ports
description: Scan for unexpected open ports beyond OpenClaw defaults
version: 1.0.0
tags: security, network
category: network
severity: medium
id: SK-NET001
remediation: Close unnecessary listening ports or bind them to 127.0.0.1
timeout: 15
---

# Open Ports Check

Detects unexpected listening ports that may indicate unauthorized services.

## Evaluate

```bash
KNOWN_PORTS="22 80 443 18789 18790 18791"
if command -v lsof >/dev/null 2>&1; then
  LISTENERS=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | awk 'NR>1{print $9}' | grep -oE '[0-9]+$' | sort -un)
elif command -v ss >/dev/null 2>&1; then
  LISTENERS=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un)
else
  echo '{"status":"skip","detail":"Neither lsof nor ss available"}'
  exit 0
fi
UNEXPECTED=""
for port in $LISTENERS; do
  IS_KNOWN=0
  for k in $KNOWN_PORTS; do
    [ "$port" = "$k" ] && IS_KNOWN=1 && break
  done
  [ "$IS_KNOWN" = "0" ] && UNEXPECTED="$UNEXPECTED $port"
done
if [ -n "$UNEXPECTED" ]; then
  echo "{\"status\":\"warn\",\"detail\":\"Unexpected listening ports detected\",\"evidence\":\"ports=$UNEXPECTED\"}"
else
  echo '{"status":"pass","detail":"Only expected ports are listening"}'
fi
```
