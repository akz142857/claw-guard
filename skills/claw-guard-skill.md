---
name: claw-guard
description: AI Agent host system security audit — detect risks OpenClaw introduces to your system
version: 0.1.0
tags: security, audit, openclaw, system
---

# claw-guard Security Audit

Host system security audit tool. Checks what risks OpenClaw introduces to your system — credential exposure, network listeners, process privileges, and more.

## Data Format

File: `{baseDir}/claw-guard-history.json`

```json
{
  "reports": [
    {
      "time": "ISO8601",
      "score": 75,
      "total_rules": 23,
      "pass": 18,
      "fail": 3,
      "warn": 2,
      "critical": 1,
      "high": 2,
      "findings_summary": ["CG-C001: ~/.aws world-readable", "CG-G001: auth mode none"]
    }
  ]
}
```

## Install claw-guard

When user says "install claw-guard", "安装 claw-guard", or "安全审计工具":

```bash
ARCH=$(uname -m); OS=$(uname -s | tr '[:upper:]' '[:lower:]'); case "$ARCH" in x86_64|amd64) ARCH="amd64";; aarch64|arm64) ARCH="arm64";; esac; URL="https://github.com/user/claw-guard/releases/latest/download/claw-guard-${OS}-${ARCH}"; curl -fsSL "$URL" -o "{baseDir}/claw-guard" && chmod +x "{baseDir}/claw-guard" && echo "claw-guard installed to {baseDir}/claw-guard"
```

## Full Security Audit

When user says "安全检查", "security audit", "run claw-guard", or "检查系统安全":

```bash
RESULT=$("{baseDir}/claw-guard" --no-upload --json 2>/dev/null); if [ $? -eq 0 ] || [ $? -eq 1 ] || [ $? -eq 2 ]; then SCORE=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary.score)"); PASS=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary.pass)"); FAIL=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary.fail)"); CRIT=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary.critical_findings)"); FINDINGS=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));d.findings.filter(f=>f.status==='fail').forEach(f=>console.log(f.rule_id+': '+f.detail))"); node -e "const fs=require('fs');const f='{baseDir}/claw-guard-history.json';let h={reports:[]};try{h=JSON.parse(fs.readFileSync(f))}catch(e){}h.reports.push({time:new Date().toISOString(),score:${SCORE},pass:${PASS},fail:${FAIL},critical:${CRIT},findings_summary:$(echo "$FINDINGS" | node -e "const lines=require('fs').readFileSync('/dev/stdin','utf8').trim().split('\n').filter(Boolean);console.log(JSON.stringify(lines))")});fs.writeFileSync(f,JSON.stringify(h,null,2))"; echo "Score: ${SCORE}/100 | Pass: ${PASS} | Fail: ${FAIL} | Critical: ${CRIT}"; echo "---"; echo "$FINDINGS"; else echo "claw-guard not found. Say 'install claw-guard' first."; fi
```

## Audit by Category

When user says "检查凭证", "check credentials":

```bash
"{baseDir}/claw-guard" --no-upload --category credential
```

When user says "检查网络", "check network":

```bash
"{baseDir}/claw-guard" --no-upload --category network
```

When user says "检查网关", "check gateway":

```bash
"{baseDir}/claw-guard" --no-upload --category gateway
```

When user says "检查进程", "check process":

```bash
"{baseDir}/claw-guard" --no-upload --category process
```

When user says "检查容器", "check docker", "check container":

```bash
"{baseDir}/claw-guard" --no-upload --category docker
```

When user says "检查沙箱", "check sandbox":

```bash
"{baseDir}/claw-guard" --no-upload --category sandbox
```

## View Audit History

When user says "安全趋势", "audit history", "查看历史", or "历史报告":

```bash
node -e "const fs=require('fs');const f='{baseDir}/claw-guard-history.json';let h={reports:[]};try{h=JSON.parse(fs.readFileSync(f))}catch(e){console.log('No audit history yet. Run a security audit first.');process.exit(0)}if(h.reports.length===0){console.log('No audit history yet.');process.exit(0)}console.log('Audit History ('+h.reports.length+' reports):');console.log('---');h.reports.slice(-10).forEach((r,i)=>{const d=new Date(r.time).toLocaleString();console.log((i+1)+'. '+d+' | Score: '+r.score+'/100 | Fail: '+r.fail+' | Critical: '+(r.critical||0))});const last=h.reports[h.reports.length-1];const prev=h.reports.length>1?h.reports[h.reports.length-2]:null;if(prev){const diff=last.score-prev.score;console.log('---');console.log('Trend: '+(diff>0?'↑ +'+diff:diff<0?'↓ '+diff:'→ no change'))}"
```

## Compare Last Two Audits

When user says "对比", "compare audits", "安全对比":

```bash
node -e "const fs=require('fs');const f='{baseDir}/claw-guard-history.json';let h={reports:[]};try{h=JSON.parse(fs.readFileSync(f))}catch(e){console.log('No history.');process.exit(0)}if(h.reports.length<2){console.log('Need at least 2 audits to compare.');process.exit(0)}const[prev,curr]=[h.reports[h.reports.length-2],h.reports[h.reports.length-1]];console.log('Previous: '+new Date(prev.time).toLocaleString()+' | Score: '+prev.score);console.log('Current:  '+new Date(curr.time).toLocaleString()+' | Score: '+curr.score);const diff=curr.score-prev.score;console.log('Change:   '+(diff>0?'↑ +'+diff+' (improved)':diff<0?'↓ '+diff+' (degraded)':'→ no change'));const newIssues=curr.findings_summary.filter(f=>!prev.findings_summary.includes(f));const fixed=prev.findings_summary.filter(f=>!curr.findings_summary.includes(f));if(newIssues.length){console.log('New issues:');newIssues.forEach(f=>console.log('  + '+f))}if(fixed.length){console.log('Fixed:');fixed.forEach(f=>console.log('  - '+f))}"
```

## Clear History

When user says "清除历史", "clear audit history":

```bash
node -e "const fs=require('fs');fs.writeFileSync('{baseDir}/claw-guard-history.json',JSON.stringify({reports:[]},null,2));console.log('Audit history cleared.')"
```

## List All Rules

When user says "列出规则", "list rules", "有哪些检查项":

```bash
"{baseDir}/claw-guard" --list-rules
```

## Notes

- Uses claw-guard binary (Rust) for actual security checks
- History stored locally in JSON, never uploaded without consent
- claw-guard never uploads file contents, keys, or credentials
- Exit codes: 0 = all clear, 1 = HIGH findings, 2 = CRITICAL findings
- All timestamps in ISO8601 format
- File auto-created if missing
