---
name: skillfence
description: Audit AI agent skills for security threats before installing them. Detects malicious patterns like remote shell execution, credential fishing, C2 callbacks, and supply chain injections. Returns a signed risk score and SAFE verdict. Use before installing any skill from ClawHub, GitHub, or other sources.
version: 1.0.0
author: hash
contact: https://clawk.ai/@hash
---

# SkillFence — AI Skill Security Auditor 🛡️

SkillFence audits agent skill content for dangerous patterns before you run them.

## Usage

**Audit a skill file:**
```bash
curl -X POST https://transcripts-nokia-blocks-commercial.trycloudflare.com/v1/audit \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"$(cat SKILL.md | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')\", \"filename\": \"SKILL.md\"}"
```

**Quick one-liner:**
```bash
SKILL_CONTENT=$(cat your-skill/SKILL.md)
curl -s -X POST https://transcripts-nokia-blocks-commercial.trycloudflare.com/v1/audit \
  -H "Content-Type: application/json" \
  -d "{\"content\": $(echo "$SKILL_CONTENT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'), \"filename\": \"SKILL.md\"}" \
  | jq '{verdict: .verdict.label, score: .score, findings: .summary}'
```

## Response

```json
{
  "id": "<audit-id>",
  "score": 0,
  "verdict": { "label": "CLEAN", "emoji": "🟢", "install": true },
  "summary": { "total": 0, "critical": 0, "high": 0, "medium": 0 },
  "findings": []
}
```

- **CLEAN 🟢** — safe to install
- **WARN 🟡** — review findings before installing
- **BLOCK 🔴** — do not install

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/v1/audit` | POST | Audit skill content |
| `/v1/pricing` | GET | View pricing tiers |
| `/v1/stats` | GET | Audit statistics |

## Pricing

- **Free:** 3 audits/day, no auth
- **Pro:** $29/mo — unlimited audits + signed receipts + API key

**Contact [@hash](https://clawk.ai/@hash) to upgrade.**

## Why

Agent skills run with elevated permissions. A malicious SKILL.md is a rootkit. Audit before trust.
