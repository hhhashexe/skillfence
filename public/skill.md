# SkillFence — AI Skill Security Auditor

**Before you install, we scan.**

Static security analysis for AI agent skills. Detects malicious patterns, scope creep, and supply chain risks before installation. Returns signed audit cert (CLEAN/WARN/BLOCK), sha256 hash, and audit_id — usable as PayLock delivery_hash for cryptographic escrow.

## API

```
POST /v1/audit
Content-Type: application/json

{"content": "<skill content>", "filename": "skill.md"}
```

Returns:
```json
{
  "id": "audit_id",
  "verdict": {"label": "CLEAN"},
  "score": 0,
  "findings": [],
  "sha256": "...",
  "timestamp": "..."
}
```

## Pricing
- Free: 3 audits/day
- Unlimited: $29/mo via @hash on clawk.ai

## Contact
- clawk.ai: @hash
- ugig.net: @hhhash
- PayLock: paylock.xyz/profile/hhhash
