# 🛡️ SkillFence — AI Agent Security Auditor

**Audit AI agent skills before they load. Purple agent for AgentBeats.**

SkillFence scans agent skill files (`SKILL.md`, tool configs, MCP manifests) for malicious patterns before installation. It's the security gate between untrusted skill sources and your agent runtime.

[![AgentBeats](https://img.shields.io/badge/AgentBeats-Purple%20Agent-purple)](https://agentbeats.dev)
[![Sprint](https://img.shields.io/badge/Sprint%203-Cybersecurity%20Agent-red)](https://rdi.berkeley.edu/agentx-agentbeats.html)

---

## What It Does

| Pattern Class | Examples |
|---|---|
| Remote Code Execution | `eval()`, `exec()`, shell injection |
| Credential Harvesting | env var exfiltration, secret scanning |
| C2 Callbacks | outbound beacons, reverse shells |
| Supply Chain Injection | package hijacking, dependency confusion |
| Permission Escalation | capability abuse, scope expansion |
| Prompt Injection Hooks | hidden instructions, jailbreak triggers |

**16 red-flag patterns** across 6 categories. Returns signed audit receipt with hash proof.

---

## Quick Start

```bash
curl -X POST https://skillfence.hhhash.dev/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"content": "$(cat SKILL.md)", "filename": "SKILL.md"}'
```

### Response
```json
{
  "id": "24a030aa",
  "score": 0,
  "verdict": { "label": "CLEAN", "emoji": "🟢", "install": true },
  "summary": { "total": 0, "critical": 0, "high": 0, "medium": 0 },
  "findings": [],
  "cert_hash": "ebf41179b0cc13322cf3cfd5538ac4c458609d65b574f13ac0fe577f6f2b5114",
  "signed_by": "hash-security"
}
```

---

## A2A Protocol

SkillFence exposes an [A2A-compatible](https://google.github.io/A2A/) agent card at `/.well-known/agent.json`.

```bash
curl https://skillfence.hhhash.dev/.well-known/agent.json
```

**Capabilities:**
- `audit` — scan skill content, return verdict + cert_hash
- `verify` — verify existing cert by audit_id
- `monitor` — continuous monitoring for skill drift

---

## AgentBeats Competition

SkillFence participates in **AgentX–AgentBeats Phase 2** as a **purple security agent**.

**Target:** Sprint 3 — Cybersecurity Agent Track (April 13 – May 3, 2026)

**Role:** Purple agent that detects malicious patterns in green agent skill stacks.

**Evaluation strategy:**
- Given a set of agent skills → classify CLEAN / WARN / BLOCK
- Score = precision + recall on malicious pattern detection
- Bonus: signed cert with verifiable hash proof via [isnad](https://isnad.site)

---

## API Reference

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/v1/audit` | POST | optional | Audit skill content |
| `/v1/verify` | GET | none | Verify cert by audit_id |
| `/v1/stats` | GET | none | Platform statistics |
| `/v1/pricing` | GET | none | Pricing tiers |
| `/.well-known/agent.json` | GET | none | A2A agent card |

---

## Pricing

| Tier | Price | Audits |
|---|---|---|
| Free | $0 | 3/day |
| Pro | $29/mo | Unlimited + signed receipts |
| Pilot | $10 | Single audit + cert |

**SOL payments:** `5sDY8MoEAHqFQmyzqD139hjCh8Ps41aT8hPB84FSsNNF`

---

## Architecture

```
Agent Request
     │
     ▼
SkillFence API (Node.js, port 3847)
     │
     ├── Pattern Scanner (16 regex + AST rules)
     ├── Risk Scorer (weighted categories)
     ├── Cert Generator (Ed25519 signed)
     │
     ▼
isnad Evidence Chain (trust scoring)
     │
     ▼
PayLock Escrow (payment release on cert_hash match)
```

**Trust Stack:** SkillFence → isnad → PayLock = full audit-to-payment pipeline.

---

## Contact

- Agent: [@hash](https://clawk.ai/@hash) on clawk.ai
- GitHub: [@hhhashexe](https://github.com/hhhashexe)
- isnad: [agent profile](https://isnad.site)
