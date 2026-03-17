# 🛡️ SkillFence

> **"Genuinely one of the best security audits I received — 4 rounds, 9 GitHub issues, honest FP corrections, and actionable fixes. Professional-grade work."**
> — kai, founder of AgentPass

Security scanner for AI agent skills, MCP servers, and tool configs.

[![npm](https://img.shields.io/npm/v/skillfence)](https://npmjs.com/package/skillfence)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Why SkillFence?

**43% of MCP servers contain security vulnerabilities.** Most ship with prompt injection vectors, data exfiltration paths, or hardcoded credentials — and nobody scans them before installation.

SkillFence catches these before they reach production:

- ✅ **coinpayportal.com** — 18 critical/high security issues found and patched *(CORS wildcard on payment API, zero rate limiting, admin exposure)*
- ✅ **AgentPass** — 9 issues across 4 audit rounds *(CRITICAL: default JWT secret in public repo, trust score manipulation)*
- ✅ **isnad.site** — 11 issues *(unauthenticated evidence submission, replay attacks)*

## Quick Start

```bash
npx skillfence scan .              # Scan current directory
npx skillfence scan SKILL.md       # Scan a file
npx skillfence scan --stdin        # Pipe from stdin
npx skillfence rules               # List all 76 rules
```

## What It Detects

**76 detection rules** across 12 categories, mapped to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/):

| Category | Rules | Examples |
|----------|-------|---------|
| 🔴 Remote Code Execution | 5 | curl pipe to shell, eval(), child_process |
| 🎯 Prompt Injection | 5 | instruction override, role hijacking, hidden prompts |
| 🔑 Credential Exposure | 5 | API keys, .env access, hardcoded secrets |
| 💀 Destructive Operations | 4 | rm -rf, filesystem wipe, DROP TABLE |
| 📤 Data Exfiltration | 6 | DNS tunneling, base64 encoding, file upload |
| ⚡ MCP Attacks | 9 | tool poisoning, sampling abuse, forced execution, CORS |
| 🧠 AI Safety | 8 | LangChain exploits, pickle RCE, HuggingFace code exec |
| 🔐 Authentication | 3 | disabled auth, weak JWT, TLS bypass |
| 📊 PII / Data Leak | 3 | password logging, token exposure, training data PII |
| 🚫 DoS / Availability | 3 | infinite loops, rate limit bypass, token exhaustion |
| 📦 Supply Chain | 6 | typosquatting, lifecycle scripts, unsafe-perm |
| 💰 Crypto / Financial | 4 | wallet theft, transaction signing, token approvals |
| 🔒 Privilege Escalation | 1 | sudo usage |

## What Our Clients Say

> **"The audit was thorough — 18 security issues filed, all fixed in one batch PR. Rate limiting, CORS, admin exposure — everything caught and patched."**
> — Anthony Ettinger (chovy), founder of coinpayportal.com & ugig.net

> **"Genuinely one of the best security audits I received — 4 rounds, 9 GitHub issues, honest FP corrections, and actionable fixes for everything. Professional-grade work."**
> — kai, founder of AgentPass (agentpass.space)

## Pre-Commit Hook

Block dangerous code before it's committed:

```bash
npx skillfence install-hook    # Install git pre-commit hook
```

Commits with CRITICAL findings are blocked. Use `git commit --no-verify` to bypass.

## GitHub Action

```yaml
- uses: hhhashexe/skillfence@main
  with:
    path: '.'
    fail-on: 'BLOCK'
```

## Output Formats

```bash
npx skillfence scan . --json     # JSON output for CI/CD
npx skillfence scan . --sarif    # SARIF for GitHub Security tab
```

## Exit Codes

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | CLEAN | No issues found |
| 1 | REVIEW | Low-severity findings |
| 2 | WARN | Medium-severity findings |
| 3 | BLOCK | Critical issues — must fix |

## Install Globally

```bash
npm install -g skillfence
skillfence scan /path/to/project
```

## Zero Dependencies

SkillFence has **zero npm dependencies**. Just Node.js 16+.

## API

SkillFence also offers a hosted API for CI/CD integration:

```bash
curl -X POST https://your-instance/audit   -H "Content-Type: application/json"   -d '{"skill_content": "..."}'
```

## License

MIT
