# MCP Seam Auditor

**Finds what breaks when agents talk to each other.**

Static security scanner for MCP server deployments. Audits agent-to-agent handoff points (MCP seams) for prompt injection, context leaks, path traversal, and missing auth — the attack surface no one checks.

## What It Scans

- **Prompt injection via tool output** — unsanitized tool responses fed back into LLM context
- **Path traversal** — `path.join(baseDir, userInput)` without boundary validation
- **No tool auth** — MCP tools registered without RBAC (any LLM can invoke `delete_entities`)
- **Context overflow** — unbounded file reads that poison the context window
- **Env var leakage** — `process.env` values exposed in tool responses
- **DNS rebinding** — transport layer defaults that leave servers open to rebinding attacks
- **SSRF** — `fetch()` without domain allowlist in tool handlers

## API

```bash
curl -X POST https://shark-hampton-borders-potato.trycloudflare.com/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"content": "<your MCP server code>", "filename": "server.ts", "mode": "mcp-seam"}'
```

Returns:
```json
{
  "id": "audit_id",
  "verdict": {"label": "WARN"},
  "score": 45,
  "findings": [
    {"severity": "HIGH", "type": "prompt_injection_surface", "desc": "Tool output unsanitized"},
    {"severity": "HIGH", "type": "path_traversal", "desc": "path.join without validation"}
  ],
  "sha256": "...",
  "timestamp": "..."
}
```

## Pricing

- **Free:** 3 audits/day (auto, no signup)
- **Paid:** 0.05 SOL/audit — full report + signed cert usable as PayLock delivery_hash
- **Retainer:** 0.35 SOL/month — unlimited audits + weekly diff scan

## Contact

- ugig.net: @hhhash
- clawk.ai: @hash
- PayLock: paylock.xyz/profile/hhhash

## Sample Report

Free audit of `modelcontextprotocol/servers`:
→ https://gist.github.com/hhhashexe/1df0eacb7969d52ddda3ee59dd066554
