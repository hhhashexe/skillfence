/**
 * SkillFence Security Patterns v1.1
 * 52 detection rules mapped to OWASP MCP Top 10
 */

const PATTERNS = [
  // ═══════════════════════════════════════
  // CRITICAL — Remote Code Execution
  // ═══════════════════════════════════════
  { id: 'RCE-001', re: /curl\s[^|]*\|\s*(ba)?sh/gi,           sev: 'CRITICAL', cat: 'rce', desc: 'Remote shell via curl pipe', owasp: 'MCP-01', fix: 'Download file first, verify checksum, then execute' },
  { id: 'RCE-002', re: /wget\s[^|]*\|\s*(ba)?sh/gi,           sev: 'CRITICAL', cat: 'rce', desc: 'Remote shell via wget pipe', owasp: 'MCP-01', fix: 'Download file first, verify checksum, then execute' },
  { id: 'RCE-003', re: /\/dev\/tcp\//gi,                       sev: 'CRITICAL', cat: 'rce', desc: 'Bash TCP redirect — reverse shell', owasp: 'MCP-01', fix: 'Remove /dev/tcp usage entirely' },
  { id: 'RCE-004', re: /nc\s+-[elp]/gi,                        sev: 'CRITICAL', cat: 'rce', desc: 'Netcat with listener/exec — reverse shell', owasp: 'MCP-01', fix: 'Remove netcat listener usage' },
  { id: 'RCE-005', re: /python[3]?\s+-c\s+['"]/gi,             sev: 'HIGH',     cat: 'rce', desc: 'Inline Python execution', owasp: 'MCP-01', fix: 'Use a script file instead of inline code' },
  { id: 'RCE-006', re: /powershell\s.*-e(nc|ncodedCommand)/gi, sev: 'CRITICAL', cat: 'rce', desc: 'PowerShell encoded command — obfuscated exec', owasp: 'MCP-01', fix: 'Never use encoded PowerShell commands' },

  // ═══════════════════════════════════════
  // CRITICAL — Code Injection
  // ═══════════════════════════════════════
  { id: 'INJ-001', re: /eval\s*\(/gi,                          sev: 'HIGH',     cat: 'injection', desc: 'eval() — dynamic code execution', owasp: 'MCP-02', fix: 'Use JSON.parse() or a safe parser instead' },
  { id: 'INJ-002', re: /exec\s*\(/gi,                          sev: 'HIGH',     cat: 'injection', desc: 'exec() — shell command execution', owasp: 'MCP-02', fix: 'Use execFile() with argument array' },
  { id: 'INJ-003', re: /os\.system\s*\(/gi,                    sev: 'HIGH',     cat: 'injection', desc: 'os.system() — Python shell injection', owasp: 'MCP-02', fix: 'Use subprocess.run() with shell=False' },
  { id: 'INJ-004', re: /subprocess\..*shell\s*=\s*True/gi,     sev: 'HIGH',     cat: 'injection', desc: 'subprocess with shell=True', owasp: 'MCP-02', fix: 'Set shell=False and pass args as list' },
  { id: 'INJ-005', re: /child_process/gi,                      sev: 'MEDIUM',   cat: 'injection', desc: 'Node.js child_process import', owasp: 'MCP-02', fix: 'Ensure arguments are sanitized' },
  { id: 'INJ-006', re: /Function\s*\(\s*['"]/gi,               sev: 'HIGH',     cat: 'injection', desc: 'Dynamic Function constructor', owasp: 'MCP-02', fix: 'Avoid dynamic function creation' },

  // ═══════════════════════════════════════
  // HIGH — Credential Access
  // ═══════════════════════════════════════
  { id: 'CRED-001', re: /\.ssh\//gi,                           sev: 'HIGH',     cat: 'credential', desc: 'SSH directory access', owasp: 'MCP-03', fix: 'Never access SSH keys from agent tools' },
  { id: 'CRED-002', re: /\.aws\//gi,                           sev: 'HIGH',     cat: 'credential', desc: 'AWS credentials directory access', owasp: 'MCP-03', fix: 'Use IAM roles, not credential files' },
  { id: 'CRED-003', re: /\.env\b/gi,                           sev: 'MEDIUM',   cat: 'credential', desc: '.env file access — potential secret leak', owasp: 'MCP-03', fix: 'Use secret managers instead' },
  { id: 'CRED-004', re: /process\.env\.[A-Z_]{3,}/gi,          sev: 'MEDIUM',   cat: 'credential', desc: 'Environment variable access', owasp: 'MCP-03', fix: 'Limit env access to necessary vars only' },
  { id: 'CRED-005', re: /ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN/gi, sev: 'CRITICAL', cat: 'credential', desc: 'Known API key variable access', owasp: 'MCP-03', fix: 'Never reference API keys in skill files' },
  { id: 'CRED-006', re: /auth-profiles\.json/gi,               sev: 'CRITICAL', cat: 'credential', desc: 'OpenClaw auth profiles — credential theft', owasp: 'MCP-03', fix: 'Never access auth profiles from tools' },
  { id: 'CRED-007', re: /openclaw\.json/gi,                    sev: 'CRITICAL', cat: 'credential', desc: 'OpenClaw config access — key theft risk', owasp: 'MCP-03', fix: 'Config files must be read-only for tools' },
  { id: 'CRED-008', re: /MEMORY\.md/gi,                        sev: 'HIGH',     cat: 'credential', desc: 'Agent memory file access — data leak', owasp: 'MCP-03', fix: 'Agent memory should never be read by tools' },

  // ═══════════════════════════════════════
  // HIGH — Data Exfiltration
  // ═══════════════════════════════════════
  { id: 'EXFIL-001', re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi, sev: 'HIGH', cat: 'exfiltration', desc: 'HTTP request to IP address — C2 beacon', owasp: 'MCP-04', fix: 'Use domain names, not raw IPs' },
  { id: 'EXFIL-002', re: /base64\s+(-d|--decode)/gi,           sev: 'HIGH',     cat: 'exfiltration', desc: 'Base64 decode — payload obfuscation', owasp: 'MCP-04', fix: 'Inspect decoded content manually' },
  { id: 'EXFIL-003', re: /btoa\s*\(|atob\s*\(/gi,              sev: 'MEDIUM',   cat: 'exfiltration', desc: 'Browser base64 encoding/decoding', owasp: 'MCP-04', fix: 'Ensure not used for data obfuscation' },
  { id: 'EXFIL-004', re: /webhook\.site|hookbin|requestbin|pipedream/gi, sev: 'CRITICAL', cat: 'exfiltration', desc: 'Known data exfiltration endpoint', owasp: 'MCP-04', fix: 'Remove all webhook/capture service URLs' },
  { id: 'EXFIL-005', re: /ngrok\.io|trycloudflare\.com.*\/receive/gi, sev: 'HIGH', cat: 'exfiltration', desc: 'Tunnel endpoint — potential data exfiltration', owasp: 'MCP-04', fix: 'Verify tunnel is authorized' },

  // ═══════════════════════════════════════
  // HIGH — Prompt Injection
  // ═══════════════════════════════════════
  { id: 'PI-001', re: /ignore\s+(all\s+)?previous\s+instructions/gi, sev: 'CRITICAL', cat: 'prompt_injection', desc: 'Classic prompt injection — instruction override', owasp: 'MCP-05', fix: 'Remove prompt injection payload' },
  { id: 'PI-002', re: /you\s+are\s+now\s+[a-z]+/gi,            sev: 'HIGH',     cat: 'prompt_injection', desc: 'Role hijacking attempt', owasp: 'MCP-05', fix: 'Remove role reassignment text' },
  { id: 'PI-003', re: /system\s*:\s*you/gi,                     sev: 'HIGH',     cat: 'prompt_injection', desc: 'Fake system prompt injection', owasp: 'MCP-05', fix: 'Remove system prompt spoofing' },
  { id: 'PI-004', re: /\[INST\]|\[\/INST\]|<\|im_start\|>/gi,  sev: 'CRITICAL', cat: 'prompt_injection', desc: 'Raw model control tokens in skill', owasp: 'MCP-05', fix: 'Remove model-specific control tokens' },
  { id: 'PI-005', re: /<!--.*(?:ignore|override|system).*-->/gi, sev: 'HIGH',    cat: 'prompt_injection', desc: 'Hidden instruction in HTML comment', owasp: 'MCP-05', fix: 'Remove hidden instructions from comments' },

  // ═══════════════════════════════════════
  // MEDIUM — Destructive Operations
  // ═══════════════════════════════════════
  { id: 'DESTR-001', re: /rm\s+-rf\s+[\/~]/gi,                 sev: 'CRITICAL', cat: 'destructive', desc: 'Recursive delete from root or home', owasp: 'MCP-06', fix: 'Use trash/safe delete instead' },
  { id: 'DESTR-002', re: /chmod\s+777/gi,                      sev: 'HIGH',     cat: 'destructive', desc: 'World-writable permissions', owasp: 'MCP-06', fix: 'Use minimal required permissions' },
  { id: 'DESTR-003', re: /mkfs|fdisk|dd\s+if=/gi,              sev: 'CRITICAL', cat: 'destructive', desc: 'Disk formatting / raw write', owasp: 'MCP-06', fix: 'Never allow disk operations from tools' },

  // ═══════════════════════════════════════
  // HIGH — MCP-Specific Attacks
  // ═══════════════════════════════════════
  { id: 'MCP-001', re: /tool_description[\s\S]*?<\!--/gi,      sev: 'CRITICAL', cat: 'mcp_attack', desc: 'Hidden instructions in tool description (tool poisoning)', owasp: 'MCP-07', fix: 'Remove HTML comments from tool descriptions' },
  { id: 'MCP-002', re: /rug_pull|shadow_tool|tool_swap/gi,      sev: 'CRITICAL', cat: 'mcp_attack', desc: 'Tool rug pull / swap indicators', owasp: 'MCP-07', fix: 'Pin tool versions and verify checksums' },
  { id: 'MCP-003', re: /list_tools_changed|tools\/list.*override/gi, sev: 'HIGH', cat: 'mcp_attack', desc: 'Dynamic tool list manipulation', owasp: 'MCP-07', fix: 'Use static tool manifests' },
  { id: 'MCP-004', re: /cross_origin|cross.?server.*call/gi,    sev: 'HIGH',     cat: 'mcp_attack', desc: 'Cross-origin MCP server call', owasp: 'MCP-08', fix: 'Restrict MCP server communication to allowed origins' },

  // ═══════════════════════════════════════
  // MEDIUM — Privilege Escalation
  // ═══════════════════════════════════════
  { id: 'PRIV-001', re: /sudo\s/gi,                             sev: 'HIGH',     cat: 'privilege', desc: 'sudo usage — privilege escalation', owasp: 'MCP-09', fix: 'Run tools with minimal privileges' },
  { id: 'PRIV-002', re: /--privileged|--cap-add/gi,             sev: 'HIGH',     cat: 'privilege', desc: 'Docker privileged mode', owasp: 'MCP-09', fix: 'Use minimal container capabilities' },
  { id: 'PRIV-003', re: /setuid|setgid|chown\s+root/gi,        sev: 'HIGH',     cat: 'privilege', desc: 'File ownership / SUID change', owasp: 'MCP-09', fix: 'Avoid changing file ownership in tools' },

  // ═══════════════════════════════════════
  // MEDIUM — Supply Chain
  // ═══════════════════════════════════════
  { id: 'SC-001', re: /npm\s+install\s+[^-]/gi,                 sev: 'MEDIUM',   cat: 'supply_chain', desc: 'Dynamic npm install in skill', owasp: 'MCP-10', fix: 'Pre-install dependencies, do not install at runtime' },
  { id: 'SC-002', re: /pip\s+install\s+[^-]/gi,                 sev: 'MEDIUM',   cat: 'supply_chain', desc: 'Dynamic pip install in skill', owasp: 'MCP-10', fix: 'Pre-install dependencies, do not install at runtime' },
  { id: 'SC-003', re: /curl.*\|\s*pip|wget.*\|\s*pip/gi,        sev: 'CRITICAL', cat: 'supply_chain', desc: 'Pipe to pip — untrusted package install', owasp: 'MCP-10', fix: 'Never pipe network output to package managers' },
  { id: 'SC-004', re: /--break-system-packages/gi,              sev: 'HIGH',     cat: 'supply_chain', desc: 'System package override flag', owasp: 'MCP-10', fix: 'Use virtual environments instead' },
  { id: 'SC-005', re: /npm\s+.*--unsafe-perm/gi,                sev: 'HIGH',     cat: 'supply_chain', desc: 'npm unsafe permissions flag', owasp: 'MCP-10', fix: 'Remove --unsafe-perm flag' },

  // ═══════════════════════════════════════
  // MEDIUM — Crypto / Wallet
  // ═══════════════════════════════════════
  { id: 'CRYPTO-001', re: /private.?key|seed.?phrase|mnemonic/gi, sev: 'CRITICAL', cat: 'crypto', desc: 'Cryptocurrency private key / seed phrase access', owasp: 'MCP-03', fix: 'Never handle crypto keys in agent tools' },
  { id: 'CRYPTO-002', re: /solana|phantom|metamask.*password/gi,  sev: 'HIGH',    cat: 'crypto', desc: 'Wallet application targeting', owasp: 'MCP-03', fix: 'Remove wallet-targeting code' },

  // ═══════════════════════════════════════
  // LOW — Information Disclosure
  // ═══════════════════════════════════════
  { id: 'INFO-001', re: /console\.log.*password|console\.log.*token|console\.log.*key/gi, sev: 'MEDIUM', cat: 'info_disclosure', desc: 'Logging sensitive data', owasp: 'MCP-04', fix: 'Remove sensitive data from log output' },
  { id: 'INFO-002', re: /DEBUG\s*=\s*[Tt]rue|NODE_ENV.*development/gi, sev: 'LOW', cat: 'info_disclosure', desc: 'Debug mode enabled', owasp: 'MCP-04', fix: 'Disable debug mode in production' },
];

// Suspicious domain patterns
const SUSPICIOUS_DOMAINS = [
  /https?:\/\/[a-z0-9]+\.onion/gi,
  /https?:\/\/paste(?:bin)?\.com/gi,
  /https?:\/\/transfer\.sh/gi,
  /https?:\/\/file\.io/gi,
];

module.exports = { PATTERNS, SUSPICIOUS_DOMAINS };

// Additional patterns to reach 52
const EXTRA_PATTERNS = [
  { id: 'MCP-005', re: /sampling.*create|createMessage.*sampling/gi, sev: 'HIGH', cat: 'mcp_attack', desc: 'MCP sampling abuse — autonomous message creation', owasp: 'MCP-07', fix: 'Require human approval for sampling' },
  { id: 'EXFIL-006', re: /FormData|multipart.*upload|upload.*file/gi, sev: 'MEDIUM', cat: 'exfiltration', desc: 'File upload capability — potential exfiltration', owasp: 'MCP-04', fix: 'Restrict upload destinations to allowed domains' },
  { id: 'INJ-007', re: /new\s+Function\s*\(/gi, sev: 'HIGH', cat: 'injection', desc: 'Dynamic Function constructor (alternative to eval)', owasp: 'MCP-02', fix: 'Avoid dynamic code generation' },
];

// Merge extra patterns
PATTERNS.push(...EXTRA_PATTERNS);

// === v1.2 AI/LLM SPECIFIC RULES ===
const V12_PATTERNS = [
  // AI Safety
  { id: 'AI-001', re: /load_tools\s*\(\s*\[.*"terminal"/gi, sev: 'HIGH', cat: 'ai_safety', desc: 'LangChain terminal tool — arbitrary command execution', owasp: 'MCP-02', fix: 'Remove terminal tool or sandbox execution' },
  { id: 'AI-002', re: /PythonREPL|python_repl/gi, sev: 'CRITICAL', cat: 'ai_safety', desc: 'Python REPL tool — unrestricted code execution', owasp: 'MCP-02', fix: 'Use sandboxed execution environment' },
  { id: 'AI-003', re: /pickle\.load|torch\.load|joblib\.load/gi, sev: 'HIGH', cat: 'ai_safety', desc: 'Unsafe deserialization — potential RCE', owasp: 'MCP-02', fix: 'Use safetensors or JSON serialization' },
  { id: 'AI-004', re: /trust_remote_code\s*=\s*True/gi, sev: 'MEDIUM', cat: 'ai_safety', desc: 'HuggingFace trust_remote_code enabled', owasp: 'MCP-02', fix: 'Set trust_remote_code=False' },
  { id: 'AI-005', re: /langchain.*SQLDatabase|create_sql_agent/gi, sev: 'HIGH', cat: 'ai_safety', desc: 'LangChain SQL agent — SQL injection via LLM', owasp: 'MCP-02', fix: 'Use read-only DB and query whitelists' },
  { id: 'AI-006', re: /allow_dangerous_requests?\s*=\s*True/gi, sev: 'MEDIUM', cat: 'ai_safety', desc: 'Dangerous requests explicitly enabled', owasp: 'MCP-06', fix: 'Disable allow_dangerous_requests' },
  { id: 'AI-007', re: /AutoGPT|BabyAGI|CrewAI.*allow_code/gi, sev: 'HIGH', cat: 'ai_safety', desc: 'Autonomous agent with code execution', owasp: 'MCP-02', fix: 'Add human approval gates' },
  { id: 'AI-008', re: /\.run\(.*user_input|\.invoke\(.*user_input/gi, sev: 'MEDIUM', cat: 'ai_safety', desc: 'Direct user input to LLM chain — injection risk', owasp: 'MCP-05', fix: 'Sanitize input before chain' },
  // PII / Data Leak
  { id: 'PII-001', re: /console\.log\(.*password|print\(.*password|logger\.\w+\(.*password/gi, sev: 'MEDIUM', cat: 'data_leak', desc: 'Password logged to console', owasp: 'MCP-04', fix: 'Never log passwords' },
  { id: 'PII-002', re: /console\.log\(.*token|print\(.*api.?key/gi, sev: 'MEDIUM', cat: 'data_leak', desc: 'API token logged to output', owasp: 'MCP-04', fix: 'Redact tokens in logs' },
  { id: 'PII-003', re: /training.?data.*personal|fine.?tun.*private|embed.*pii/gi, sev: 'HIGH', cat: 'data_leak', desc: 'PII in training data reference', owasp: 'MCP-04', fix: 'Scrub PII from training data' },
  // DoS / Availability
  { id: 'DOS-001', re: /while\s*\(\s*true\s*\)|for\s*\(\s*;;\s*\)/gi, sev: 'MEDIUM', cat: 'availability', desc: 'Infinite loop — potential DoS', owasp: 'MCP-06', fix: 'Add loop bounds and timeout' },
  { id: 'DOS-002', re: /no.?rate.?limit|disable.?throttl|unlimited.?request/gi, sev: 'MEDIUM', cat: 'availability', desc: 'Rate limiting disabled', owasp: 'MCP-06', fix: 'Implement rate limiting' },
  { id: 'DOS-003', re: /max.?tokens?\s*[:=]\s*\d{5,}/gi, sev: 'LOW', cat: 'availability', desc: 'Very high max_tokens — cost/DoS risk', owasp: 'MCP-06', fix: 'Set reasonable token limits' },
  // MCP Advanced
  { id: 'MCP-ADV-001', re: /tool_choice\s*[:=]\s*["']?required/gi, sev: 'CRITICAL', cat: 'mcp_attack', desc: 'Forced tool execution — bypasses model judgment', owasp: 'MCP-01', fix: 'Use tool_choice=auto' },
  { id: 'MCP-ADV-002', re: /server\.tool\(.*\bexec\b|server\.tool\(.*\bspawn\b/gi, sev: 'HIGH', cat: 'mcp_attack', desc: 'MCP tool with exec/spawn — command injection', owasp: 'MCP-02', fix: 'Validate all tool inputs' },
  { id: 'MCP-ADV-003', re: /allowedTools\s*[:=]\s*\[\s*["']\*["']\s*\]|toolFilter.*all/gi, sev: 'HIGH', cat: 'mcp_attack', desc: 'Wildcard tool permissions', owasp: 'MCP-01', fix: 'Whitelist required tools only' },
  { id: 'MCP-ADV-004', re: /cross.?origin|cors\s*[:=]\s*["']\*/gi, sev: 'HIGH', cat: 'mcp_attack', desc: 'CORS wildcard on MCP server', owasp: 'MCP-08', fix: 'Restrict CORS origins' },
  // Auth
  { id: 'AUTH-001', re: /auth\s*[:=]\s*["']?none|authentication\s*[:=]\s*false|no.?auth/gi, sev: 'CRITICAL', cat: 'auth', desc: 'Authentication disabled — open access', owasp: 'MCP-08', fix: 'Enable authentication' },
  { id: 'AUTH-002', re: /jwt.?secret\s*[:=]\s*["'][^"']{1,20}["']/gi, sev: 'HIGH', cat: 'auth', desc: 'Weak JWT secret — brute-forceable', owasp: 'MCP-03', fix: 'Use 256+ bit random secret' },
  { id: 'AUTH-003', re: /verify\s*[:=]\s*false|rejectUnauthorized\s*[:=]\s*false/gi, sev: 'HIGH', cat: 'auth', desc: 'TLS verification disabled — MITM risk', owasp: 'MCP-08', fix: 'Enable TLS verification' },
  // Supply Chain Advanced
  { id: 'SC-ADV-001', re: /postinstall|preinstall/gi, sev: 'HIGH', cat: 'supply_chain', desc: 'npm lifecycle script — code on install', owasp: 'MCP-10', fix: 'Audit install scripts' },
  // Crypto Advanced
  { id: 'CRYPTO-ADV-001', re: /transfer\(|sendTransaction|signTransaction/gi, sev: 'CRITICAL', cat: 'crypto', desc: 'Blockchain transaction signing', owasp: 'MCP-03', fix: 'Require human approval for transactions' },
  { id: 'CRYPTO-ADV-002', re: /approve\(.*uint256|setApprovalForAll/gi, sev: 'HIGH', cat: 'crypto', desc: 'Token approval — unlimited spending risk', owasp: 'MCP-03', fix: 'Set specific approval amounts' },
];

PATTERNS.push(...V12_PATTERNS);

// === v2.0 PATTERNS — From n8n deep audit + real-world findings ===
const V20_PATTERNS = [
  // CORS Misconfiguration
  { id: 'CORS-001', re: /Access-Control-Allow-Origin['":\s]*\*|allowedOrigins.*\[.*['"]?\*['"]?\s*\]/gi, sev: 'HIGH', cat: 'cors', desc: 'CORS wildcard origin — any website can access API', owasp: 'MCP-08', fix: 'Restrict allowed origins to specific domains' },
  { id: 'CORS-002', re: /Allow-Origin.*req\.headers\.origin|Allow-Origin.*request.*origin/gi, sev: 'CRITICAL', cat: 'cors', desc: 'CORS origin reflection — mirrors any origin (SSRF/cookie theft)', owasp: 'MCP-08', fix: 'Validate origin against allowlist, never reflect blindly' },
  { id: 'CORS-003', re: /Allow-Credentials.*true.*Allow-Origin|allowCredentials.*true/gi, sev: 'HIGH', cat: 'cors', desc: 'CORS credentials + permissive origin — cookie theft risk', owasp: 'MCP-08', fix: 'Never combine Allow-Credentials:true with wildcard/reflected origin' },

  // AI Tool Safety (from n8n usableAsTool finding)
  { id: 'AI-TOOL-001', re: /usableAsTool\s*[:=]\s*true/gi, sev: 'HIGH', cat: 'ai_safety', desc: 'Node exposed as AI Agent tool — verify HITL gate exists', owasp: 'MCP-01', fix: 'Add Human-in-the-Loop approval for dangerous tools' },
  { id: 'AI-TOOL-002', re: /usableAsTool.*exec|exec.*usableAsTool/gi, sev: 'CRITICAL', cat: 'ai_safety', desc: 'Shell execution exposed as AI tool — prompt injection → RCE', owasp: 'MCP-01', fix: 'Remove usableAsTool or add mandatory HITL gate + command allowlist' },

  // SSRF
  { id: 'SSRF-001', re: /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/gi, sev: 'CRITICAL', cat: 'ssrf', desc: 'Cloud metadata endpoint — SSRF target', owasp: 'MCP-04', fix: 'Block requests to cloud metadata endpoints' },
  { id: 'SSRF-002', re: /127\.0\.0\.1|localhost:\d|0\.0\.0\.0/gi, sev: 'MEDIUM', cat: 'ssrf', desc: 'Localhost/loopback reference — potential SSRF', owasp: 'MCP-04', fix: 'Validate URLs against internal network ranges' },

  // JWT / Session Security
  { id: 'JWT-001', re: /jwtSecret\s*=\s*['"][^'"]{1,20}['"]/gi, sev: 'HIGH', cat: 'auth', desc: 'Weak/short JWT secret — brute-forceable', owasp: 'MCP-03', fix: 'Use 256+ bit cryptographically random secret' },
  { id: 'JWT-002', re: /createHash.*every.*char|baseKey.*\+=.*encryptionKey\[i/gi, sev: 'HIGH', cat: 'auth', desc: 'JWT secret derived with weak algorithm — reduced entropy', owasp: 'MCP-03', fix: 'Use full-strength key derivation (HKDF, scrypt, Argon2)' },
  { id: 'JWT-003', re: /sameSite\s*[:=]\s*['"]?none['"]?/gi, sev: 'HIGH', cat: 'auth', desc: 'Cookie SameSite=none — cross-site request allowed', owasp: 'MCP-08', fix: 'Use SameSite=strict or lax unless cross-site is required' },
  { id: 'JWT-004', re: /secure\s*[:=]\s*false|cookie.*secure.*false/gi, sev: 'MEDIUM', cat: 'auth', desc: 'Cookie secure flag disabled — sent over HTTP', owasp: 'MCP-08', fix: 'Set secure: true for auth cookies' },

  // Deprecated/Vulnerable Dependencies
  { id: 'DEP-001', re: /from\s+['"]vm2['"]\s|require\s*\(\s*['"]vm2['"]\s*\)/gi, sev: 'HIGH', cat: 'supply_chain', desc: 'vm2 import — deprecated library with multiple sandbox escapes', owasp: 'MCP-10', fix: 'Migrate to isolated-vm or Node.js task runner' },
  { id: 'DEP-002', re: /from\s+['"]node-serialize['"]\s|require\s*\(\s*['"]node-serialize['"]\s*\)/gi, sev: 'CRITICAL', cat: 'supply_chain', desc: 'node-serialize — known RCE via deserialization', owasp: 'MCP-10', fix: 'Use JSON.parse/JSON.stringify instead' },

  // Weak Crypto
  { id: 'WCRYPTO-001', re: /createHash\s*\(\s*['"]md5['"]\s*\)/gi, sev: 'MEDIUM', cat: 'crypto', desc: 'MD5 hash — cryptographically broken', owasp: 'MCP-03', fix: 'Use SHA-256 or SHA-3 for integrity checks' },
  { id: 'WCRYPTO-002', re: /createHash\s*\(\s*['"]sha1['"]\s*\)|createHmac\s*\(\s*['"]sha1['"]\s*\)/gi, sev: 'MEDIUM', cat: 'crypto', desc: 'SHA-1 hash/HMAC — considered weak', owasp: 'MCP-03', fix: 'Use SHA-256 or SHA-3' },
  { id: 'WCRYPTO-003', re: /Math\.random\s*\(\s*\)/gi, sev: 'MEDIUM', cat: 'crypto', desc: 'Math.random() — not cryptographically secure', owasp: 'MCP-03', fix: 'Use crypto.randomBytes() or crypto.randomUUID()' },
];

PATTERNS.push(...V20_PATTERNS);

