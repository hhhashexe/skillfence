#!/usr/bin/env node
/**
 * SkillFence CLI
 * Security scanner for AI agent skills & MCP servers
 * Usage: skillfence scan [path]
 */

const fs = require('fs');
const path = require('path');
const { scanContent, scanDirectory } = require('../lib/scanner');
const { PATTERNS } = require('../lib/patterns');

// ═══════════════════════════════════════
// COLORS (no dependencies)
// ═══════════════════════════════════════
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const SEV_COLORS = {
  CRITICAL: `${c.bgRed}${c.white}${c.bold} CRITICAL ${c.reset}`,
  HIGH:     `${c.red}${c.bold} HIGH ${c.reset}`,
  MEDIUM:   `${c.yellow} MEDIUM ${c.reset}`,
  LOW:      `${c.dim} LOW ${c.reset}`,
  INFO:     `${c.blue} INFO ${c.reset}`,
};

const VERDICT_DISPLAY = {
  BLOCK:  `${c.bgRed}${c.white}${c.bold}  ✗ BLOCKED  ${c.reset}`,
  WARN:   `${c.bgYellow}${c.bold}  ⚠ WARNING  ${c.reset}`,
  REVIEW: `${c.yellow}  ◉ REVIEW   ${c.reset}`,
  CLEAN:  `${c.bgGreen}${c.white}${c.bold}  ✓ CLEAN    ${c.reset}`,
};

// ═══════════════════════════════════════
// CLI
// ═══════════════════════════════════════
const args = process.argv.slice(2);
const command = args[0];

function printBanner() {
  const pkg = require('../package.json');
  const ruleCount = PATTERNS.length;
  console.log(`
${c.magenta}${c.bold}  ╔═══════════════════════════════════╗
  ║  🛡️  SkillFence Security Scanner  ║
  ║     v${pkg.version} • ${ruleCount} detection rules  ║
  ╚═══════════════════════════════════╝${c.reset}
`);
}

function printHelp() {
  printBanner();
  console.log(`${c.bold}USAGE${c.reset}
  ${c.cyan}skillfence scan${c.reset} [path]          Scan a file or directory
  ${c.cyan}skillfence scan${c.reset} --stdin         Scan from stdin
  ${c.cyan}skillfence rules${c.reset}                List all detection rules
  ${c.cyan}skillfence version${c.reset}              Show version
  ${c.cyan}skillfence help${c.reset}                 Show this help

${c.bold}OPTIONS${c.reset}
  ${c.dim}--json${c.reset}         Output as JSON
  ${c.dim}--sarif${c.reset}        Output as SARIF (GitHub Security tab)
  ${c.dim}--quiet${c.reset}        Only output verdict and exit code
  ${c.dim}--no-context${c.reset}   Disable context-aware filtering
  ${c.dim}--no-color${c.reset}     Disable colors

${c.bold}EXIT CODES${c.reset}
  0  CLEAN — no findings
  1  REVIEW — low/medium findings
  2  WARN — high severity findings
  3  BLOCK — critical findings detected

${c.bold}EXAMPLES${c.reset}
  ${c.dim}# Scan current directory${c.reset}
  skillfence scan .

  ${c.dim}# Scan a specific skill file${c.reset}
  skillfence scan SKILL.md

  ${c.dim}# Scan and get JSON output${c.reset}
  skillfence scan . --json

  ${c.dim}# Use in CI/CD${c.reset}
  skillfence scan . --quiet || exit 1

  ${c.dim}# Pipe content${c.reset}
  cat suspicious-skill.md | skillfence scan --stdin
`);
}

function printRules() {
  printBanner();
  console.log(`${c.bold}${PATTERNS.length} Detection Rules${c.reset}\n`);
  
  const categories = {};
  for (const p of PATTERNS) {
    if (!categories[p.cat]) categories[p.cat] = [];
    categories[p.cat].push(p);
  }

  for (const [cat, rules] of Object.entries(categories)) {
    console.log(`${c.cyan}${c.bold}▸ ${cat.toUpperCase()}${c.reset}`);
    for (const r of rules) {
      const sevColor = r.sev === 'CRITICAL' ? c.red : r.sev === 'HIGH' ? c.yellow : c.dim;
      console.log(`  ${c.dim}${r.id}${c.reset}  ${sevColor}${r.sev.padEnd(9)}${c.reset} ${r.desc} ${c.dim}[${r.owasp}]${c.reset}`);
    }
    console.log();
  }
}

function printFindings(result, filePath) {
  if (result.totalFindings !== undefined) {
    // Directory scan result
    printBanner();
    console.log(`${c.bold}Scanning:${c.reset} ${filePath}`);
    console.log(`${c.dim}Files scanned: ${result.filesScanned}${c.reset}\n`);

    if (result.totalFindings === 0) {
      console.log(VERDICT_DISPLAY.CLEAN);
      console.log(`\n${c.green}No security issues found.${c.reset}\n`);
      return;
    }

    // Print findings by file
    for (const [file, fileResult] of Object.entries(result.files)) {
      console.log(`${c.bold}${c.cyan}📄 ${file}${c.reset}`);
      for (const f of fileResult.findings) {
        const confTag = f.confidence === 'low' ? ` ${c.dim}[low confidence]${c.reset}` : '';
        console.log(`  ${SEV_COLORS[f.severity] || SEV_COLORS.LOW} ${f.description}${confTag}`);
        console.log(`  ${c.dim}   Rule: ${f.id} | OWASP: ${f.owasp} | Match: "${f.sample}"${c.reset}`);
        if (f.contextNote) {
          console.log(`  ${c.blue}   ℹ Context: ${f.contextNote}${f.originalSeverity ? ` (was ${f.originalSeverity})` : ''}${c.reset}`);
        }
        console.log(`  ${c.green}   Fix: ${f.fix}${c.reset}`);
      }
      console.log();
    }
  } else {
    // Single file/content scan
    printBanner();
    console.log(`${c.bold}Scanning:${c.reset} ${filePath}\n`);

    if (result.findings.length === 0) {
      console.log(VERDICT_DISPLAY.CLEAN);
      console.log(`\n${c.green}No security issues found.${c.reset}\n`);
      return;
    }

    for (const f of result.findings) {
      console.log(`  ${SEV_COLORS[f.severity]} ${f.description}`);
      console.log(`  ${c.dim}   Rule: ${f.id} | OWASP: ${f.owasp} | Match: "${f.sample}"${c.reset}`);
      console.log(`  ${c.green}   Fix: ${f.fix}${c.reset}`);
    }
    console.log();
  }

  // Summary
  const summary = result.summary || {
    critical: result.findings.filter(f => f.severity === 'CRITICAL').length,
    high: result.findings.filter(f => f.severity === 'HIGH').length,
    medium: result.findings.filter(f => f.severity === 'MEDIUM').length,
    low: result.findings.filter(f => f.severity === 'LOW').length,
  };

  console.log(`${c.bold}───────────────────────────────────${c.reset}`);
  console.log(`  ${VERDICT_DISPLAY[result.verdict]}`);
  console.log(`  ${c.bold}Risk Score:${c.reset} ${result.score}/100`);
  const infoCount = summary.info || 0;
  console.log(`  ${c.red}${c.bold}${summary.critical}${c.reset} critical  ${c.yellow}${summary.high}${c.reset} high  ${c.dim}${summary.medium}${c.reset} medium  ${c.dim}${summary.low || 0}${c.reset} low${infoCount ? `  ${c.blue}${infoCount}${c.reset} info` : ''}`);
  console.log(`${c.bold}───────────────────────────────────${c.reset}\n`);
}

// ═══════════════════════════════════════
// COMMANDS
// ═══════════════════════════════════════

if (!command || command === 'help' || command === '--help' || command === '-h') {
  printHelp();
  process.exit(0);
}

if (command === 'version' || command === '--version' || command === '-v') {
  const pkg = require('../package.json');
  console.log(`skillfence v${pkg.version}`);
  process.exit(0);
}

if (command === 'rules') {
  printRules();
  process.exit(0);
}

if (command === 'scan') {
  const target = args[1] || '.';
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isQuiet = args.includes('--quiet');
  const isStdin = args.includes('--stdin');
  const noContext = args.includes('--no-context');
  const scanOptions = { contextAware: !noContext };

  let result;

  if (isStdin) {
    // Read from stdin
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => input += chunk);
    process.stdin.on('end', () => {
      result = scanContent(input, 'stdin', scanOptions);
      outputResult(result, 'stdin');
    });
    return;
  }

  const targetPath = path.resolve(target);
  if (!fs.existsSync(targetPath)) {
    console.error(`${c.red}Error: ${target} not found${c.reset}`);
    process.exit(1);
  }

  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    result = scanDirectory(targetPath, scanOptions);
  } else {
    const content = fs.readFileSync(targetPath, 'utf8');
    result = scanContent(content, target, scanOptions);
  }

  outputResult(result, target);

  function outputResult(result, target) {
    if (isJson) {
      console.log(JSON.stringify(result, null, 2));
    } else if (isSarif) {
      console.log(JSON.stringify(toSarif(result), null, 2));
    } else if (isQuiet) {
      const exitMap = { CLEAN: 0, REVIEW: 1, WARN: 2, BLOCK: 3 };
      console.log(result.verdict);
      process.exit(exitMap[result.verdict] || 0);
    } else {
      printFindings(result, target);
    }

    const exitMap = { CLEAN: 0, REVIEW: 1, WARN: 2, BLOCK: 3 };
    process.exit(exitMap[result.verdict] || 0);
  }

  function toSarif(result) {
    return {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'SkillFence',
            version: '1.0.0',
            informationUri: 'https://github.com/hhhashexe/skillfence',
            rules: PATTERNS.map(p => ({
              id: p.id,
              shortDescription: { text: p.desc },
              helpUri: `https://github.com/hhhashexe/skillfence#${p.id}`,
              defaultConfiguration: { level: p.sev === 'CRITICAL' ? 'error' : p.sev === 'HIGH' ? 'error' : 'warning' },
              properties: { 'security-severity': p.sev === 'CRITICAL' ? '9.0' : p.sev === 'HIGH' ? '7.0' : '4.0' }
            }))
          }
        },
        results: (result.findings || []).map(f => ({
          ruleId: f.id,
          level: f.severity === 'CRITICAL' ? 'error' : f.severity === 'HIGH' ? 'error' : 'warning',
          message: { text: f.description },
          locations: f.file ? [{ physicalLocation: { artifactLocation: { uri: f.file } } }] : []
        }))
      }]
    };
  }
}

// Unknown command
console.error(`${c.red}Unknown command: ${command}${c.reset}`);
console.log(`Run ${c.cyan}skillfence help${c.reset} for usage`);
process.exit(1);

// Install hook command
if (command === 'install-hook') {
  const fs = require('fs');
  const path = require('path');
  const hookPath = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');
  const hookDir = path.dirname(hookPath);
  
  if (!fs.existsSync(path.join(process.cwd(), '.git'))) {
    console.error('❌ Not a git repository. Run from your project root.');
    process.exit(1);
  }
  
  if (!fs.existsSync(hookDir)) fs.mkdirSync(hookDir, { recursive: true });
  
  const hookContent = `#!/usr/bin/env bash
# SkillFence Pre-Commit Hook (auto-installed)
set -e
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(md|yaml|yml|json|js|ts|py|toml)$' || true)
[ -z "$STAGED" ] && exit 0
echo "🛡️  SkillFence: Scanning staged files..."
FAIL=0
for f in $STAGED; do
  [ -f "$f" ] || continue
  V=$(npx -y skillfence scan "$f" --json 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).verdict)}catch{console.log('CLEAN')}})" 2>/dev/null)
  [ "$V" = "BLOCK" ] && echo "❌ BLOCKED: $f" && npx -y skillfence scan "$f" 2>/dev/null && FAIL=1
  [ "$V" = "WARN" ] && echo "⚠️  WARNING: $f"
done
[ "$FAIL" -eq 1 ] && echo "🛡️ Commit blocked. Fix issues or use --no-verify" && exit 1
echo "🛡️  SkillFence: All clear ✓"
`;
  
  fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
  console.log('✅ Pre-commit hook installed at .git/hooks/pre-commit');
  console.log('   Commits with CRITICAL findings will be blocked.');
  console.log('   Use "git commit --no-verify" to bypass.');
  process.exit(0);
}
