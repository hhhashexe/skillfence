/**
 * SkillFence Core Scanner
 * Scans files for security vulnerabilities in AI agent skills
 */

const fs = require('fs');
const path = require('path');
const { PATTERNS, SUSPICIOUS_DOMAINS } = require('./patterns');
const { classifyFile, applyContext } = require('./context');

const SCAN_EXTENSIONS = new Set([
  '.md', '.js', '.ts', '.py', '.sh', '.bash', '.yaml', '.yml',
  '.json', '.toml', '.cfg', '.conf', '.env', '.txt', '.mjs', '.cjs'
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', '.nuxt', 'coverage', '.github'
]);

const SEV_WEIGHT = { CRITICAL: 30, HIGH: 15, MEDIUM: 5, LOW: 2, INFO: 0 };

function scanContent(content, filename = 'input', options = {}) {
  const findings = [];
  const suppressed = [];
  let score = 0;

  const fileContext = classifyFile(filename);
  const contextAware = options.contextAware !== false; // default ON

  // Check patterns
  for (const pattern of PATTERNS) {
    const re = new RegExp(pattern.re.source, pattern.re.flags);
    const matches = content.match(re);
    if (!matches) continue;

    const finding = {
      id: pattern.id,
      severity: pattern.sev,
      category: pattern.cat,
      description: pattern.desc,
      owasp: pattern.owasp,
      fix: pattern.fix,
      file: filename,
      matches: matches.length,
      sample: matches[0].substring(0, 80),
      confidence: fileContext.confidence,
      fileType: fileContext.type,
    };

    // Apply context-aware filtering
    if (contextAware) {
      const ctx = applyContext(finding, content, fileContext);
      if (ctx.action === 'suppress') {
        suppressed.push({ ...finding, suppressReason: ctx.reason });
        continue;
      }
      if (ctx.action === 'downgrade') {
        finding.originalSeverity = finding.severity;
        finding.severity = ctx.newSeverity;
        finding.contextNote = ctx.reason;
      }
    }

    findings.push(finding);
    score += (SEV_WEIGHT[finding.severity] || 0) * matches.length;
  }

  // Check suspicious domains
  for (const domPattern of SUSPICIOUS_DOMAINS) {
    const matches = content.match(domPattern);
    if (matches) {
      const finding = {
        id: 'EXFIL-DNS',
        severity: 'HIGH',
        category: 'exfiltration',
        description: `Suspicious domain: ${matches[0].substring(0, 60)}`,
        owasp: 'MCP-04',
        fix: 'Remove or verify this external URL',
        file: filename,
        matches: matches.length,
        sample: matches[0].substring(0, 80),
        confidence: fileContext.confidence,
        fileType: fileContext.type,
      };
      
      if (contextAware && fileContext.type === 'doc') {
        finding.originalSeverity = 'HIGH';
        finding.severity = 'INFO';
        finding.contextNote = 'Found in documentation';
      }
      
      findings.push(finding);
      score += (SEV_WEIGHT[finding.severity] || 0);
    }
  }

  // Normalize score to 0-100
  score = Math.min(score, 100);

  // Determine verdict (INFO findings don't affect verdict)
  const realFindings = findings.filter(f => f.severity !== 'INFO');
  const hasCritical = realFindings.some(f => f.severity === 'CRITICAL');
  const hasHigh = realFindings.some(f => f.severity === 'HIGH');
  const verdict = hasCritical ? 'BLOCK' : hasHigh ? 'WARN' : realFindings.length > 0 ? 'REVIEW' : 'CLEAN';

  const result = { findings, score, verdict };
  if (suppressed.length > 0) result.suppressed = suppressed;
  return result;
}

function scanFile(filePath, options = {}) {
  const content = fs.readFileSync(filePath, 'utf8');
  const relPath = path.relative(process.cwd(), filePath);
  return scanContent(content, relPath, options);
}

function scanDirectory(dirPath, options = {}) {
  const allFindings = [];
  const allSuppressed = [];
  let totalScore = 0;
  let filesScanned = 0;
  const fileResults = {};

  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCAN_EXTENSIONS.has(ext) || entry.name === 'SKILL.md' || entry.name === 'Dockerfile') {
          const content = fs.readFileSync(fullPath, 'utf8');
          const relPath = path.relative(process.cwd(), fullPath);
          const result = scanContent(content, relPath, options);
          filesScanned++;
          if (result.findings.length > 0) {
            fileResults[relPath] = result;
            allFindings.push(...result.findings);
            totalScore = Math.min(totalScore + result.score, 100);
          }
          if (result.suppressed) allSuppressed.push(...result.suppressed);
        }
      }
    }
  }

  walk(dirPath);

  const realFindings = allFindings.filter(f => f.severity !== 'INFO');
  const hasCritical = realFindings.some(f => f.severity === 'CRITICAL');
  const hasHigh = realFindings.some(f => f.severity === 'HIGH');
  const verdict = hasCritical ? 'BLOCK' : hasHigh ? 'WARN' : realFindings.length > 0 ? 'REVIEW' : 'CLEAN';

  const result = {
    verdict,
    score: totalScore,
    filesScanned,
    totalFindings: allFindings.length,
    summary: {
      critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
      high: allFindings.filter(f => f.severity === 'HIGH').length,
      medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
      low: allFindings.filter(f => f.severity === 'LOW').length,
      info: allFindings.filter(f => f.severity === 'INFO').length,
    },
    files: fileResults,
    findings: allFindings,
  };
  if (allSuppressed.length > 0) result.suppressed = allSuppressed;
  return result;
}

module.exports = { scanContent, scanFile, scanDirectory, SCAN_EXTENSIONS };
