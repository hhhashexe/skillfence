/**
 * SkillFence Core Scanner
 * Scans files for security vulnerabilities in AI agent skills
 */

const fs = require('fs');
const path = require('path');
const { PATTERNS, SUSPICIOUS_DOMAINS } = require('./patterns');

const SCAN_EXTENSIONS = new Set([
  '.md', '.js', '.ts', '.py', '.sh', '.bash', '.yaml', '.yml',
  '.json', '.toml', '.cfg', '.conf', '.env', '.txt', '.mjs', '.cjs'
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', '.nuxt', 'coverage', '.github'
]);

// Files that commonly have false positives
const REDUCED_SEVERITY_FILES = new Set([
  'CONTRIBUTING.md', 'CHANGELOG.md', 'HISTORY.md',
  'docker-compose.yml', 'docker-compose.yaml',
  '.env.example', '.env.sample'
]);

function scanContent(content, filename = 'input') {
  const findings = [];
  let score = 0;

  // Check patterns
  for (const pattern of PATTERNS) {
    const matches = content.match(pattern.re);
    if (matches) {
      findings.push({
        id: pattern.id,
        severity: pattern.sev,
        category: pattern.cat,
        description: pattern.desc,
        owasp: pattern.owasp,
        fix: pattern.fix,
        file: filename,
        matches: matches.length,
        sample: matches[0].substring(0, 80)
      });
      const weight = pattern.sev === 'CRITICAL' ? 30 : pattern.sev === 'HIGH' ? 15 : pattern.sev === 'MEDIUM' ? 5 : 2;
      score += weight * matches.length;
    }
  }

  // Check suspicious domains
  for (const domPattern of SUSPICIOUS_DOMAINS) {
    const matches = content.match(domPattern);
    if (matches) {
      findings.push({
        id: 'EXFIL-DNS',
        severity: 'HIGH',
        category: 'exfiltration',
        description: `Suspicious domain: ${matches[0].substring(0, 60)}`,
        owasp: 'MCP-04',
        fix: 'Remove or verify this external URL',
        file: filename,
        matches: matches.length,
        sample: matches[0].substring(0, 80)
      });
      score += 15;
    }
  }

  // Normalize score to 0-100
  score = Math.min(score, 100);

  // Determine verdict
  const hasCritical = findings.some(f => f.severity === 'CRITICAL');
  const hasHigh = findings.some(f => f.severity === 'HIGH');
  const verdict = hasCritical ? 'BLOCK' : hasHigh ? 'WARN' : findings.length > 0 ? 'REVIEW' : 'CLEAN';

  return { findings, score, verdict };
}

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const relPath = path.relative(process.cwd(), filePath);
  return scanContent(content, relPath);
}

function scanDirectory(dirPath, options = {}) {
  const allFindings = [];
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
          const result = scanFile(fullPath);
          filesScanned++;
          if (result.findings.length > 0) {
            const relPath = path.relative(process.cwd(), fullPath);
            fileResults[relPath] = result;
            allFindings.push(...result.findings);
            totalScore = Math.min(totalScore + result.score, 100);
          }
        }
      }
    }
  }

  walk(dirPath);

  const hasCritical = allFindings.some(f => f.severity === 'CRITICAL');
  const hasHigh = allFindings.some(f => f.severity === 'HIGH');
  const verdict = hasCritical ? 'BLOCK' : hasHigh ? 'WARN' : allFindings.length > 0 ? 'REVIEW' : 'CLEAN';

  return {
    verdict,
    score: totalScore,
    filesScanned,
    totalFindings: allFindings.length,
    summary: {
      critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
      high: allFindings.filter(f => f.severity === 'HIGH').length,
      medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
      low: allFindings.filter(f => f.severity === 'LOW').length,
    },
    files: fileResults,
    findings: allFindings,
  };
}

module.exports = { scanContent, scanFile, scanDirectory, SCAN_EXTENSIONS };
