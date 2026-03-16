/**
 * SkillFence Context Analysis v2.0
 * Reduces false positives by understanding file context
 */

const path = require('path');

// Files that are DOCUMENTATION, not executable code
const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst', '.adoc']);

const DOC_PATHS = [
  /readme/i, /changelog/i, /contributing/i, /history/i, /license/i,
  /docs?\//i, /documentation\//i, /examples?\//i, /tutorials?\//i,
  /guides?\//i, /wiki\//i, /\.github\//i, /SECURITY\.md/i
];

// Test files — lower confidence
const TEST_PATHS = [
  /\.test\./i, /\.spec\./i, /test\//i, /tests\//i, /__tests__\//i,
  /fixtures?\//i, /mocks?\//i, /\.stories\./i, /e2e\//i, /cypress\//i
];

// Config / infrastructure files — some patterns are expected
const CONFIG_PATHS = [
  /docker-compose/i, /dockerfile/i, /\.env\.example/i, /\.env\.sample/i,
  /cloudformation/i, /terraform\//i, /ansible\//i, /helm\//i,
  /k8s\//i, /kubernetes\//i, /\.yaml$/i, /\.yml$/i
];

// Patterns that are EXPECTED in certain contexts (not vulnerabilities)
const CONTEXT_ALLOWLIST = {
  // MD5 in S3 is AWS spec (Content-MD5 header required by RFC)
  'createHash.*md5': { allowIn: /s3|aws|amazon/i, reason: 'AWS S3 Content-MD5 (RFC requirement)' },
  // SHA1 in webhook verification — dictated by external API
  'sha1': { allowIn: /facebook|helpscout|shopify|stripe|github.*webhook/i, reason: 'API-mandated HMAC-SHA1' },
  // private_key references in crypto/identity systems are domain, not leak
  'private.?key': { allowIn: /crypto|wallet|identity|signing|key.?management|attestation|certificate/i, reason: 'Crypto domain — key handling is core function' },
  // sudo in documentation is instruction, not execution
  'sudo': { allowInDocs: true, reason: 'Installation instruction in docs' },
  // npm/pip install in docs are instructions
  'npm\\s+install': { allowInDocs: true, reason: 'Installation instruction in docs' },
  'pip\\s+install': { allowInDocs: true, reason: 'Installation instruction in docs' },
  // github_token in README is documentation reference
  'GITHUB_TOKEN': { allowInDocs: true, reason: 'Documentation reference' },
  // eval in docs/README is description, not execution
  'eval': { allowInDocs: true, reason: 'Description/warning in docs' },
  // curl | sh in README is installation instruction
  'curl.*\\|.*sh': { allowInDocs: true, reason: 'Installation instruction (still risky but documented)' },
  // exec() in regex context (RegExp.exec) is not shell execution
  'exec\\s*\\(': { allowIn: /regex|regexp|\.exec\(|resolvable|match/i, reason: 'RegExp.exec(), not shell execution' },
  // rejectUnauthorized:false behind explicit user opt-in
  'rejectUnauthorized.*false': { allowIn: /allowUnauthorizedCerts|option|toggle|checkbox/i, reason: 'User-controlled opt-in toggle' },
  // no auth in test/example configs
  'no.?auth': { allowInDocs: true, allowIn: /test|example|sample|demo/i, reason: 'Test/example configuration' },
};

/**
 * Classify a file's context
 * @param {string} filePath - relative file path
 * @returns {{ type: 'code'|'doc'|'test'|'config', confidence: 'high'|'low' }}
 */
function classifyFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const normalized = filePath.replace(/\\/g, '/');
  
  if (DOC_EXTENSIONS.has(ext) || DOC_PATHS.some(p => p.test(normalized))) {
    return { type: 'doc', confidence: 'low' };
  }
  if (TEST_PATHS.some(p => p.test(normalized))) {
    return { type: 'test', confidence: 'low' };
  }
  if (CONFIG_PATHS.some(p => p.test(normalized))) {
    return { type: 'config', confidence: 'low' };
  }
  return { type: 'code', confidence: 'high' };
}

/**
 * Check if a finding should be suppressed or downgraded based on context
 * @param {object} finding - { id, severity, sample, file }
 * @param {string} content - file content around the match
 * @param {object} fileContext - from classifyFile()
 * @returns {{ action: 'keep'|'downgrade'|'suppress', reason?: string, newSeverity?: string }}
 */
function applyContext(finding, content, fileContext) {
  const sample = finding.sample || '';
  const file = finding.file || '';

  // Check context allowlist
  for (const [pattern, rule] of Object.entries(CONTEXT_ALLOWLIST)) {
    const patternRe = new RegExp(pattern, 'i');
    if (!patternRe.test(sample) && !patternRe.test(finding.description)) continue;

    // Allow in docs?
    if (rule.allowInDocs && fileContext.type === 'doc') {
      return { action: 'downgrade', reason: rule.reason, newSeverity: 'INFO' };
    }
    // Allow in specific file contexts?
    if (rule.allowIn && (rule.allowIn.test(file) || rule.allowIn.test(content.substring(0, 500)))) {
      return { action: 'downgrade', reason: rule.reason, newSeverity: 'INFO' };
    }
  }

  // General rule: findings in docs get downgraded
  if (fileContext.type === 'doc' && (finding.severity === 'CRITICAL' || finding.severity === 'HIGH')) {
    return { 
      action: 'downgrade', 
      reason: `Found in documentation file (${file})`,
      newSeverity: 'INFO'
    };
  }

  // Test files: downgrade to MEDIUM max
  if (fileContext.type === 'test' && (finding.severity === 'CRITICAL' || finding.severity === 'HIGH')) {
    return {
      action: 'downgrade',
      reason: `Found in test file (${file})`,
      newSeverity: 'MEDIUM'
    };
  }

  return { action: 'keep' };
}

module.exports = { classifyFile, applyContext, CONTEXT_ALLOWLIST };
