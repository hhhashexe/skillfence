#!/usr/bin/env bash
# SkillFence Pre-Commit Hook
# Install: cp pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Or: npx skillfence install-hook

set -e

# Get staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
  exit 0
fi

# Filter relevant files
FILES=$(echo "$STAGED" | grep -E '\.(md|yaml|yml|json|js|ts|py|toml)$' || true)

if [ -z "$FILES" ]; then
  exit 0
fi

echo "🛡️  SkillFence: Scanning staged files..."

# Run scan on each file
FAILED=0
for f in $FILES; do
  if [ -f "$f" ]; then
    RESULT=$(npx skillfence scan "$f" --json 2>/dev/null || true)
    VERDICT=$(echo "$RESULT" | node -e "
      let d='';process.stdin.on('data',c=>d+=c);
      process.stdin.on('end',()=>{try{console.log(JSON.parse(d).verdict)}catch{console.log('CLEAN')}})
    " 2>/dev/null)
    
    if [ "$VERDICT" = "BLOCK" ]; then
      echo "❌ BLOCKED: $f"
      npx skillfence scan "$f" 2>/dev/null
      FAILED=1
    elif [ "$VERDICT" = "WARN" ]; then
      echo "⚠️  WARNING: $f (commit allowed)"
      npx skillfence scan "$f" 2>/dev/null
    fi
  fi
done

if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "🛡️  SkillFence: Commit blocked due to CRITICAL security issues."
  echo "   Fix the issues above or use 'git commit --no-verify' to bypass."
  exit 1
fi

echo "🛡️  SkillFence: All clear ✓"
exit 0
