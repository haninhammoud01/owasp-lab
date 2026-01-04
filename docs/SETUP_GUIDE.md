# Complete Setup Guide - OWASP Security Lab

## Prerequisites

```bash
# Required
- Node.js 18+
- Git
- Python 3.8+ (for Semgrep)

# Optional
- Docker (for containerized scanning)
- OPA CLI (for policy enforcement)
```

## Step 1: Initial Setup

```bash
cd "/mnt/c/Users/LENOVO/Documents/Build-Projects/OWASP Security Lab"

# Initialize Git
git init
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Create .gitignore
cat > .gitignore << 'EOF'
node_modules/
*.log
.env
security-reports/*.json
security-reports/*.html
!security-reports/.gitkeep
EOF

# Install Semgrep
pip3 install semgrep

# Verify installation
semgrep --version
```

## Step 2: Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Create required directories
mkdir -p security-reports
mkdir -p dashboard
touch security-reports/.gitkeep
```

## Step 3: Run First Security Scan

```bash
# Run Semgrep without Git (fixes your error)
semgrep --config semgrep-rules.yml src/ --no-git-ignore --json --output security-reports/custom-rules.json

# Or use the full scan script
bash scripts/run-semgrep.sh
```

## Step 4: Start Security Dashboard

```bash
# Start the dashboard server
node dashboard/server.js

# Open browser to:
# http://localhost:8888/index.html
```

## Step 5: Setup GitHub Actions (Optional)

```bash
# Stage files
git add .

# Commit
git commit -m "Initial security lab setup"

# Create GitHub repository and push
git remote add origin https://github.com/yourusername/owasp-security-lab.git
git push -u origin main
```

## Step 6: Install OPA (Optional)

```bash
# Linux/WSL
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Verify
opa version

# Test policy
node scripts/opa-enforce.js
```

## Common Commands

### Security Scanning

```bash
# Quick scan
semgrep --config semgrep-rules.yml src/ --no-git-ignore

# Comprehensive scan
bash scripts/run-semgrep.sh

# Scan specific file
semgrep --config semgrep-rules.yml src/vulnerable/sample.js --no-git-ignore

# Generate report
node scripts/parse-semgrep-results.js security-reports/custom-rules.json
```

### Dashboard Operations

```bash
# Start dashboard
node dashboard/server.js

# Test API endpoint
curl http://localhost:8888/api/security/summary

# Export report
curl http://localhost:8888/api/security/export > report.html
```

### Policy Enforcement

```bash
# Evaluate deployment policy
node scripts/opa-enforce.js

# Test specific policy
opa eval -d opa/security-policies.rego -i input.json "data.security.allow_deployment"
```

## Troubleshooting

### Error: Git ls-files failed

**Solution:** Use `--no-git-ignore` flag
```bash
semgrep --config semgrep-rules.yml src/ --no-git-ignore
```

### Error: No rules loaded

**Solution:** Check if rule files exist
```bash
ls -la semgrep-rules.yml semgrep-advanced.yml
```

### Error: Module not found

**Solution:** Install dependencies
```bash
npm install
```

### Dashboard not loading data

**Solution:** Run a scan first
```bash
semgrep --config semgrep-rules.yml src/ --no-git-ignore --json --output security-reports/custom-rules.json
```

## Project Structure

```
OWASP Security Lab/
├── src/
│   ├── vulnerable/          # Intentionally vulnerable code
│   │   └── sample.js
│   └── secure/              # Secure implementations
│       └── sample.js
├── scripts/
│   ├── run-semgrep.sh       # Comprehensive scan script
│   ├── parse-semgrep-results.js
│   └── opa-enforce.js       # Policy enforcement
├── dashboard/
│   ├── index.html           # Security dashboard UI
│   └── server.js            # Dashboard API server
├── opa/
│   └── security-policies.rego
├── security-reports/        # Scan results (gitignored)
├── semgrep-rules.yml        # Custom Semgrep rules
├── semgrep-advanced.yml     # Advanced rules
└── .github/
    └── workflows/
        └── security-pipeline.yml
```

## Next Steps

### 1. Explore Vulnerable Code

```bash
# Review intentional vulnerabilities
cat src/vulnerable/sample.js

# Compare with secure version
cat src/secure/sample.js
```

### 2. Customize Rules

```bash
# Edit custom rules
nano semgrep-rules.yml

# Test rule changes
semgrep --config semgrep-rules.yml src/vulnerable/sample.js --no-git-ignore
```

### 3. View Results in Dashboard

1. Run scan: `semgrep --config semgrep-rules.yml src/ --no-git-ignore --json --output security-reports/custom-rules.json`
2. Start server: `node dashboard/server.js`
3. Open: `http://localhost:8888/index.html`

### 4. Setup CI/CD

1. Create GitHub repository
2. Push code
3. GitHub Actions will run automatically

### 5. Implement Policies

1. Review OPA policies: `cat opa/security-policies.rego`
2. Customize thresholds
3. Enforce in CI/CD

## Best Practices

1. **Run scans regularly**
   - Before commits
   - In CI/CD pipeline
   - Weekly scheduled scans

2. **Review findings carefully**
   - Prioritize critical issues
   - Understand root causes
   - Document false positives

3. **Keep rules updated**
   - Update Semgrep regularly
   - Add project-specific rules
   - Review community rules

4. **Monitor trends**
   - Track vulnerability counts
   - Measure resolution time
   - Set improvement goals

## Resources

- Semgrep Documentation: https://semgrep.dev/docs
- OWASP Top 10: https://owasp.org/Top10
- OPA Documentation: https://openpolicyagent.org/docs
- Project Repository: (your repo link)

## Support

For issues or questions:
1. Check troubleshooting section
2. Review logs in `security-reports/`
3. Open GitHub issue
4. Contact security team