# Semgrep Custom Rules Documentation

## Overview

This project uses Semgrep for static application security testing (SAST). Our custom rules are designed to catch vulnerabilities specific to Node.js/Express applications with a focus on OWASP Top 10 risks.

## Rule Categories

### 1. Injection Vulnerabilities

#### SQL Injection (`express-sql-injection-string-concat`)

**Severity:** ERROR  
**CWE:** CWE-89  
**OWASP:** A03:2021 - Injection

Detects string concatenation in SQL queries which allows SQL injection attacks.

**Vulnerable Pattern:**
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
pool.query(query);
```

**Secure Pattern:**
```javascript
const query = 'SELECT * FROM users WHERE id = $1';
pool.query(query, [userId]);
```

**Why This Matters:**
SQL injection can lead to unauthorized data access, data modification, or complete system compromise. Parameterized queries ensure user input is treated as data, not executable code.

---

#### Sequelize Raw Query Injection (`express-sequelize-raw-query-injection`)

**Severity:** ERROR  
**CWE:** CWE-89  
**OWASP:** A03:2021 - Injection

Catches raw Sequelize queries with string interpolation.

**Secure Pattern:**
```javascript
sequelize.query(
  'SELECT * FROM users WHERE id = :id',
  { replacements: { id: userId } }
);
```

---

### 2. Cross-Site Scripting (XSS)

#### Reflected XSS (`reflected-xss-res-send`)

**Severity:** ERROR  
**CWE:** CWE-79  
**OWASP:** A03:2021 - Injection

Detects user input rendered in HTML responses without sanitization.

**Vulnerable Pattern:**
```javascript
app.get('/search', (req, res) => {
  const term = req.query.q;
  res.send(`<h1>Results for: ${term}</h1>`);
});
```

**Mitigation Strategies:**
1. Use template engines with auto-escaping
2. Sanitize with DOMPurify
3. Set Content-Security-Policy headers
4. Context-aware output encoding

---

### 3. Authentication & Cryptography

#### Hardcoded JWT Secret (`jwt-secret-hardcoded`)

**Severity:** ERROR  
**CWE:** CWE-798  
**OWASP:** A07:2021 - Identification and Authentication Failures

**Why This Is Critical:**
A compromised JWT secret allows attackers to forge valid authentication tokens for any user.

**Best Practices:**
- Store secrets in environment variables
- Use strong, random secrets (32+ characters)
- Rotate secrets periodically
- Use different secrets per environment
- Consider RS256 (asymmetric) for public verification

---

#### Weak Bcrypt Rounds (`bcrypt-low-rounds`)

**Severity:** WARNING  
**CWE:** CWE-916

Detects bcrypt configurations with fewer than 10 rounds.

**Recommended Configuration (2025):**
```javascript
const hash = await bcrypt.hash(password, 12);
```

**Trade-offs:**
- Higher rounds = better security but slower
- Balance based on threat model and performance needs
- 12-14 rounds recommended for production

---

### 4. Security Misconfiguration

#### Missing Rate Limiting (`missing-rate-limit-auth-endpoint`)

**Severity:** WARNING  
**CWE:** CWE-307

Identifies authentication endpoints without rate limiting.

**Implementation:**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, authController.login);
```

**Additional Protections:**
- Account lockout after N failed attempts
- CAPTCHA after multiple failures
- Distributed attack monitoring

---

#### Missing Helmet (`express-no-helmet`)

**Severity:** WARNING  
**CWE:** CWE-1021

Detects Express apps without Helmet security middleware.

**Headers Set by Helmet:**
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Strict-Transport-Security
- Content-Security-Policy
- X-XSS-Protection

---

### 5. Cryptographic Failures

#### Weak Algorithms (`weak-crypto-algorithm`)

**Severity:** ERROR  
**CWE:** CWE-327

Detects usage of broken cryptographic algorithms.

**Broken Algorithms:**
- MD5 (collision attacks)
- SHA1 (deprecated)
- DES (key size too small)
- RC4 (keystream biases)

**Use Instead:**
- Hashing: SHA-256, SHA-384, SHA-512
- Encryption: AES-256-GCM

---

#### Insecure Random (`insecure-random-for-security`)

**Severity:** ERROR  
**CWE:** CWE-338

Flags Math.random() in security contexts.

**Secure Alternative:**
```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
const uuid = crypto.randomUUID();
```

---

### 6. Command & Path Injection

#### Command Injection (`command-injection-exec`)

**Severity:** ERROR  
**CWE:** CWE-78

**Attack Example:**
```javascript
const userInput = "; rm -rf /";
exec(`ls ${userInput}`);
```

**Safe Alternative:**
```javascript
const { execFile } = require('child_process');
execFile('ls', ['-la', directory], callback);
```

---

#### Path Traversal (`path-traversal-file-access`)

**Severity:** ERROR  
**CWE:** CWE-22

**Attack Example:**
```
GET /download?file=../../../../etc/passwd
```

**Secure Implementation:**
```javascript
const path = require('path');
const baseDir = '/var/www/uploads';
const fullPath = path.join(baseDir, filename);

if (!fullPath.startsWith(path.resolve(baseDir))) {
  return res.status(403).send('Access denied');
}
```

---

### 7. Access Control

#### IDOR Detection (`authorization-check-missing`)

**Severity:** ERROR  
**CWE:** CWE-639  
**OWASP:** A01:2021 - Broken Access Control

Uses taint analysis to detect user-controlled IDs used without authorization checks.

**Secure Pattern:**
```javascript
app.get('/users/:userId/profile', authMiddleware, async (req, res) => {
  if (req.params.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const user = await User.findByPk(req.params.userId);
  res.json(user);
});
```

---

#### Mass Assignment (`mass-assignment-vulnerability`)

**Severity:** ERROR  
**CWE:** CWE-915

**Attack Scenario:**
```javascript
POST /api/users
{
  "username": "hacker",
  "role": "admin"
}
```

**Mitigation:**
```javascript
const allowedFields = ['username', 'email', 'age'];
const userData = {};
allowedFields.forEach(field => {
  if (req.body[field] !== undefined) {
    userData[field] = req.body[field];
  }
});
await User.create(userData);
```

---

### 8. SSRF & Open Redirects

#### Server-Side Request Forgery (`server-side-request-forgery`)

**Severity:** ERROR  
**CWE:** CWE-918

**Attack Vectors:**
- Access internal services
- Port scan internal network
- Read cloud metadata endpoints
- Bypass firewalls

**Secure URL Validation:**
```javascript
function validateUrl(userUrl) {
  const url = new URL(userUrl);
  
  if (isPrivateIP(url.hostname) || url.hostname === 'localhost') {
    return false;
  }
  
  const allowedDomains = ['api.trusted.com'];
  if (!allowedDomains.includes(url.hostname)) {
    return false;
  }
  
  if (!['http:', 'https:'].includes(url.protocol)) {
    return false;
  }
  
  return true;
}
```

---

## Running Scans

### Local Development

```bash
# Quick scan with custom rules
semgrep --config semgrep-rules.yml src/

# Full scan with all rulesets
bash scripts/run-semgrep.sh

# Scan specific file
semgrep --config semgrep-rules.yml src/routes/auth.js
```

### CI/CD Pipeline

The GitHub Actions workflow runs automatically on:
- Push to main/develop
- Pull requests
- Weekly schedule (Mondays 2 AM)
- Manual trigger

### Generating Reports

```bash
# Parse results and generate reports
node scripts/parse-semgrep-results.js security-reports/custom-rules.json

# Outputs:
#   - security-report.md
#   - security-report.html
#   - summary.json
```

---

## Rule Development

### Creating Custom Rules

Rules follow this structure:

```yaml
rules:
  - id: unique-rule-id
    patterns:
      - pattern: code pattern to match
      - pattern-not: exclude these patterns
    message: |
      Description of vulnerability
      Mitigation advice
      Code examples
    severity: ERROR|WARNING|INFO
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-XXX"
      owasp: "AXX:2021"
```

### Pattern Matching

**Basic Pattern:**
```yaml
pattern: pool.query("..." + $VAR + "...")
```

**Multiple Patterns (AND):**
```yaml
patterns:
  - pattern: dangerous_function($VAR)
  - pattern-inside: route_handler(...)
```

**Alternative Patterns (OR):**
```yaml
pattern-either:
  - pattern: option_a(...)
  - pattern: option_b(...)
```

**Exclusions:**
```yaml
pattern-not: safe_wrapper($CALL)
```

### Metavariables

- `$VAR` - matches any expression
- `$FIELD` - matches field names
- `...` - matches any arguments

### Testing Rules

```bash
# Test rule on specific file
semgrep --config my-rule.yml test-file.js

# Validate rule syntax
semgrep --validate --config my-rule.yml

# Test with example code
semgrep --test my-rule.yml
```

---

## False Positives

### Suppressing Findings

**In-line suppression:**
```javascript
// nosemgrep: rule-id
const query = buildQuery(userInput);
```

**File-level suppression:**
```javascript
// nosemgrep
```

**Configuration-based:**
Add to `.semgrepignore`:
```
src/legacy/
tests/
```

### When to Suppress

- Code is actually safe (validated elsewhere)
- Legacy code scheduled for refactor
- Test/mock code
- Third-party code

**Best Practice:** Always add comment explaining why suppression is safe.

---

## Integration with Other Tools

### Combine with Dynamic Analysis

```bash
# SAST with Semgrep
semgrep --config auto src/

# DAST with OWASP ZAP
docker run owasp/zap2docker-stable zap-baseline.py -t http://localhost:3000
```

### SonarQube Integration

Semgrep SARIF output can be imported into SonarQube for unified reporting.

### IDE Integration

**VS Code:**
```bash
code --install-extension semgrep.semgrep
```

**IntelliJ:**
Available through marketplace

---

## Performance Optimization

### Scan Time Reduction

1. Exclude unnecessary directories
2. Use specific configs instead of `--config auto`
3. Run incremental scans in CI
4. Parallelize with `--jobs` flag

### Resource Limits

```yaml
max_memory: 8000
max_target_bytes: 5000000
timeout: 30
jobs: 4
```

---

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Registry](https://semgrep.dev/explore)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

## Contributing Rules

When adding new rules:

1. Follow naming convention: `category-specific-description`
2. Include comprehensive message with examples
3. Add metadata (CWE, OWASP)
4. Test against both vulnerable and secure code
5. Document in this file
6. Update tests in `tests/security/`