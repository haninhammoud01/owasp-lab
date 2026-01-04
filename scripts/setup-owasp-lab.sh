#!/bin/bash

set -e

echo "=========================================="
echo "OWASP Top 10 Lab - Complete Setup"
echo "=========================================="
echo ""

PROJECT_DIR="/mnt/c/Users/LENOVO/Documents/Build-Projects/OWASP Security Lab"
cd "$PROJECT_DIR"

echo "Step 1: Initialize Git Repository"
if [ ! -d .git ]; then
    git init
    git config user.name "Your Name"
    git config user.email "your.email@example.com"
    echo "Git repository initialized"
else
    echo "Git repository already exists"
fi

echo ""
echo "Step 2: Create .gitignore"
cat > .gitignore << 'EOF'
node_modules/
dist/
build/
coverage/
*.log
.env
.DS_Store
security-reports/*.json
security-reports/*.html
security-reports/*.md
!security-reports/.gitkeep
zap-reports/
*.sarif
EOF

echo ""
echo "Step 3: Create directory structure"
mkdir -p src/{config,middleware,routes,controllers,models,vulnerable,secure}
mkdir -p tests/{unit,integration,security}
mkdir -p docs/{vulnerabilities,mitigations,threat-models}
mkdir -p scripts
mkdir -p security-reports
mkdir -p .github/workflows

touch security-reports/.gitkeep

echo ""
echo "Step 4: Create sample vulnerable code"
cat > src/vulnerable/sample.js << 'EOF'
const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  
  const result = await db.query(query);
  
  if (result.rows.length > 0) {
    return res.json({ success: true });
  }
  
  return res.status(401).json({ success: false });
});

router.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send(`<h1>Results for: ${searchTerm}</h1>`);
});

router.post('/upload', (req, res) => {
  const filename = req.body.filename;
  fs.readFile(filename, (err, data) => {
    res.send(data);
  });
});

module.exports = router;
EOF

echo ""
echo "Step 5: Create sample secure code"
cat > src/secure/sample.js << 'EOF'
const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const path = require('path');

router.post('/login',
  body('username').trim().isLength({ min: 3, max: 50 }),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = req.body;
    
    const query = 'SELECT * FROM users WHERE username = $1';
    const result = await db.query(query, [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (isValid) {
      return res.json({ success: true });
    }
    
    return res.status(401).json({ success: false });
  }
);

router.get('/search',
  query('q').trim().isLength({ min: 1, max: 100 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const searchTerm = req.query.q;
    const clean = DOMPurify.sanitize(searchTerm);
    res.send(`<h1>Results for: ${clean}</h1>`);
  }
);

router.post('/upload', (req, res) => {
  const filename = req.body.filename;
  const baseDir = '/var/www/uploads';
  const fullPath = path.join(baseDir, filename);
  
  if (!fullPath.startsWith(path.resolve(baseDir))) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  fs.readFile(fullPath, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'File read error' });
    }
    res.send(data);
  });
});

module.exports = router;
EOF

echo ""
echo "Step 6: Stage all files for Git"
git add .

echo ""
echo "Step 7: Test Semgrep without Git dependency"
echo "Running Semgrep with --no-git-ignore flag..."
semgrep --config semgrep-rules.yml src/ --no-git-ignore --verbose

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "You can now run:"
echo "  semgrep --config semgrep-rules.yml src/ --no-git-ignore"
echo "  bash scripts/run-semgrep.sh"
echo ""