const fs = require("fs");
const DOMPurify = require("dompurify")(new (require("jsdom").JSDOM)().window);

// mock database connection (intentional for lab)
const db = {
  query: async () => []
};

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
