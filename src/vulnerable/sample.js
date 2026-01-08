const fs = require("fs");

// intentionally unsafe mock DB for OWASP lab
const db = {
  query: async () => []
};

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
