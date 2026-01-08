// intentionally vulnerable ORM model (lab only)
const User = {
  findOne: async () => null
};

const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * VULNERABILITY: SQL Injection
 * OWASP: A03:2021 - Injection
 * CWE-89: Improper Neutralization of Special Elements used in SQL Command
 * 
 * Risk Level: CRITICAL
 * 
 * Attack Vector:
 * username: admin' OR '1'='1' --
 * This will bypass authentication entirely
 * 
 * Business Impact:
 * - Unauthorized access to all user accounts
 * - Data exfiltration
 * - Potential data manipulation or deletion
 */

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const query = `
    SELECT id, username, email, role 
    FROM users 
    WHERE username = '${username}' 
    AND password = '${password}'
  `;
  
  try {
    const result = await pool.query(query);
    
    if (result.rows.length > 0) {
      return res.json({
        success: true,
        user: result.rows[0],
        message: 'Login successful'
      });
    }
    
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      query: query
    });
  }
});

/*
 * VULNERABILITY: SQL Injection via Search
 * 
 * Attack Vector:
 * search: '; DROP TABLE users; --
 * This could lead to data destruction
 */

router.get('/search', async (req, res) => {
  const { search } = req.query;
  
  const query = `
    SELECT * FROM products 
    WHERE name LIKE '%${search}%' 
    OR description LIKE '%${search}%'
  `;
  
  try {
    const result = await pool.query(query);
    return res.json({
      success: true,
      results: result.rows,
      count: result.rowCount
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      query: query
    });
  }
});

/*
 * VULNERABILITY: NoSQL Injection (if using MongoDB)
 * 
 * Attack Vector:
 * {"username": {"$ne": null}, "password": {"$ne": null}}
 */

router.post('/nosql-login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await User.findOne({
    username: username,
    password: password
  });
  
  if (user) {
    return res.json({ success: true, user });
  }
  
  return res.status(401).json({
    success: false,
    message: 'Invalid credentials'
  });
});

module.exports = router;