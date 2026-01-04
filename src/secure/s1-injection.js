const express = require('express');
const { Pool } = require('pg');
const { body, query, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * SECURE IMPLEMENTATION: SQL Injection Prevention
 * 
 * Mitigation Strategies:
 * 1. Parameterized queries (prepared statements)
 * 2. Input validation using express-validator
 * 3. Input sanitization
 * 4. Principle of least privilege for database user
 * 5. ORM usage (Sequelize) as additional layer
 * 
 * Security Controls:
 * - Whitelist validation
 * - Type checking
 * - Length restrictions
 * - Character encoding
 */

const loginValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain alphanumeric characters, underscores, and hyphens'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
];

router.post('/login', loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  
  const { username, password } = req.body;
  
  const query = `
    SELECT id, username, email, role, password_hash 
    FROM users 
    WHERE username = $1
  `;
  
  try {
    const result = await pool.query(query, [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: process.env.JWT_EXPIRATION,
        issuer: 'owasp-lab',
        audience: 'owasp-lab-users'
      }
    );
    
    const { password_hash, ...userWithoutPassword } = user;
    
    return res.json({
      success: true,
      token: token,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during login'
    });
  }
});

/*
 * SECURE IMPLEMENTATION: Search with Parameterized Queries
 * 
 * Additional protections:
 * - ILIKE with proper escaping
 * - Pagination to prevent data dumping
 * - Result limiting
 */

const searchValidation = [
  query('search')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be between 1 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-_.,]+$/)
    .withMessage('Search term contains invalid characters'),
  query('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .toInt()
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .toInt()
    .withMessage('Limit must be between 1 and 100')
];

router.get('/search', searchValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  
  const search = req.query.search;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  
  const searchPattern = `%${search}%`;
  
  const query = `
    SELECT id, name, description, price, category
    FROM products 
    WHERE name ILIKE $1 OR description ILIKE $2
    ORDER BY name
    LIMIT $3 OFFSET $4
  `;
  
  const countQuery = `
    SELECT COUNT(*) as total
    FROM products 
    WHERE name ILIKE $1 OR description ILIKE $2
  `;
  
  try {
    const [results, countResult] = await Promise.all([
      pool.query(query, [searchPattern, searchPattern, limit, offset]),
      pool.query(countQuery, [searchPattern, searchPattern])
    ]);
    
    const totalResults = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(totalResults / limit);
    
    return res.json({
      success: true,
      results: results.rows,
      pagination: {
        page: page,
        limit: limit,
        totalResults: totalResults,
        totalPages: totalPages
      }
    });
  } catch (error) {
    console.error('Search error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during search'
    });
  }
});

/*
 * SECURE IMPLEMENTATION: ORM Usage with Sequelize
 * 
 * Additional layer of protection through ORM's built-in sanitization
 */

const { User } = require('../models/user.model');

router.get('/users/:id', async (req, res) => {
  const userId = parseInt(req.params.id);
  
  if (isNaN(userId)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid user ID'
    });
  }
  
  try {
    const user = await User.findByPk(userId, {
      attributes: ['id', 'username', 'email', 'role', 'created_at']
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    return res.json({
      success: true,
      user: user
    });
  } catch (error) {
    console.error('User fetch error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred while fetching user'
    });
  }
});

module.exports = router;