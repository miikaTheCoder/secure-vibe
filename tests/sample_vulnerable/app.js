// Vulnerable JavaScript Application - For Testing Purposes
// This file contains intentional security vulnerabilities for testing Secure Vibe MCP

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'hardcoded_password_123',  // SEC-016: Hardcoded Secrets
  database: 'app_db'
});

// ============================================
// VULNERABILITY 1: Code Injection (SEC-001)
// ============================================
app.post('/api/calculate', (req, res) => {
  const { formula } = req.body;
  
  // DANGEROUS: Using eval() with user input
  const result = eval(formula);  // SEC-001: Code Injection via eval()
  
  res.json({ result });
});

// ============================================
// VULNERABILITY 2: SQL Injection (SEC-002)
// ============================================
app.get('/api/users', (req, res) => {
  const { id } = req.query;
  
  // DANGEROUS: String concatenation in SQL query
  const query = `SELECT * FROM users WHERE id = ${id}`;  // SEC-002: SQL Injection
  
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// ============================================
// VULNERABILITY 3: Command Injection (SEC-003)
// ============================================
const { exec } = require('child_process');

app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  // DANGEROUS: User input in command execution
  exec(`ping -c 4 ${host}`, (error, stdout) => {  // SEC-003: Command Injection
    res.send(stdout);
  });
});

// ============================================
// VULNERABILITY 4: XSS via innerHTML (SEC-009)
// ============================================
app.get('/api/render', (req, res) => {
  const { content } = req.query;
  
  // This would be in a client-side script, but demonstrating the pattern
  const html = `
    <html>
      <body>
        <div id="output"></div>
        <script>
          // DANGEROUS: Using innerHTML with user input
          document.getElementById('output').innerHTML = '${content}';  // SEC-009: XSS
        </script>
      </body>
    </html>
  `;
  
  res.send(html);
});

// ============================================
// VULNERABILITY 5: document.write XSS (SEC-010)
// ============================================
app.get('/api/legacy', (req, res) => {
  const { message } = req.query;
  
  const html = `
    <script>
      // DANGEROUS: document.write with user input
      document.write('<div>${message}</div>');  // SEC-010: document.write XSS
    </script>
  `;
  
  res.send(html);
});

// ============================================
// VULNERABILITY 6: Weak Hash Algorithm (SEC-015)
// ============================================
app.post('/api/hash', (req, res) => {
  const { data } = req.body;
  
  // DANGEROUS: Using weak hash algorithm
  const hash = crypto.createHash('md5').update(data).digest('hex');  // SEC-015: MD5
  // Also vulnerable: sha1
  const hash2 = crypto.createHash('sha1').update(data).digest('hex');  // SEC-015: SHA1
  
  res.json({ md5: hash, sha1: hash2 });
});

// ============================================
// VULNERABILITY 7: Insecure Random (SEC-017)
// ============================================
app.get('/api/token', (req, res) => {
  // DANGEROUS: Math.random() is not cryptographically secure
  const token = Math.random().toString(36).substring(2);  // SEC-017: Insecure Random
  
  res.json({ token });
});

// ============================================
// VULNERABILITY 8: Hardcoded JWT Secret (SEC-022)
// ============================================
const jwt = require('jsonwebtoken');

function generateToken(user) {
  // DANGEROUS: Hardcoded JWT secret
  const secret = 'my-super-secret-jwt-key-12345';  // SEC-022, SEC-016: Hardcoded Secrets
  
  return jwt.sign(user, secret, { algorithm: 'HS256' });
}

// ============================================
// VULNERABILITY 9: Path Traversal (SEC-035)
// ============================================
app.get('/api/download', (req, res) => {
  const { filename } = req.query;
  
  // DANGEROUS: No path validation
  const filePath = `./uploads/${filename}`;  // SEC-035: Path Traversal
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
      return;
    }
    res.send(data);
  });
});

// ============================================
// VULNERABILITY 10: Insecure Deserialization (SEC-026)
// ============================================
app.post('/api/process', (req, res) => {
  const { data } = req.body;
  
  // DANGEROUS: Insecure deserialization
  const obj = eval('(' + data + ')');  // SEC-026: Insecure Deserialization
  
  res.json({ processed: obj });
});

// ============================================
// VULNERABILITY 11: Open Redirect (SEC-032)
// ============================================
app.get('/api/redirect', (req, res) => {
  const { url } = req.query;
  
  // DANGEROUS: Unvalidated redirect
  res.redirect(url);  // SEC-032: Open Redirect
});

// ============================================
// VULNERABILITY 12: Regex DoS (SEC-044)
// ============================================
app.post('/api/validate', (req, res) => {
  const { email } = req.body;
  
  // DANGEROUS: Regex vulnerable to ReDoS
  const emailRegex = /^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})*$/;  // SEC-044: ReDoS
  
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

// ============================================
// VULNERABILITY 13: Insecure CORS (SEC-033)
// ============================================
app.use((req, res, next) => {
  // DANGEROUS: Overly permissive CORS
  res.header('Access-Control-Allow-Origin', '*');  // SEC-033: Insecure CORS
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// ============================================
// VULNERABILITY 14: Information Disclosure (SEC-030)
// ============================================
app.use((err, req, res, next) => {
  // DANGEROUS: Exposing stack traces in production
  res.status(500).json({
    error: err.message,
    stack: err.stack,  // SEC-030: Debug Info Exposure
    query: req.query,
    body: req.body
  });
});

// ============================================
// VULNERABILITY 15: NoSQL Injection (SEC-004)
// ============================================
const mongoose = require('mongoose');
const User = mongoose.model('User', new mongoose.Schema({}));

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // DANGEROUS: NoSQL injection vulnerability
  const user = await User.findOne({
    username: username,
    password: password  // SEC-004: NoSQL Injection if passed as object
  });
  
  if (user) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.status(401).json({ success: false });
  }
});

// ============================================
// VULNERABILITY 16: SSRF (SEC-031)
// ============================================
const axios = require('axios');

app.post('/api/fetch', async (req, res) => {
  const { url } = req.body;
  
  // DANGEROUS: Server-Side Request Forgery
  try {
    const response = await axios.get(url);  // SEC-031: SSRF
    res.send(response.data);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// ============================================
// VULNERABILITY 17: Weak Password Storage (SEC-021)
// ============================================
function hashPassword(password) {
  // DANGEROUS: Weak hashing without salt
  return crypto.createHash('sha256').update(password).digest('hex');  // SEC-021, SEC-019
}

// ============================================
// VULNERABILITY 18: Insecure Direct Object Reference (SEC-023)
// ============================================
app.get('/api/documents/:id', (req, res) => {
  const { id } = req.params;
  
  // DANGEROUS: No authorization check
  db.query('SELECT * FROM documents WHERE id = ?', [id], (err, results) => {  // SEC-023
    if (err) throw err;
    res.json(results[0]);
  });
});

// ============================================
// Additional Helper Functions with Vulnerabilities
// ============================================

// DANGEROUS: Dynamic code execution
function executeUserCode(code) {
  return new Function(code)();  // SEC-001: Code Injection
}

// DANGEROUS: setTimeout with string
function delayExecution(code, ms) {
  setTimeout(code, ms);  // SEC-001: Code Injection via setTimeout
}

// DANGEROUS: setInterval with string
function repeatExecution(code, ms) {
  setInterval(code, ms);  // SEC-001: Code Injection via setInterval
}

// DANGEROUS: Using Function constructor
function createFunction(body) {
  return new Function('return ' + body);  // SEC-001: Code Injection
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app listening on port ${PORT}`);
  console.log('⚠️  WARNING: This application contains intentional security vulnerabilities!');
  console.log('🔒 Use only for testing Secure Vibe MCP scanner');
});

module.exports = app;
