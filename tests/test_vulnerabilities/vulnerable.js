// Test file with intentional vulnerabilities for testing

// Vulnerability 1: eval() usage (Critical)
function processUserInput(input) {
    return eval(input);
}

// Vulnerability 2: innerHTML XSS (High)
function displayUserContent(content) {
    document.getElementById('output').innerHTML = content;
}

// Vulnerability 3: SQL injection (Critical)
function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.query(query);
}

// Vulnerability 4: Hardcoded secret (High)
const API_KEY = "sk-1234567890abcdef";
const PASSWORD = "admin123";

// Vulnerability 5: Insecure randomness (Medium)
function generateToken() {
    return Math.random().toString(36);
}

// Vulnerability 6: Prototype pollution (High)
function mergeObjects(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// Vulnerability 7: Path traversal (High)
const fs = require('fs');
function readUserFile(filename) {
    return fs.readFileSync('./uploads/' + filename);
}

// Vulnerability 8: document.write XSS (High)
function writeContent(data) {
    document.write(data);
}
