# Claude Desktop Integration Guide

This guide explains how to integrate Secure Vibe MCP with Claude Desktop for AI-powered security scanning.

## Prerequisites

- Claude Desktop installed (version 1.0.0 or higher)
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/yourusername/secure-vibe-mcp.git
cd secure-vibe-mcp
./install.sh
```

### Step 2: Configure Claude Desktop

1. Open Claude Desktop
2. Go to **Settings** → **Developer** → **Edit Config**
3. Or edit the file directly at:
   - **macOS**: `~/Library/Application Support/Claude/config.json`
   - **Windows**: `%APPDATA%/Claude/config.json`
   - **Linux**: `~/.config/Claude/config.json`

4. Add the Secure Vibe MCP configuration:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "/path/to/secure-vibe/.venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SEVERITY_THRESHOLD": "medium",
        "AUTO_PATCH": "false",
        "RULES_PATH": "/path/to/secure-vibe/src/scanner/rules/rules.yaml",
        "BACKUP_ENABLED": "true",
        "PARALLEL_SCANNING": "true",
        "MAX_WORKERS": "4",
        "LOG_LEVEL": "INFO"
      },
      "disabled": false
    }
  }
}
```

> **Note**: Update `/path/to/secure-vibe/` with your actual installation path.

### Step 3: Restart Claude Desktop

1. Fully quit Claude Desktop (Cmd+Q / Ctrl+Q)
2. Restart the application
3. Check the Developer panel to confirm Secure Vibe is connected

## Usage Examples

Once configured, you can use Secure Vibe directly in Claude conversations:

### Example 1: Scan Current File

```
User: Scan the current file for security vulnerabilities

Claude: I'll scan the current file for security issues using Secure Vibe.

[Claude uses the scan_file tool]

I found 3 vulnerabilities in app.js:

🔴 Critical (1)
  • SEC-001: Code Injection via eval() on line 42
    eval(userInput)
    
🟠 High (1)
  • SEC-015: Weak Hash Algorithm on line 67
    crypto.createHash('md5')
    
🟡 Medium (1)
  • SEC-033: Insecure CORS Configuration on line 89
```

### Example 2: Scan Project Directory

```
User: Scan my entire project for security issues

Claude: I'll perform a comprehensive security scan of your project.

[Claude uses the scan_directory tool]

📊 Scan Summary
• Files scanned: 47
• Vulnerabilities found: 12
• Risk score: 7.2/10

Breakdown by severity:
🔴 Critical: 2
🟠 High: 4
🟡 Medium: 6
🟢 Low: 0

Top issues to address:
1. SQL Injection in api/users.js:23
2. Hardcoded API key in config.js:15
3. eval() usage in utils.js:78
```

### Example 3: Generate Security Report

```
User: Generate a security report for this codebase

Claude: I'll generate a comprehensive security report.

[Claude uses the get_security_report tool]

I've generated a security report with the following findings:

📄 Report saved to: security-report.html

Executive Summary:
• Overall security rating: C (needs improvement)
• Critical issues requiring immediate attention: 2
• Estimated time to remediate: 4-6 hours

High Priority Issues:
1. SQL Injection (CWE-89) - CVSS 9.8
2. Hardcoded Credentials (CWE-798) - CVSS 9.1

Would you like me to help fix these vulnerabilities?
```

### Example 4: Auto-Patch Vulnerabilities

```
User: Fix the SQL injection vulnerability in database.py

Claude: I'll attempt to automatically patch the SQL injection vulnerability.

[Claude uses the patch_vulnerability tool]

✅ Successfully patched database.py

Changes made:
- Line 45: Replaced string concatenation with parameterized query
- Before: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
- After:  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

A backup was created at: database.py.bak

The fix addresses CWE-89 (SQL Injection) and reduces the CVSS score from 9.8 to 0.0
```

### Example 5: Check Available Rules

```
User: What security rules does Secure Vibe check for?

Claude: Let me get the list of supported security rules.

[Claude uses the get_supported_rules tool]

Secure Vibe includes 47 security rules across 9 categories:

🔴 Injection (8 rules)
  • SEC-001: Code Injection via eval()
  • SEC-002: SQL Injection
  • SEC-003: Command Injection
  • ...

🟠 Cryptography (6 rules)
  • SEC-015: Weak Hash (MD5/SHA1)
  • SEC-016: Hardcoded Secrets
  • ...

🟡 Authentication (5 rules)
  • SEC-021: Weak Password Policy
  • SEC-022: JWT None Algorithm
  • ...

Would you like details on any specific rule category?
```

## Available Tools

Secure Vibe MCP provides 7 tools that Claude can use:

### 1. `scan_file`
Scan a single file for vulnerabilities.

**Parameters:**
- `file_path` (string, required): Path to the file
- `include_code` (boolean): Include vulnerable code snippets

### 2. `scan_directory`
Scan an entire directory recursively.

**Parameters:**
- `directory_path` (string, required): Path to directory
- `recursive` (boolean): Scan subdirectories
- `file_extensions` (array): File types to scan
- `exclude_patterns` (array): Patterns to exclude

### 3. `scan_code`
Scan a code snippet directly.

**Parameters:**
- `code` (string, required): Code to scan
- `language` (string, required): Programming language
- `include_remediation` (boolean): Include fix suggestions

### 4. `get_security_report`
Generate a comprehensive security report.

**Parameters:**
- `target_path` (string, required): Path to scan
- `report_format` (string): json, yaml, sarif, html
- `severity_filter` (array): Filter by severity
- `include_statistics` (boolean): Include stats

### 5. `patch_vulnerability`
Automatically fix a vulnerability.

**Parameters:**
- `file_path` (string, required): File to patch
- `vulnerability_id` (string, required): Rule ID
- `backup` (boolean): Create backup

### 6. `validate_fix`
Verify a patch was applied correctly.

**Parameters:**
- `original_file` (string): Original file path
- `patched_file` (string): Patched file path
- `vulnerability_type` (string): Type of vulnerability

### 7. `get_supported_rules`
List all available security rules.

**Parameters:**
- `category` (string): Filter by category
- `include_descriptions` (boolean): Include descriptions

## Troubleshooting

### Issue: "MCP server not found"

**Solution:**
1. Verify the Python path in config.json is correct
2. Ensure the virtual environment is set up
3. Check that `src/mcp_server.py` exists

```bash
# Test the server manually
cd /path/to/secure-vibe
source .venv/bin/activate
python -m src.mcp_server
```

### Issue: "Permission denied"

**Solution:**
```bash
chmod +x /path/to/secure-vibe/.venv/bin/python
```

### Issue: Claude doesn't recognize commands

**Solution:**
1. Restart Claude Desktop completely
2. Check Developer panel for errors
3. Verify JSON syntax in config file

```bash
# Validate JSON
python -m json.tool ~/.config/Claude/config.json
```

### Issue: Slow performance

**Solution:**
Adjust environment variables in config:
```json
{
  "env": {
    "PARALLEL_SCANNING": "true",
    "MAX_WORKERS": "8",
    "SEVERITY_THRESHOLD": "high"
  }
}
```

## Configuration Options

### Severity Thresholds

- `low`: Report all issues (most verbose)
- `medium`: Report medium and above (recommended)
- `high`: Report only high and critical
- `critical`: Report only critical issues

### Auto-Patch Settings

- `AUTO_PATCH: "false"`: Manual approval required (recommended)
- `AUTO_PATCH: "true"`: Automatic patching (use with caution)
- `BACKUP_ENABLED: "true"`: Always create backups before patching

### Performance Tuning

- `PARALLEL_SCANNING`: Enable multi-threading
- `MAX_WORKERS`: Number of parallel workers (2-8 recommended)
- `ENABLE_SEMANTIC_ANALYSIS`: Deep code analysis (slower but thorough)

## Best Practices

### 1. Always Review Patches

Even with auto-patch enabled, review changes before committing:

```
User: Review the changes made by the security patch

Claude: Let me show you the diff of the patched file...
```

### 2. Use Backups

Keep `BACKUP_ENABLED: "true"` to ensure you can rollback:

```bash
# If something goes wrong
cp app.js.bak app.js
```

### 3. Start with High Severity

Begin with `SEVERITY_THRESHOLD: "high"` to focus on critical issues first.

### 4. Regular Scans

Make security scanning part of your workflow:

```
User: Scan any new security issues since yesterday
```

### 5. Custom Rules

Add project-specific rules for your codebase patterns.

## Advanced Usage

### Custom Rules Integration

```
User: Add a custom rule to detect our internal API key format

Claude: I'll help you create a custom security rule. What's the pattern for your API keys?

User: They look like "sk_internal_" followed by 32 characters

Claude: [Creates custom rule file]

I've created a custom rule at custom-rules.yaml:

rules:
  - id: CUSTOM-001
    name: "Internal API Key Exposure"
    pattern: "sk_internal_[a-zA-Z0-9]{32}"
    severity: critical
    
This will now be checked in all scans.
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Secure Vibe
        uses: secure-vibe/action@v1
        with:
          severity-threshold: high
```

## Support

- 📖 [Documentation](https://docs.secure-vibe.dev)
- 🐛 [Issue Tracker](https://github.com/yourusername/secure-vibe-mcp/issues)
- 💬 [Discussions](https://github.com/yourusername/secure-vibe-mcp/discussions)

## Next Steps

1. Try scanning a file: "Scan app.js for security issues"
2. Generate a report: "Create a security report"
3. Fix vulnerabilities: "Help me fix the SQL injection"
4. Explore rules: "Show me all authentication security rules"
