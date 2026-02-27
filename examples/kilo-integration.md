# Kilo CLI Integration Guide

This guide explains how to integrate Secure Vibe MCP with Kilo CLI for AI-powered security scanning.

## Prerequisites

- Kilo CLI installed (`npm install -g @kilocode/cli`)
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/miikaTheCoder/secure-vibe.git
cd secure-vibe
pip install -e .
```

### Step 2: Configure Kilo CLI

#### Option A: Project-Level Configuration (Recommended)

Create a `kilo.json` file in your project root (or `.kilo/kilo.json`):

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["python", "-m", "src.mcp_server"],
      "enabled": true,
      "environment": {
        "SEVERITY_THRESHOLD": "medium",
        "AUTO_PATCH": "false",
        "RULES_PATH": "./src/scanner/rules/rules.yaml",
        "BACKUP_ENABLED": "true",
        "PARALLEL_SCANNING": "true",
        "MAX_WORKERS": "4",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

#### Option B: Global Configuration

Add to `~/.config/kilo/kilo.json`:

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["python", "-m", "src.mcp_server"],
      "enabled": true,
      "environment": {
        "SEVERITY_THRESHOLD": "medium"
      }
    }
  }
}
```

### Step 3: Start Kilo CLI

```bash
kilo
```

Kilo will automatically detect and load the MCP configuration.

## Usage Examples

Once configured, you can use Secure Vibe directly in Kilo:

### Example 1: Scan Current File

```
User: Scan the current file for security vulnerabilities

Kilo: I'll scan the current file for security issues using Secure Vibe.

[Kilo uses the scan_file tool]

Found 3 vulnerabilities in app.js:

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

Kilo: I'll perform a comprehensive security scan of your project.

[Kilo uses the scan_directory tool]

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

### Example 3: Auto-Patch Vulnerabilities

```
User: Fix the SQL injection vulnerability in database.py

Kilo: I'll attempt to automatically patch the SQL injection vulnerability.

[Kilo uses the patch_vulnerability tool]

✅ Successfully patched database.py

Changes made:
- Line 45: Replaced string concatenation with parameterized query
- Before: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
- After: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

A backup was created at: database.py.bak
```

### Example 4: Check Available Rules

```
User: What security rules does Secure Vibe check for?

Kilo: Let me get the list of supported security rules.

[Kilo uses the list_rules tool]

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
```

## Available Tools

Secure Vibe MCP provides 7 tools that Kilo can use:

### 1. `scan_file`
Scan a single file for vulnerabilities.

**Parameters:**
- `file_path` (string, required): Path to the file
- `severity_threshold` (string): Minimum severity to report (low/medium/high/critical)

### 2. `scan_directory`
Scan an entire directory recursively.

**Parameters:**
- `directory` (string, required): Path to directory
- `severity_threshold` (string): Minimum severity to report

### 3. `scan_code`
Scan a code snippet directly.

**Parameters:**
- `code` (string, required): Code to scan
- `language` (string): Programming language (auto/python/javascript/go)
- `severity_threshold` (string): Minimum severity to report

### 4. `patch_vulnerability`
Automatically fix a vulnerability.

**Parameters:**
- `file_path` (string, required): File to patch
- `vulnerability_id` (string, required): Vulnerability ID to fix

### 5. `get_security_report`
Get a previous scan result.

**Parameters:**
- `scan_id` (string, required): Scan ID returned from a scan

### 6. `list_rules`
List all available security rules.

### 7. `configure_rules`
Update rule configuration.

**Parameters:**
- `config` (object): Configuration dictionary

## Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEVERITY_THRESHOLD` | `medium` | Minimum severity to report |
| `AUTO_PATCH` | `false` | Enable automatic patching |
| `RULES_PATH` | `./src/scanner/rules/rules.yaml` | Path to rules file |
| `BACKUP_ENABLED` | `true` | Create backups before patching |
| `PARALLEL_SCANNING` | `true` | Enable parallel scanning |
| `MAX_WORKERS` | `4` | Number of parallel workers |
| `LOG_LEVEL` | `INFO` | Logging level |

### Severity Thresholds

- `low`: Report all issues (most verbose)
- `medium`: Report medium and above (recommended)
- `high`: Report only high and critical
- `critical`: Report only critical issues

## Troubleshooting

### Issue: "MCP server not found"

**Solution:**
1. Verify the Python path in kilo.json is correct
2. Ensure dependencies are installed: `pip install -e .`
3. Check that `src/mcp_server.py` exists

```bash
# Test the server manually
cd /path/to/secure-vibe
python -m src.mcp_server
```

### Issue: MCP server doesn't start

**Solution:**
1. Check Python is in your PATH
2. Verify the working directory is correct
3. Add `cwd` to your config if needed:

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["python", "-m", "src.mcp_server"],
      "cwd": "/path/to/secure-vibe",
      "enabled": true
    }
  }
}
```

### Issue: Slow performance

**Solution:**
Adjust environment variables in config:
```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["python", "-m", "src.mcp_server"],
      "enabled": true,
      "environment": {
        "PARALLEL_SCANNING": "true",
        "MAX_WORKERS": "8",
        "SEVERITY_THRESHOLD": "high"
      }
    }
  }
}
```

## Best Practices

### 1. Always Review Patches

Even with auto-patch enabled, review changes before committing.

### 2. Use Backups

Keep `BACKUP_ENABLED: "true"` to ensure you can rollback.

### 3. Start with High Severity

Begin with `SEVERITY_THRESHOLD: "high"` to focus on critical issues first.

### 4. Regular Scans

Make security scanning part of your workflow.

## Support

- 📖 [Documentation](https://docs.secure-vibe.dev)
- 🐛 [Issue Tracker](https://github.com/miikaTheCoder/secure-vibe/issues)
- 💬 [Discussions](https://github.com/miikaTheCoder/secure-vibe/discussions)

## Next Steps

1. Try scanning a file: "Scan app.js for security issues"
2. Generate a report: "Create a security report"
3. Fix vulnerabilities: "Help me fix the SQL injection"
4. Explore rules: "Show me all authentication security rules"
