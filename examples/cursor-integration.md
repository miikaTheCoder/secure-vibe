# Cursor Integration Guide

This guide explains how to integrate Secure Vibe MCP with Cursor for AI-powered security scanning directly in your editor.

## Prerequisites

- Cursor Editor installed (version 0.40.0 or higher)
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/yourusername/secure-vibe-mcp.git
cd secure-vibe-mcp
./install.sh
```

### Step 2: Configure Cursor

1. Open Cursor
2. Open **Settings** (`Cmd/Ctrl + ,`)
3. Navigate to **Cursor Settings** → **MCP**
4. Click **Add new MCP server**

Or edit the configuration file directly:

Create `.cursor/mcp.json` in your project root:

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
        "LOG_LEVEL": "INFO",
        "OUTPUT_FORMAT": "json"
      }
    }
  }
}
```

> **Note**: Replace `/path/to/secure-vibe/` with your actual installation path.

### Step 3: Add to Global Cursor Config (Optional)

For system-wide availability, add to:

- **macOS**: `~/.cursor/mcp.json`
- **Windows**: `%USERPROFILE%/.cursor/mcp.json`
- **Linux**: `~/.config/Cursor/mcp.json`

### Step 4: Reload Cursor

1. Open Command Palette (`Cmd/Ctrl + Shift + P`)
2. Run **Developer: Reload Window**
3. Verify Secure Vibe appears in MCP servers list

## Usage

### Using @ Mentions

In Cursor's AI chat, use `@secure-vibe` to invoke security scanning:

```
@secure-vibe scan the current file
```

### Using Command Palette

Access Secure Vibe commands via Command Palette:

1. `Cmd/Ctrl + Shift + P`
2. Type "Secure Vibe"
3. Select desired command

## Usage Examples

### Example 1: Scan Current File

In the AI chat input:

```
@secure-vibe scan this file for security vulnerabilities
```

Cursor will scan the currently active file and display results inline:

```
🔍 Scanning app.js...

Found 4 vulnerabilities:

🔴 Line 23: SQL Injection (SEC-002)
   const query = `SELECT * FROM users WHERE id = ${userId}`;
   
   💡 Fix: Use parameterized queries
   const query = 'SELECT * FROM users WHERE id = ?';
   db.execute(query, [userId]);

🟠 Line 45: eval() usage (SEC-001)
   eval(userInput);
   
   💡 Fix: Use JSON.parse() for JSON data

🟡 Line 67: Weak crypto (SEC-015)
   crypto.createHash('md5');
   
   💡 Fix: Use SHA-256 or bcrypt
```

### Example 2: Scan Project Directory

```
@secure-vibe scan the entire src directory
```

Results show in a dedicated panel:

```
📊 Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━
Files Scanned: 34
Vulnerabilities: 12 (2 critical, 4 high, 6 medium)
Overall Risk: 7.8/10

[View Full Report] [Export SARIF] [Generate Fixes]

🔴 Critical Issues
  • api/auth.js:23 - Hardcoded JWT secret
  • db/queries.js:45 - SQL Injection

🟠 High Issues
  • utils/crypto.js:12 - MD5 hash usage
  • ...
```

### Example 3: Quick Code Scan

Select code in editor and ask:

```
@secure-vibe is this code secure?
```

Or use the inline action:

1. Select code block
2. Right-click → "Secure Vibe: Scan Selection"
3. View results in inline hint

### Example 4: Auto-Fix Vulnerabilities

```
@secure-vibe fix the SQL injection in database.py
```

Cursor will:
1. Show the vulnerability
2. Propose a fix
3. Apply the patch (with your approval)
4. Verify the fix

```
🔧 Patching database.py

Proposed changes:
- Line 23: Parameterized query
- Line 45: Input validation

[Preview Changes] [Apply] [Skip]

✅ Patch applied successfully
Backup saved to: database.py.bak
```

### Example 5: Generate Security Report

```
@secure-vibe generate a security report for this project
```

Report opens in a new tab:

```markdown
# Security Assessment Report
Generated: 2025-01-20 14:30:00

## Executive Summary
- **Risk Level**: High (7.8/10)
- **Critical Issues**: 2
- **Remediation Time**: ~6 hours

## Findings

### 🔴 Critical (2)
1. **Hardcoded Credentials** (CWE-798)
   - File: config/api.js:15
   - CVSS: 9.1
   - [View] [Fix]

### 🟠 High (4)
...

## Recommendations
1. Implement secrets management
2. Use parameterized queries
3. Upgrade weak crypto
```

### Example 6: Check Security Rules

```
@secure-vibe what rules do you check for?
```

Shows searchable list:

```
📋 Security Rules (47 total)

Filter: [All Categories ▼] [Search...]

🔴 Injection (8)
  ☑ SEC-001: eval() usage
  ☑ SEC-002: SQL Injection
  ☑ SEC-003: Command Injection
  ...

🟠 Cryptography (6)
  ☑ SEC-015: Weak Hash
  ☑ SEC-016: Hardcoded Secrets
  ...
```

## Keyboard Shortcuts

Add custom keybindings in Cursor:

```json
// keybindings.json
[
  {
    "key": "ctrl+shift+s",
    "command": "secure-vibe.scanFile",
    "when": "editorTextFocus"
  },
  {
    "key": "ctrl+shift+a",
    "command": "secure-vibe.scanSelection",
    "when": "editorHasSelection"
  },
  {
    "key": "ctrl+shift+r",
    "command": "secure-vibe.generateReport"
  }
]
```

## Available Commands

### Via @ Mention

- `@secure-vibe scan file` - Scan current file
- `@secure-vibe scan directory` - Scan project
- `@secure-vibe scan selection` - Scan selected code
- `@secure-vibe fix` - Auto-fix vulnerabilities
- `@secure-vibe report` - Generate report
- `@secure-vibe rules` - Show security rules

### Via Command Palette

- `Secure Vibe: Scan Current File`
- `Secure Vibe: Scan Project`
- `Secure Vibe: Scan Selection`
- `Secure Vibe: Generate Report`
- `Secure Vibe: Fix Vulnerabilities`
- `Secure Vibe: Show Rules`
- `Secure Vibe: Configure`

### Context Menu (Right-Click)

- `Secure Vibe: Scan This File`
- `Secure Vibe: Scan Selection`
- `Secure Vibe: Fix This Issue`

## Configuration

### Project-Specific Settings

Create `.cursor/secure-vibe.json` in your project:

```json
{
  "severity_threshold": "high",
  "exclude_patterns": [
    "node_modules/**",
    "dist/**",
    "*.test.js"
  ],
  "custom_rules": "./security/custom-rules.yaml",
  "auto_patch": false,
  "backup_enabled": true
}
```

### Severity Thresholds

Configure based on your needs:

```json
{
  "severity_threshold": "medium"  // Report medium and above
}
```

Options:
- `low` - All issues
- `medium` - Medium+ (recommended for development)
- `high` - High+ (recommended for CI/CD)
- `critical` - Critical only

### Auto-Patch Settings

```json
{
  "auto_patch": false,        // Manual approval (recommended)
  "patch_confidence": 90,     // Minimum confidence %
  "backup_enabled": true      // Always create backups
}
```

## Inline Diagnostics

Enable real-time security hints:

```json
// settings.json
{
  "secure-vibe.enableDiagnostics": true,
  "secure-vibe.diagnosticSeverity": "warning",
  "secure-vibe.scanOnSave": true
}
```

Results appear as:
- 🔴 Red squiggly: Critical issues
- 🟠 Orange squiggly: High issues
- 🟡 Yellow squiggly: Medium issues

Hover for details and quick fixes.

## Troubleshooting

### MCP Server Not Found

**Error**: "Cannot find MCP server 'secure-vibe'"

**Solutions**:

1. Check Python path:
```bash
which python3
# Use this path in mcp.json
```

2. Verify virtual environment:
```bash
cd /path/to/secure-vibe
source .venv/bin/activate
python -c "import secure_vibe; print('OK')"
```

3. Test MCP server manually:
```bash
cd /path/to/secure-vibe
source .venv/bin/activate
python -m src.mcp_server
```

### Connection Errors

**Error**: "Failed to connect to MCP server"

**Solutions**:

1. Restart Cursor completely
2. Check firewall settings
3. Verify config JSON syntax:
```bash
python -m json.tool .cursor/mcp.json
```

### Slow Performance

**Solutions**:

1. Adjust workers in config:
```json
{
  "env": {
    "MAX_WORKERS": "8",
    "PARALLEL_SCANNING": "true"
  }
}
```

2. Exclude large directories:
```json
{
  "exclude_patterns": [
    "node_modules/**",
    "dist/**",
    ".git/**",
    "*.min.js"
  ]
}
```

3. Increase severity threshold:
```json
{
  "severity_threshold": "high"
}
```

### False Positives

If Secure Vibe reports false positives:

```
@secure-vibe mark SEC-015 as false positive in this file
```

Or add to `.cursor/secure-vibe.json`:

```json
{
  "ignore_rules": ["SEC-015"],
  "ignore_patterns": [
    "test/**",
    "**/*.test.js"
  ]
}
```

## Advanced Features

### Custom Rules

Create project-specific security rules:

```yaml
# .cursor/security-rules.yaml
rules:
  - id: CUSTOM-001
    name: "Company API Key Pattern"
    category: secrets
    severity: critical
    pattern: "company_api_[a-z0-9]{32}"
    message: "Company API key exposed"
    remediation: "Use environment variables"
```

Then reference in config:

```json
{
  "custom_rules": "./.cursor/security-rules.yaml"
}
```

### Pre-Commit Hooks

Add to `.cursor/hooks/pre-scan`:

```bash
#!/bin/bash
# Scan before commit
secure-vibe scan --dir . --severity high
if [ $? -ne 0 ]; then
  echo "Security issues found. Commit aborted."
  exit 1
fi
```

### Workspace Integration

For team-wide settings, commit `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "${workspaceFolder}/../secure-vibe/.venv/bin/python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "RULES_PATH": "${workspaceFolder}/security/rules.yaml"
      }
    }
  }
}
```

## Best Practices

### 1. Regular Scanning

Make scanning part of your workflow:
- Scan on file save (enable in settings)
- Scan before commits
- Weekly full project scans

### 2. Severity-Based Workflow

```
@secure-vibe scan --severity critical
# Fix all critical first

@secure-vibe scan --severity high
# Then high priority
```

### 3. Review All Patches

Always review auto-patches:

```
@secure-vibe show diff for the last patch
```

### 4. Use Backups

Keep `backup_enabled: true` and periodically clean old backups:

```bash
find . -name "*.bak" -mtime +30 -delete
```

### 5. Custom Rules for Business Logic

Add rules for your specific patterns:

```yaml
rules:
  - id: CUSTOM-BIZ-001
    name: "Hardcoded Business Rule"
    pattern: "if \(user\.type === 'admin'\)"
    message: "Hardcoded role check - use RBAC"
```

## Tips & Tricks

### Quick Scan with Selection

1. Select suspicious code
2. Press `Ctrl+Shift+A` (custom binding)
3. View instant results

### Batch Fixes

```
@secure-vibe fix all weak hash usages in the project
```

### Compare Scans

```
@secure-vibe compare scan from yesterday
```

### Export for CI/CD

```
@secure-vibe export sarif report for GitHub
```

## Support

- 📖 [Full Documentation](https://docs.secure-vibe.dev)
- 🐛 [Report Issues](https://github.com/yourusername/secure-vibe-mcp/issues)
- 💬 [Community Discussions](https://github.com/yourusername/secure-vibe-mcp/discussions)

## Next Steps

1. Try scanning: Open any file and press `Ctrl+Shift+S`
2. Review rules: `@secure-vibe show all rules`
3. Generate report: `@secure-vibe create security report`
4. Fix issues: `@secure-vibe fix vulnerabilities`
