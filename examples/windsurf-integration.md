# Windsurf Integration Guide

This guide explains how to integrate Secure Vibe MCP with Windsurf (Codeium) for AI-powered security scanning.

## Prerequisites

- Windsurf installed
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/miikaTheCoder/secure-vibe.git
cd secure-vibe
pip install -e .
```

### Step 2: Configure Windsurf

#### Method A: Using Command Palette

1. Open Windsurf
2. Press `Cmd+Shift+P` (Mac) / `Ctrl+Shift+P` (Windows)
3. Type and select: "Windsurf: Configure MCP Servers"
4. This opens the `mcp_config.json` file

#### Method B: Direct File Edit

The config file is located at:

- **macOS/Linux:** `~/.codeium/windsurf/mcp_config.json`
- **Windows:** `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

Create or edit this file:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SEVERITY_THRESHOLD": "medium",
        "AUTO_PATCH": "false",
        "RULES_PATH": "/path/to/secure-vibe/src/scanner/rules/rules.yaml",
        "BACKUP_ENABLED": "true",
        "PARALLEL_SCANNING": "true",
        "MAX_WORKERS": "4",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

#### Method C: Project-Level Configuration

You can also add MCP servers via the Windsurf UI:

1. Click the **Plugins** icon in the sidebar
2. Click **Manage plugins**
3. Click **View raw config**
4. Add your server configuration

### Step 3: Restart Windsurf

Close and reopen Windsurf to load the MCP configuration.

## Usage Examples

### Example 1: Scan Current File

In the Windsurf chat:

```
User: @secure-vibe Scan the current file for security vulnerabilities

Windsurf: [Uses scan_file tool]

Found 3 vulnerabilities:

🔴 Critical (1)
  • SEC-001: Code Injection via eval() on line 42
    
🟠 High (1)
  • SEC-015: Weak Hash Algorithm on line 67
    
🟡 Medium (1)
  • SEC-033: Insecure CORS Configuration on line 89
```

### Example 2: Scan Project Directory

```
User: @secure-vibe Scan my project for security issues

Windsurf: [Uses scan_directory tool]

📊 Scan Summary
• Files scanned: 47
• Vulnerabilities found: 12

Breakdown:
🔴 Critical: 2
🟠 High: 4
🟡 Medium: 6
🟢 Low: 0
```

### Example 3: Auto-Patch Vulnerabilities

```
User: @secure-vibe Fix the SQL injection in database.py

Windsurf: [Uses patch_vulnerability tool]

✅ Successfully patched database.py

Changes:
- Line 45: Replaced string concatenation with parameterized query
- Backup created: database.py.bak
```

## Available Tools

- `scan_file` - Scan a single file
- `scan_directory` - Scan a directory recursively
- `scan_code` - Scan code snippets
- `patch_vulnerability` - Auto-fix vulnerabilities
- `get_security_report` - Get previous scan results
- `list_rules` - List available security rules
- `configure_rules` - Update rule configuration

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

### Issue: MCP server not found

**Solution:**
1. Verify Python is in your PATH
2. Check the config file location:
   - macOS/Linux: `~/.codeium/windsurf/mcp_config.json`
   - Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

### Issue: Server not loading

**Solution:** Check that your JSON syntax is valid. Common issues:
- Missing commas between properties
- Incorrect quote marks (use double quotes)

### Issue: Working directory error

**Solution:** Add the full path to your secure-vibe directory:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "/usr/bin/python3",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SEVERITY_THRESHOLD": "medium"
      }
    }
  }
}
```

### Issue: Slow performance

**Solution:** Adjust environment variables:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
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

### 4. Use @secure-vibe

Reference Secure Vibe in your prompts using `@secure-vibe` to ensure the correct MCP server is used.

## Support

- 📖 [Documentation](https://docs.secure-vibe.dev)
- 🐛 [Issue Tracker](https://github.com/miikaTheCoder/secure-vibe/issues)
