# OpenCode Integration Guide

This guide explains how to integrate Secure Vibe MCP with OpenCode for AI-powered security scanning.

## Prerequisites

- OpenCode installed
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/miikaTheCoder/secure-vibe.git
cd secure-vibe
pip install -e .
```

### Step 2: Configure OpenCode

Create or edit `opencode.json` in your project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
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

#### Alternative: Global Configuration

Create `~/.config/opencode/config.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
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

### Step 3: Start OpenCode

```bash
opencode
```

OpenCode will automatically detect and load the MCP configuration.

## Usage Examples

### Example 1: Scan Current File

```
User: Scan the current file for security vulnerabilities

OpenCode: [Uses scan_file tool]

Found vulnerabilities:
• SEC-001: Code Injection via eval() on line 42
• SEC-015: Weak Hash Algorithm on line 67
```

### Example 2: Scan Project Directory

```
User: Scan my project for security issues

OpenCode: [Uses scan_directory tool]

📊 Scan Summary
• Files scanned: 47
• Vulnerabilities found: 12
• Critical: 2, High: 4, Medium: 6
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

## Remote MCP Servers

OpenCode supports remote MCP servers. To use Secure Vibe as a remote server:

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "remote",
      "url": "http://localhost:8000/mcp",
      "enabled": true
    }
  }
}
```

## Troubleshooting

### Issue: MCP server not found

**Solution:**
1. Verify Python is in your PATH
2. Check the working directory is correct
3. Use absolute path to Python if needed:

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["/usr/bin/python3", "-m", "src.mcp_server"]
    }
  }
}
```

### Issue: Slow performance

**Solution:** Adjust environment variables:

```json
{
  "mcp": {
    "secure-vibe": {
      "type": "local",
      "command": ["python", "-m", "src.mcp_server"],
      "environment": {
        "PARALLEL_SCANNING": "true",
        "MAX_WORKERS": "8",
        "SEVERITY_THRESHOLD": "high"
      }
    }
  }
}
```
