# Claude Code Integration Guide

This guide explains how to integrate Secure Vibe MCP with Claude Code (CLI) for AI-powered security scanning.

## Prerequisites

- Claude Code installed (`npm install -g @anthropic-ai/claude-code`)
- Secure Vibe MCP installed and configured
- Python 3.9+ installed

## Installation

### Step 1: Install Secure Vibe MCP

```bash
git clone https://github.com/miikaTheCoder/secure-vibe.git
cd secure-vibe
pip install -e .
```

### Step 2: Configure Claude Code

#### Method A: Using CLI (Recommended)

```bash
claude mcp add secure-vibe python -m src.mcp_server
```

#### Method B: Manual Configuration

Edit `~/.claude.json` (NOT `~/.claude/settings.json`):

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

**Important:** Claude Code MCP config goes in `~/.claude.json`, NOT in `~/.claude/settings.json` (that's a known bug in the docs).

#### Method C: Project-Level Configuration

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SEVERITY_THRESHOLD": "medium"
      }
    }
  }
}
```

### Step 3: Verify Configuration

```bash
claude mcp list
```

You should see `secure-vibe` in the list.

## Usage

Start Claude Code in your project:

```bash
cd /path/to/your/project
claude
```

Then ask:

```
User: Scan this project for security vulnerabilities
```

## Available Tools

- `scan_file` - Scan a single file
- `scan_directory` - Scan a directory recursively
- `scan_code` - Scan code snippets
- `patch_vulnerability` - Auto-fix vulnerabilities
- `get_security_report` - Get previous scan results
- `list_rules` - List available security rules
- `configure_rules` - Update rule configuration

## Troubleshooting

### Issue: MCP server not loading

**Solution:** Make sure you're editing `~/.claude.json`, NOT `~/.claude/settings.json`.

### Issue: Command not found

**Solution:** Use the full path to Python if needed:

```json
{
  "command": "/usr/bin/python3"
}
```

### Issue: Working directory error

**Solution:** Add `cwd` to your config:

```json
{
  "mcpServers": {
    "secure-vibe": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "cwd": "/path/to/secure-vibe"
    }
  }
}
```

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `SEVERITY_THRESHOLD` | `medium` | Minimum severity to report |
| `AUTO_PATCH` | `false` | Enable automatic patching |
| `RULES_PATH` | `./src/scanner/rules/rules.yaml` | Path to rules file |
| `BACKUP_ENABLED` | `true` | Create backups before patching |
| `PARALLEL_SCANNING` | `true` | Enable parallel scanning |
| `MAX_WORKERS` | `4` | Number of parallel workers |
| `LOG_LEVEL` | `INFO` | Logging level |
