<div align="center">

# 🔒 Secure Vibe MCP

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Scan](https://img.shields.io/badge/security-scanning-green.svg)](https://github.com/yourusername/secure-vibe-mcp)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io/)

**AI-powered security vulnerability detection and auto-patching for your codebase**

[Installation](#installation) • [Configuration](#configuration) • [Usage](#usage) • [Rules](#security-rules) • [Contributing](#contributing)

</div>

---

## 📋 Overview

Secure Vibe MCP is an advanced security scanning engine that integrates with AI coding assistants through the Model Context Protocol (MCP). It detects 50+ security vulnerabilities across multiple languages and provides intelligent auto-patching capabilities.

### Key Features

- 🔍 **50+ Security Rules** - Comprehensive vulnerability detection
- 🚀 **MCP Integration** - Works with Claude, Cursor, Windsurf, and more
- 🛠️ **Auto-Patching** - Automatically fix vulnerabilities with one command
- 📊 **Multi-Language** - JavaScript, TypeScript, Python, Go, Rust, Java, C/C++
- 🧠 **AI-Powered** - Semantic analysis and dataflow tracking
- ⚡ **Parallel Scanning** - Fast multi-threaded analysis
- 📈 **Detailed Reports** - Risk scores, CVSS ratings, remediation guidance

---

## 🚀 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-vibe-mcp.git
cd secure-vibe-mcp

# Run the installation script
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Check Python version (3.9+ required)
python3 --version

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Verify installation
secure-vibe --version
```

### Requirements

- Python 3.9 or higher
- 2GB RAM minimum (4GB recommended)
- Unix-like system (Linux/macOS) or Windows with WSL

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SEVERITY_THRESHOLD` | `medium` | Minimum severity to report (low/medium/high/critical) |
| `AUTO_PATCH` | `false` | Enable automatic vulnerability patching |
| `RULES_PATH` | `./src/scanner/rules/rules.yaml` | Path to custom rules file |
| `BACKUP_ENABLED` | `true` | Create backups before patching |
| `PARALLEL_SCANNING` | `true` | Enable parallel file scanning |
| `MAX_WORKERS` | `4` | Number of parallel workers |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `OUTPUT_FORMAT` | `json` | Output format (json/yaml/sarif) |

### MCP Configuration

Add to your MCP client configuration:

**Claude Desktop** (`~/.config/claude/config.json`):
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

**Cursor** (`.cursor/mcp.json`):
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

---

## 🎯 Usage

### Available Tools

Secure Vibe MCP provides 7 powerful tools:

#### 1. `scan_file` - Scan a single file

```python
# Example: Scan a specific file
result = await mcp.scan_file({
    "file_path": "/path/to/app.js",
    "include_code": true
})
```

```bash
# CLI equivalent
secure-vibe scan --file app.js
```

#### 2. `scan_directory` - Scan entire directories

```python
# Example: Scan a directory recursively
result = await mcp.scan_directory({
    "directory_path": "/path/to/src",
    "recursive": true,
    "file_extensions": [".js", ".ts", ".py"],
    "exclude_patterns": ["node_modules", "__pycache__"]
})
```

```bash
# CLI equivalent
secure-vibe scan --dir ./src --recursive --ext js,ts,py
```

#### 3. `scan_code` - Scan code snippets

```python
# Example: Scan inline code
result = await mcp.scan_code({
    "code": "eval(user_input)",
    "language": "javascript",
    "include_remediation": true
})
```

#### 4. `get_security_report` - Generate comprehensive reports

```python
# Example: Full security report
result = await mcp.get_security_report({
    "target_path": "/path/to/project",
    "report_format": "json",
    "include_remediation": true,
    "include_statistics": true,
    "severity_filter": ["high", "critical"]
})
```

#### 5. `patch_vulnerability` - Auto-fix vulnerabilities

```python
# Example: Patch a specific vulnerability
result = await mcp.patch_vulnerability({
    "file_path": "/path/to/app.js",
    "vulnerability_id": "SEC-001",
    "backup": true
})
```

#### 6. `validate_fix` - Verify patches

```python
# Example: Validate a fix
result = await mcp.validate_fix({
    "original_file": "/path/to/app.js.bak",
    "patched_file": "/path/to/app.js",
    "vulnerability_type": "eval_usage"
})
```

#### 7. `get_supported_rules` - List all rules

```python
# Example: Get all security rules
result = await mcp.get_supported_rules({
    "category": "all",
    "include_descriptions": true
})
```

### Python SDK Usage

```python
from secure_vibe import SecurityScanner, Config

# Initialize scanner
config = Config(
    severity_threshold="medium",
    auto_patch=False
)
scanner = SecurityScanner(config)

# Scan a file
results = scanner.scan_file("app.js")
print(f"Found {len(results.vulnerabilities)} vulnerabilities")

# Scan directory
results = scanner.scan_directory("./src")
for vuln in results.vulnerabilities:
    print(f"{vuln.rule_id}: {vuln.message}")

# Auto-patch
scanner.patch_vulnerability("app.js", "SEC-001")
```

### Command Line Usage

```bash
# Scan single file
secure-vibe scan --file app.js --format json

# Scan directory
secure-vibe scan --dir ./src --severity high --recursive

# Generate report
secure-vibe report --output security-report.html --format html

# Auto-patch vulnerabilities
secure-vibe patch --file app.js --rule SEC-001 --backup

# List all rules
secure-vibe rules --category injection

# Check version
secure-vibe --version
```

---

## 📜 Security Rules

Secure Vibe includes **47 comprehensive security rules** across 9 categories:

### Injection Vulnerabilities (8 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-001` | Code Injection via eval() | Critical | JS, TS, Python |
| `SEC-002` | SQL Injection | Critical | All |
| `SEC-003` | Command Injection | Critical | Python, JS |
| `SEC-004` | NoSQL Injection | High | JS, Python |
| `SEC-005` | LDAP Injection | High | Java, Python |
| `SEC-006` | XPath Injection | High | Java, C# |
| `SEC-007` | XML Injection | High | All |
| `SEC-008` | Template Injection | Critical | Python, JS |

### XSS & DOM Security (6 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-009` | innerHTML XSS | Critical | JS, TS |
| `SEC-010` | document.write XSS | Critical | JS |
| `SEC-011` | DOM-based XSS | High | JS, TS |
| `SEC-012` | Reflected XSS | High | All |
| `SEC-013` | Stored XSS | Critical | All |
| `SEC-014` | Dangerous React props | High | React |

### Cryptography (6 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-015` | Weak Hash (MD5/SHA1) | High | All |
| `SEC-016` | Hardcoded Secrets | Critical | All |
| `SEC-017` | Insecure Random | Medium | All |
| `SEC-018` | Weak Crypto Algorithm | High | All |
| `SEC-019` | Missing Salt | High | All |
| `SEC-020` | ECB Mode Usage | High | All |

### Authentication (5 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-021` | Weak Password Policy | Medium | All |
| `SEC-022` | JWT None Algorithm | Critical | All |
| `SEC-023` | Missing Auth Check | Critical | All |
| `SEC-024` | Insecure Session | High | All |
| `SEC-025` | Hardcoded Credentials | Critical | All |

### Data Protection (5 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-026` | Insecure Deserialization | Critical | All |
| `SEC-027` | Sensitive Data Exposure | High | All |
| `SEC-028` | PII Logging | Medium | All |
| `SEC-029` | Unencrypted Storage | High | All |
| `SEC-030` | Debug Info Exposure | Medium | All |

### Network Security (4 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-031` | SSRF | Critical | All |
| `SEC-032` | Open Redirect | Medium | All |
| `SEC-033` | Insecure CORS | Medium | All |
| `SEC-034` | Missing TLS | High | All |

### File Operations (5 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-035` | Path Traversal | Critical | All |
| `SEC-036` | Arbitrary File Upload | Critical | All |
| `SEC-037` | Zip Slip | Critical | Java, Python |
| `SEC-038` | Unrestricted File Deletion | High | All |
| `SEC-039` | Unsafe File Permissions | Medium | All |

### Rust Security (50 rules)

| Rule ID | Name | Severity | Category |
|---------|------|----------|----------|
| `RS001` | Unsafe Block Usage | High | Memory Safety |
| `RS002` | Unsafe Function | High | Memory Safety |
| `RS003` | Raw Pointer Dereference | Critical | Memory Safety |
| `RS004` | SQL Injection (String Format) | Critical | Injection |
| `RS005` | SQL Injection (format! macro) | Critical | Injection |
| `RS006` | Command Injection | Critical | Injection |
| `RS007` | Command with Shell Execution | High | Injection |
| `RS008` | Path Traversal | High | File Operations |
| `RS009` | Panic on User Input | High | Error Handling |
| `RS010` | unwrap() on Result | Medium | Error Handling |
| `RS011` | expect() on Result | Medium | Error Handling |
| `RS012` | unwrap() on Option | Medium | Error Handling |
| `RS013` | Hardcoded Password | Critical | Secrets |
| `RS014` | Hardcoded API Key | Critical | Secrets |
| `RS015` | TLS Verification Disabled | High | Crypto/TLS |
| `RS016` | Weak Random Number Generator | High | Crypto/TLS |
| `RS017` | Insecure Hash (MD5) | Medium | Crypto/TLS |
| `RS018` | Insecure Hash (SHA1) | Medium | Crypto/TLS |
| `RS019` | Deserialization Without Validation | High | Data |
| `RS020` | debug_assert! Usage | Low | Debug |
| `RS021` | Insecure Temp File | Medium | File Operations |
| `RS022` | Dangerous transmute | Critical | Memory Safety |
| `RS023` | mem::forget Usage | Medium | Memory Safety |
| `RS024` | Uninitialized Memory | Critical | Memory Safety |
| `RS025` | Manual drop_in_place | High | Memory Safety |
| `RS026` | FFI Boundary Unsafe | High | FFI |
| `RS027` | Environment Variable Unsafe | Low | Config |
| `RS028` | Mutable Static State | Medium | Concurrency |
| `RS029` | Blocking in Async Context | Medium | Async |
| `RS030` | Insecure SSL/TLS Version | High | Crypto/TLS |
| `RS031` | Windows Batch Command Injection (CVE-2024-24576) | Critical | Injection |
| `RS032` | Deeply Nested JSON (CVE-2024-58264) | High | DoS |
| `RS033` | Unmaintained serde_yml (RUSTSEC-2025-0068) | Medium | Dependencies |
| `RS034` | SQLx Binary Protocol Issue (RUSTSEC-2024-0363) | High | Database |
| `RS035` | Typosquatted Dependency | Critical | Supply Chain |
| `RS036` | Malicious Crate Usage | Critical | Supply Chain |
| `RS037` | Build Script Command Execution | High | Supply Chain |
| `RS038` | Proc-Macro Code Execution | High | Supply Chain |
| `RS039` | Open Redirect | Medium | Web |
| `RS040` | Format Injection | Medium | Injection |
| `RS041` | XSS via HTML Rendering | High | Web |
| `RS042` | SSRF Vulnerability | High | Web |
| `RS043` | JWT Validation Bypass | Critical | Auth |
| `RS044` | TOCTOU Race Condition | Medium | Concurrency |
| `RS045` | Unsafe Signal Handler | High | System |
| `RS046` | Lazy Static Mutable | Medium | Concurrency |
| `RS047` | IDNA/Punycode Spoofing (CVE-2024-12224) | High | Web |
| `RS048` | Axum DoS via Extractor | Medium | Web |
| `RS049` | Tonic gRPC Misconfiguration | Medium | Web |
| `RS050` | CORS Misconfiguration | Medium | Web |

### Dependencies (4 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-040` | Known Vulnerable Package | High | All |
| `SEC-041` | Outdated Dependency | Medium | All |
| `SEC-042` | Unverified Package | Medium | JS, Python |
| `SEC-043` | Malicious Package Pattern | Critical | All |

### Other Security (4 rules)

| Rule ID | Name | Severity | Languages |
|---------|------|----------|-----------|
| `SEC-044` | Regex DoS | Medium | All |
| `SEC-045` | Race Condition | Medium | All |
| `SEC-046` | TOCTOU | High | C, C++ |
| `SEC-047` | Integer Overflow | High | C, C++ |

---

## 🩹 Auto-Patch Capabilities

Secure Vibe can automatically fix many vulnerabilities:

### Supported Auto-Fixes

| Vulnerability | Fix Strategy | Success Rate |
|--------------|--------------|--------------|
| eval() usage | Replace with safer alternatives | 95% |
| innerHTML | Replace with textContent | 98% |
| MD5/SHA1 | Upgrade to SHA-256 | 100% |
| SQL Injection | Parameterize queries | 85% |
| Hardcoded secrets | Move to environment variables | 90% |
| Weak crypto | Use secure algorithms | 95% |

### Patch Validation

Every patch is validated to ensure:
- ✅ Syntax correctness
- ✅ Functional equivalence
- ✅ Security improvement
- ✅ No new vulnerabilities introduced

### Safety Features

- Automatic backups before patching
- Rollback capability
- Preview mode (dry-run)
- Confidence scoring

---

## 🔌 IDE Integration

### Claude Desktop

See [examples/claude-integration.md](examples/claude-integration.md) for detailed setup instructions.

**Quick Start:**
1. Install Secure Vibe MCP
2. Add MCP config to Claude Desktop
3. Restart Claude
4. Ask: "Scan this codebase for security vulnerabilities"

### Cursor

See [examples/cursor-integration.md](examples/cursor-integration.md) for detailed setup instructions.

**Quick Start:**
1. Open Cursor Settings
2. Add MCP server configuration
3. Use `@secure-vibe` in chat
4. Run security scans inline

### Windsurf

See [examples/windsurf-integration.md](examples/windsurf-integration.md) for detailed setup instructions.

**Quick Start:**
1. Open Windsurf Settings
2. Configure MCP server (Cmd+Shift+P: "Windsurf: Configure MCP Servers")
3. Add secure-vibe configuration
4. Use `@secure-vibe` in chat

### Claude Code

See [examples/claude-code-integration.md](examples/claude-code-integration.md) for detailed setup instructions.

**Quick Start:**
1. Install Secure Vibe MCP
2. Add MCP config: `claude mcp add secure-vibe python -m src.mcp_server`
3. Start Claude Code and use it

### OpenCode

See [examples/opencode-integration.md](examples/opencode-integration.md) for detailed setup instructions.

**Quick Start:**
1. Add MCP config to `opencode.json`
2. Start OpenCode
3. Use security scanning tools

### Kilo CLI

See [examples/kilo-integration.md](examples/kilo-integration.md) for detailed setup instructions.

**Quick Start:**
1. Add MCP config to `kilo.json`
2. Start Kilo CLI
3. Scan for vulnerabilities

---

## 🎨 Custom Rules

### Creating Custom Rules

Create a `custom-rules.yaml` file:

```yaml
rules:
  - id: CUSTOM-001
    name: "Custom API Key Pattern"
    category: secrets
    severity: critical
    description: "Detects custom API key format"
    languages:
      - javascript
      - python
    patterns:
      - "custom_api_key\\s*=\\s*['\"][a-zA-Z0-9]{32}['\"]"
    remediation: "Move API keys to environment variables"
    cvss_score: 7.5
    cwe_id: "CWE-798"
    references:
      - "https://example.com/security-guide"
```

### Loading Custom Rules

```python
from secure_vibe import SecurityScanner

scanner = SecurityScanner(
    custom_rules_path="./custom-rules.yaml"
)
```

### Rule Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique rule identifier |
| `name` | string | Yes | Human-readable name |
| `category` | string | Yes | Rule category |
| `severity` | string | Yes | low/medium/high/critical |
| `description` | string | Yes | What the rule detects |
| `languages` | array | Yes | Target languages |
| `patterns` | array | Yes | Regex patterns to match |
| `remediation` | string | Yes | How to fix |
| `cvss_score` | float | No | CVSS v3.1 score |
| `cwe_id` | string | No | Associated CWE |

---

## 📊 Output Formats

### JSON Output

```json
{
  "scan_summary": {
    "total_files": 15,
    "files_scanned": 15,
    "vulnerabilities_found": 3,
    "severity_counts": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0
    }
  },
  "vulnerabilities": [
    {
      "rule_id": "SEC-001",
      "rule_name": "Code Injection via eval()",
      "severity": "critical",
      "file": "app.js",
      "line": 42,
      "column": 10,
      "code_snippet": "eval(userInput)",
      "message": "Dangerous use of eval() with user input",
      "cvss_score": 9.8,
      "cwe_id": "CWE-94",
      "remediation": "Use JSON.parse() or a safe parsing library"
    }
  ]
}
```

### SARIF Output

Compatible with GitHub Advanced Security, VS Code, and other SARIF consumers.

### HTML Report

Interactive dashboard with:
- Vulnerability overview
- Detailed findings
- Remediation guidance
- Trend analysis

---

## 🧪 Testing

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run integration tests
pytest tests/integration/
```

### Sample Vulnerable Files

Test your installation with included samples:

```bash
# Scan sample vulnerable JavaScript
secure-vibe scan --file tests/sample_vulnerable/app.js

# Scan sample vulnerable Python
secure-vibe scan --file tests/sample_vulnerable/app.py

# Scan sample vulnerable Go
secure-vibe scan --file tests/sample_vulnerable/main.go

# Scan sample vulnerable Rust
secure-vibe scan --file tests/test_vulnerable_rust.rs
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/secure-vibe-mcp.git
cd secure-vibe-mcp

# Install development dependencies
pip install -e ".[dev]"

# Run pre-commit hooks
pre-commit install
pre-commit run --all-files

# Run tests
pytest

# Type checking
mypy src/

# Linting
ruff check src/
ruff format src/
```

### Areas for Contribution

- 🌐 New language support
- 📝 Additional security rules
- 🧪 Test coverage improvements
- 📚 Documentation enhancements
- 🎨 IDE plugin development
- 🔧 Auto-patch improvements

### Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## 📄 License

Secure Vibe MCP is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2025 Secure Vibe Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🆘 Support

- 📖 [Documentation](https://docs.secure-vibe.dev)
- 🐛 [Issue Tracker](https://github.com/yourusername/secure-vibe-mcp/issues)
- 💬 [Discussions](https://github.com/yourusername/secure-vibe-mcp/discussions)
- 📧 [Email Support](mailto:support@secure-vibe.dev)

---

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines
- [CWE](https://cwe.mitre.org/) for vulnerability classification
- [Model Context Protocol](https://modelcontextprotocol.io/) for the integration standard
- All [contributors](https://github.com/yourusername/secure-vibe-mcp/graphs/contributors) who have helped this project

---

<div align="center">

**[⬆ Back to Top](#-secure-vibe-mcp)**

Made with ❤️ by the Secure Vibe Team

</div>
