"""
Generic vulnerability detector for Secure Vibe.
Detects language-agnostic vulnerabilities like secrets and insecure patterns.
"""

import re
from typing import Any, Dict, List

from .base import BaseDetector


class GenericDetector(BaseDetector):
    """Detects language-agnostic vulnerabilities."""

    def __init__(self, rules: Dict[str, Any]):
        super().__init__(rules)
        self.language = "generic"
        self._init_patterns()

    def _init_patterns(self):
        """Initialize generic detection patterns."""
        self.patterns = {
            "private_key": {
                "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "Private key detected in source code",
                "remediation": "Remove private keys from source code and use environment variables or secret management",
                "auto_fixable": False,
            },
            "aws_access_key": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "AWS Access Key ID detected",
                "remediation": "Use environment variables or AWS IAM roles instead",
                "auto_fixable": True,
            },
            "aws_secret_key": {
                "pattern": r'["\']?[Aa][Ww][Ss][_-]?[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "AWS Secret Access Key detected",
                "remediation": "Use environment variables or AWS IAM roles instead",
                "auto_fixable": True,
            },
            "github_token": {
                "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "GitHub token detected",
                "remediation": "Use environment variables for GitHub tokens",
                "auto_fixable": True,
            },
            "slack_token": {
                "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "Slack token detected",
                "remediation": "Use environment variables for Slack tokens",
                "auto_fixable": True,
            },
            "generic_api_key": {
                "pattern": r'[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*["\'][a-zA-Z0-9_\-]{32,}["\']',
                "severity": "high",
                "cwe": "CWE-798",
                "description": "Generic API key detected",
                "remediation": "Use environment variables for API keys",
                "auto_fixable": True,
            },
            "generic_secret": {
                "pattern": r'[sS][eE][cC][rR][eE][tT]\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
                "severity": "high",
                "cwe": "CWE-798",
                "description": "Generic secret detected",
                "remediation": "Use environment variables for secrets",
                "auto_fixable": True,
            },
            "password_in_code": {
                "pattern": r'[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*["\'][^"\']+["\']',
                "severity": "high",
                "cwe": "CWE-798",
                "description": "Hardcoded password detected",
                "remediation": "Use environment variables or a secrets manager",
                "auto_fixable": True,
            },
            "jwt_pattern": {
                "pattern": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
                "severity": "high",
                "cwe": "CWE-798",
                "description": "JWT token pattern detected",
                "remediation": "Remove hardcoded JWT tokens from source code",
                "auto_fixable": True,
            },
            "basic_auth": {
                "pattern": r"https?://[^:]+:[^@]+@",
                "severity": "critical",
                "cwe": "CWE-798",
                "description": "Basic authentication credentials in URL",
                "remediation": "Use environment variables for credentials",
                "auto_fixable": True,
            },
            "insecure_url": {
                "pattern": r'["\']http://[^"\']+["\']',
                "severity": "medium",
                "cwe": "CWE-319",
                "description": "Insecure HTTP URL detected",
                "remediation": "Use HTTPS instead of HTTP",
                "auto_fixable": True,
            },
            "disable_ssl_verify": {
                "pattern": r'(?:verify[_-]?ssl|ssl[_-]?verify|verify)["\']?\s*[:=]\s*["\']?false["\']?',
                "severity": "high",
                "cwe": "CWE-295",
                "description": "SSL/TLS certificate verification disabled",
                "remediation": "Enable SSL certificate verification",
                "auto_fixable": True,
            },
            "todo_with_sensitive_info": {
                "pattern": r"(?:TODO|FIXME|XXX|HACK).*password|secret|key|token|credential",
                "severity": "low",
                "cwe": "CWE-546",
                "description": "TODO/FIXME comment may contain sensitive information",
                "remediation": "Remove sensitive information from comments",
                "auto_fixable": True,
            },
            "suspicious_comment": {
                "pattern": r"(?:TODO|FIXME|XXX|HACK).*(?:backdoor|bypass|disable|skip|ignore)",
                "severity": "low",
                "cwe": "CWE-546",
                "description": "Suspicious comment detected",
                "remediation": "Review and remove suspicious comments",
                "auto_fixable": False,
            },
            "ip_address": {
                "pattern": r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                "severity": "low",
                "cwe": "CWE-200",
                "description": "IP address detected in code",
                "remediation": "Review if IP address exposure is intentional",
                "auto_fixable": False,
            },
        }

    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect generic vulnerabilities."""
        vulnerabilities = []
        lines = code.split("\n")

        for vuln_type, config in self.patterns.items():
            for match in re.finditer(config["pattern"], code, re.IGNORECASE):
                line_num = code[: match.start()].count("\n") + 1
                col_num = match.start() - code.rfind("\n", 0, match.start())

                # Extract code context
                line_idx = line_num - 1
                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = match.group(0)

                # Mask sensitive data
                if vuln_type in ["private_key", "aws_secret_key", "github_token", "slack_token"]:
                    code_snippet = self._mask_sensitive(code_snippet)

                # Generate fixed code if auto-fixable
                fixed_code = None
                if config.get("auto_fixable"):
                    fixed_code = self._generate_fix(code_snippet, vuln_type)

                vuln = {
                    "rule_id": f"generic-{vuln_type}",
                    "severity": config["severity"],
                    "line": line_num,
                    "column": col_num,
                    "code": code_snippet,
                    "description": config["description"],
                    "cwe": config["cwe"],
                    "remediation": config["remediation"],
                    "auto_fixable": config.get("auto_fixable", False),
                    "fixed_code": fixed_code,
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _mask_sensitive(self, code_snippet: str) -> str:
        """Mask sensitive data in code snippet."""
        # Replace potential secret values with placeholder
        masked = re.sub(r'[=:]\s*["\'][^"\']{8,}["\']', '= "***REDACTED***"', code_snippet)
        return masked

    def _generate_fix(self, code_snippet: str, vuln_type: str) -> str:
        """Generate a fix for auto-fixable vulnerabilities."""
        if vuln_type == "aws_access_key":
            return "const awsAccessKey = process.env.AWS_ACCESS_KEY_ID;"
        elif vuln_type == "aws_secret_key":
            return "const awsSecretKey = process.env.AWS_SECRET_ACCESS_KEY;"
        elif vuln_type == "github_token":
            return "const githubToken = process.env.GITHUB_TOKEN;"
        elif vuln_type == "slack_token":
            return "const slackToken = process.env.SLACK_TOKEN;"
        elif vuln_type == "generic_api_key":
            return "const apiKey = process.env.API_KEY;"
        elif vuln_type == "generic_secret":
            return "const secret = process.env.SECRET;"
        elif vuln_type == "password_in_code":
            return "const password = process.env.PASSWORD;"
        elif vuln_type == "jwt_pattern":
            return "const token = process.env.JWT_TOKEN;"
        elif vuln_type == "basic_auth":
            return "// Remove credentials from URL, use proper authentication"
        elif vuln_type == "insecure_url":
            return code_snippet.replace("http://", "https://")
        elif vuln_type == "disable_ssl_verify":
            return code_snippet.replace("false", "true")
        elif vuln_type == "todo_with_sensitive_info":
            return "// TODO: [REMOVED SENSITIVE INFO]"
        return code_snippet
