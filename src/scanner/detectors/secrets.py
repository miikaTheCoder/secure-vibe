"""Generic secrets detector for detecting API keys, tokens, and credentials."""

import re
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecretFinding:
    """Represents a detected secret/credential."""

    rule_id: str
    name: str
    severity: str
    language: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    matched_code: str
    description: str
    cwe: str = None
    remediation: str = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "matched_code": self.matched_code,
            "description": self.description,
            "cwe": self.cwe,
            "remediation": self.remediation,
        }


class SecretsDetector:
    """Detects API keys, tokens, passwords, and other secrets in code."""

    # AWS patterns
    AWS_ACCESS_KEY_ID = re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)
    AWS_SECRET_ACCESS_KEY = re.compile(
        r'["\']?[Aa][Ww][Ss][_\-]?[Ss][Ee][Cc][Rr][Ee][Tt][_\-]?[Aa][Cc][Cc][Ee][Ss][Ss][_\-]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\']?[a-zA-Z0-9/+=]{40}["\']?',
        re.IGNORECASE,
    )

    # GitHub patterns
    GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.IGNORECASE)
    GITHUB_OAUTH = re.compile(r"[a-f0-9]{40}", re.IGNORECASE)

    # Slack patterns
    SLACK_TOKEN = re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", re.IGNORECASE)
    SLACK_WEBHOOK = re.compile(
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
        re.IGNORECASE,
    )

    # Generic API Key patterns
    GENERIC_API_KEY = re.compile(
        r'["\']?[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
        re.IGNORECASE,
    )

    # Private Key patterns
    RSA_PRIVATE_KEY = re.compile(
        r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
    )
    SSH_PRIVATE_KEY = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE)

    # JWT Token pattern
    JWT_TOKEN = re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*")

    # Database connection strings
    DB_CONNECTION_STRING = re.compile(
        r"(mongodb(\+srv)?|mysql|postgresql|postgres|redis|mssql|oracle)://[^:]+:[^@]+@[^/\s]+",
        re.IGNORECASE,
    )

    # Password patterns
    PASSWORD_IN_CODE = re.compile(
        r'["\']?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]["\']?\s*[:=]\s*["\'][^"\']{4,}["\']', re.IGNORECASE
    )
    SECRET_IN_CODE = re.compile(
        r'["\']?[Ss][Ee][Cc][Rr][Ee][Tt]["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE
    )

    # Google API Key
    GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_-]{35}", re.IGNORECASE)

    # Firebase
    FIREBASE_API_KEY = re.compile(
        r'["\']?[Ff][Ii][Rr][Ee][Bb][Aa][Ss][Ee][_\-]?[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{39}["\']?',
        re.IGNORECASE,
    )

    # Heroku API Key
    HEROKU_API_KEY = re.compile(
        r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        re.IGNORECASE,
    )

    # Stripe
    STRIPE_API_KEY = re.compile(r"[sr]k_live_[0-9a-zA-Z]{24}", re.IGNORECASE)
    STRIPE_PUBLISHABLE_KEY = re.compile(r"pk_live_[0-9a-zA-Z]{24,34}", re.IGNORECASE)

    # Twilio
    TWILIO_API_KEY = re.compile(r"SK[0-9a-fA-F]{32}", re.IGNORECASE)

    # Mailgun
    MAILGUN_API_KEY = re.compile(r"key-[0-9a-zA-Z]{32}", re.IGNORECASE)

    # SendGrid
    SENDGRID_API_KEY = re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", re.IGNORECASE)

    # Azure
    AZURE_STORAGE_KEY = re.compile(r"AccountKey=[a-zA-Z0-9+/=]{88}", re.IGNORECASE)

    # Generic secret patterns
    GENERIC_SECRET = re.compile(
        r'["\']?[Ss][Ee][Cc][Rr][Ee][Tt][_\-]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
        re.IGNORECASE,
    )

    # Bearer token
    BEARER_TOKEN = re.compile(r"[Bb]earer\s+[a-zA-Z0-9_\-\.=]{20,}", re.IGNORECASE)

    # Basic Auth
    BASIC_AUTH = re.compile(r"[Bb]asic\s+[a-zA-Z0-9+/=]{20,}", re.IGNORECASE)

    # URL with embedded credentials
    URL_WITH_CREDS = re.compile(r"(https?|ftp)://[^:]+:[^@]+@[^\s/]+", re.IGNORECASE)

    # NPM Token
    NPM_TOKEN = re.compile(r"npm_[a-zA-Z0-9]{36}", re.IGNORECASE)

    # PyPI Token
    PYPI_TOKEN = re.compile(r"pypi-[a-zA-Z0-9_-]{37}", re.IGNORECASE)

    # Docker registry password
    DOCKER_PASSWORD = re.compile(
        r'["\']?[Dd][Oo][Cc][Kk][Ee][Rr][_\-]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
        re.IGNORECASE,
    )

    # Private key file paths
    PRIVATE_KEY_FILE = re.compile(r'[\'"](.*\.(pem|key|pkcs12|pfx|p12))[\'"]', re.IGNORECASE)

    # Rules definition for structured output
    SECRET_RULES = {
        "aws-access-key": {
            "name": "AWS Access Key ID",
            "severity": "critical",
            "pattern": AWS_ACCESS_KEY_ID,
            "cwe": "CWE-798",
            "remediation": "Remove hardcoded credentials and use environment variables or AWS IAM roles instead",
        },
        "aws-secret-key": {
            "name": "AWS Secret Access Key",
            "severity": "critical",
            "pattern": AWS_SECRET_ACCESS_KEY,
            "cwe": "CWE-798",
            "remediation": "Remove hardcoded credentials and use environment variables or AWS IAM roles instead",
        },
        "github-token": {
            "name": "GitHub Token",
            "severity": "critical",
            "pattern": GITHUB_TOKEN,
            "cwe": "CWE-798",
            "remediation": "Use GitHub Actions secrets or environment variables for tokens",
        },
        "slack-token": {
            "name": "Slack Token",
            "severity": "high",
            "pattern": SLACK_TOKEN,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Slack tokens and rotate exposed tokens immediately",
        },
        "slack-webhook": {
            "name": "Slack Webhook URL",
            "severity": "medium",
            "pattern": SLACK_WEBHOOK,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for webhook URLs",
        },
        "api-key": {
            "name": "Generic API Key",
            "severity": "high",
            "pattern": GENERIC_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or a secrets manager for API keys",
        },
        "rsa-private-key": {
            "name": "RSA/SSH Private Key",
            "severity": "critical",
            "pattern": RSA_PRIVATE_KEY,
            "cwe": "CWE-798",
            "remediation": "Remove private keys from code and use proper key management solutions",
        },
        "ssh-private-key": {
            "name": "SSH Private Key",
            "severity": "critical",
            "pattern": SSH_PRIVATE_KEY,
            "cwe": "CWE-798",
            "remediation": "Remove private keys from code and use SSH agent or key management solutions",
        },
        "jwt-token": {
            "name": "JWT Token",
            "severity": "medium",
            "pattern": JWT_TOKEN,
            "cwe": "CWE-798",
            "remediation": "JWT tokens should not be hardcoded; use secure token storage",
        },
        "db-connection-string": {
            "name": "Database Connection String with Credentials",
            "severity": "critical",
            "pattern": DB_CONNECTION_STRING,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or secrets management for database credentials",
        },
        "password-in-code": {
            "name": "Hardcoded Password",
            "severity": "high",
            "pattern": PASSWORD_IN_CODE,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or a secrets manager for passwords",
        },
        "secret-in-code": {
            "name": "Hardcoded Secret",
            "severity": "high",
            "pattern": SECRET_IN_CODE,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or a secrets manager for secrets",
        },
        "google-api-key": {
            "name": "Google API Key",
            "severity": "high",
            "pattern": GOOGLE_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for API keys and restrict key usage in Google Cloud Console",
        },
        "firebase-api-key": {
            "name": "Firebase API Key",
            "severity": "high",
            "pattern": FIREBASE_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Firebase configuration",
        },
        "heroku-api-key": {
            "name": "Heroku API Key",
            "severity": "critical",
            "pattern": HEROKU_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use Heroku config vars instead of hardcoded credentials",
        },
        "stripe-api-key": {
            "name": "Stripe API Key",
            "severity": "critical",
            "pattern": STRIPE_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Stripe keys and rotate exposed keys immediately",
        },
        "stripe-publishable-key": {
            "name": "Stripe Publishable Key",
            "severity": "medium",
            "pattern": STRIPE_PUBLISHABLE_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Stripe configuration",
        },
        "twilio-api-key": {
            "name": "Twilio API Key",
            "severity": "high",
            "pattern": TWILIO_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Twilio credentials",
        },
        "mailgun-api-key": {
            "name": "Mailgun API Key",
            "severity": "high",
            "pattern": MAILGUN_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for Mailgun configuration",
        },
        "sendgrid-api-key": {
            "name": "SendGrid API Key",
            "severity": "critical",
            "pattern": SENDGRID_API_KEY,
            "cwe": "CWE-798",
            "remediation": "Use environment variables for SendGrid API keys and rotate exposed keys immediately",
        },
        "azure-storage-key": {
            "name": "Azure Storage Key",
            "severity": "critical",
            "pattern": AZURE_STORAGE_KEY,
            "cwe": "CWE-798",
            "remediation": "Use Azure Key Vault or managed identities instead of hardcoded credentials",
        },
        "generic-secret": {
            "name": "Generic Secret Key",
            "severity": "high",
            "pattern": GENERIC_SECRET,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or a secrets manager for secrets",
        },
        "bearer-token": {
            "name": "Bearer Token",
            "severity": "high",
            "pattern": BEARER_TOKEN,
            "cwe": "CWE-798",
            "remediation": "Use secure token storage and never hardcode bearer tokens",
        },
        "basic-auth": {
            "name": "HTTP Basic Authentication",
            "severity": "high",
            "pattern": BASIC_AUTH,
            "cwe": "CWE-798",
            "remediation": "Use secure authentication methods instead of Basic Auth in code",
        },
        "url-with-creds": {
            "name": "URL with Embedded Credentials",
            "severity": "critical",
            "pattern": URL_WITH_CREDS,
            "cwe": "CWE-798",
            "remediation": "Remove credentials from URLs and use environment variables",
        },
        "npm-token": {
            "name": "NPM Token",
            "severity": "high",
            "pattern": NPM_TOKEN,
            "cwe": "CWE-798",
            "remediation": "Use .npmrc file with proper permissions or environment variables",
        },
        "pypi-token": {
            "name": "PyPI Token",
            "severity": "high",
            "pattern": PYPI_TOKEN,
            "cwe": "CWE-798",
            "remediation": "Use environment variables or repository secrets for PyPI tokens",
        },
        "docker-password": {
            "name": "Docker Password",
            "severity": "high",
            "pattern": DOCKER_PASSWORD,
            "cwe": "CWE-798",
            "remediation": "Use Docker credential helpers or environment variables",
        },
        "private-key-file": {
            "name": "Reference to Private Key File",
            "severity": "medium",
            "pattern": PRIVATE_KEY_FILE,
            "cwe": "CWE-798",
            "remediation": "Ensure private key files are not committed to version control",
        },
    }

    def __init__(self):
        """Initialize the secrets detector."""
        pass

    def scan(self, code: str, file_path: str = "<inline>") -> list[SecretFinding]:
        """Scan code for secrets and credentials.

        Args:
            code: Source code to scan
            file_path: Path to the file being scanned

        Returns:
            List of SecretFinding objects
        """
        findings = []
        lines = code.split("\n")

        for rule_id, rule_config in self.SECRET_RULES.items():
            pattern = rule_config["pattern"]

            for line_num, line in enumerate(lines, 1):
                for match in pattern.finditer(line):
                    # Skip matches that look like variable names or placeholders
                    matched_text = match.group(0)
                    if self._is_likely_placeholder(matched_text):
                        continue

                    finding = SecretFinding(
                        rule_id=f"secret-{rule_id}",
                        name=rule_config["name"],
                        severity=rule_config["severity"],
                        language="generic",
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        matched_code=matched_text,
                        description=f"Potential secret detected: {rule_config['name']}",
                        cwe=rule_config.get("cwe"),
                        remediation=rule_config.get("remediation"),
                    )
                    findings.append(finding)

        return findings

    def _is_likely_placeholder(self, text: str) -> bool:
        """Check if matched text is likely a placeholder or variable name.

        Args:
            text: The matched text

        Returns:
            True if likely a placeholder
        """
        # Common placeholder patterns
        placeholders = [
            r"\$\w+",  # $VAR, ${VAR}
            r"%\w+%",  # %VAR%
            r"\{\{\s*\w+\s*\}\}",  # {{ VAR }}
            r"\{\w+\}",  # {VAR}
            r"\$\{\w+\}",  # ${VAR}
            r"process\.env\.\w+",  # process.env.VAR
            r"os\.getenv\([^)]+\)",  # os.getenv('VAR')
            r"environ\.get\([^)]+\)",  # environ.get('VAR')
            r'getenv\s*\(\s*["\']',  # getenv('VAR')
        ]

        for pattern in placeholders:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # Check for obvious placeholder values
        placeholder_values = [
            "your-key-here",
            "your_token_here",
            "placeholder",
            "example",
            "test",
            "demo",
            "sample",
            "changeme",
            "password",
            "secret",
            "key",
            "token",
            "YOUR_",
            "MY_",
            "XXX",
            "***",
            "xxx",
        ]

        text_lower = text.lower()
        for placeholder in placeholder_values:
            if placeholder in text_lower:
                return True

        return False

    def scan_line(
        self, line: str, file_path: str = "<inline>", line_number: int = 1
    ) -> list[SecretFinding]:
        """Scan a single line for secrets.

        Args:
            line: Single line of code
            file_path: Path to the file
            line_number: Line number in the file

        Returns:
            List of SecretFinding objects
        """
        return self.scan(line, file_path)
