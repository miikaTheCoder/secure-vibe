"""Main scanning orchestrator for security vulnerability detection."""

import hashlib
import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from src.scanner.rules import RuleLoader
from src.scanner.detectors.secrets import SecretsDetector, SecretFinding

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""

    id: str
    rule_id: str
    severity: str
    language: str
    file: str
    line: int
    column: int
    code: str
    description: str
    cwe: str
    remediation: str
    auto_fixable: bool
    fixed_code: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "language": self.language,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "description": self.description,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "auto_fixable": self.auto_fixable,
            "fixed_code": self.fixed_code,
        }


class ScanResult:
    """Represents a single vulnerability finding (backward compatible with new engine)."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        language: str,
        file_path: str,
        line_number: int,
        column_start: int,
        column_end: int,
        matched_code: str,
        description: str,
        cwe: Optional[str] = None,
        remediation: Optional[str] = None,
        auto_fixable: bool = False,
        fix_template: Optional[str] = None,
    ):
        self.id = str(uuid.uuid4())
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.language = language
        self.file_path = file_path
        self.line_number = line_number
        self.column_start = column_start
        self.column_end = column_end
        self.matched_code = matched_code
        self.description = description
        self.cwe = cwe
        self.remediation = remediation
        self.auto_fixable = auto_fixable
        self.fix_template = fix_template

        # Backward compatibility attributes
        self.file = file_path
        self.line = line_number
        self.column = column_start
        self.code = matched_code
        self.fixed_code = fix_template

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "language": self.language,
            "file_path": self.file_path,
            "file": self.file,
            "line_number": self.line_number,
            "line": self.line,
            "column_start": self.column_start,
            "column": self.column,
            "column_end": self.column_end,
            "matched_code": self.matched_code,
            "code": self.code,
            "description": self.description,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "auto_fixable": self.auto_fixable,
            "fix_template": self.fix_template,
            "fixed_code": self.fixed_code,
        }

    def get_hash(self) -> str:
        """Generate unique hash for deduplication."""
        content = f"{self.rule_id}:{self.file_path}:{self.line_number}:{self.matched_code}"
        return hashlib.md5(content.encode()).hexdigest()


class ScanEngine:
    """Main scanning orchestrator for security vulnerability detection."""

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    SKIP_DIRS = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".pytest_cache",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "target",
        "vendor",
        ".next",
        "out",
        "coverage",
    }

    SKIP_EXTENSIONS = {".min.js", ".min.css", ".map", ".lock", ".sum"}

    LANGUAGE_MAP = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".py": "python",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".rs": "rust",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".sql": "sql",
    }

    SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".rb", ".php"}

    def __init__(self, rules_path: Optional[str] = None, max_workers: Optional[int] = None):
        """Initialize the scanner engine.

        Args:
            rules_path: Path to rules YAML file. If None, uses default.
            max_workers: Maximum number of parallel workers. If None, uses CPU count.
        """
        self.rules_path = rules_path or "./src/scanner/rules/rules.yaml"
        self.rule_loader = RuleLoader(rules_path)
        self.rules = self.rule_loader.load_rules()
        self.secrets_detector = SecretsDetector()
        self.max_workers = max_workers or os.cpu_count() or 4
        self.vuln_counter = 0

    def _get_language(self, file_path: str) -> Optional[str]:
        """Determine language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.LANGUAGE_MAP.get(ext)

    def _is_binary(self, file_path: str) -> bool:
        """Check if file is binary."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
                if not chunk:
                    return False
                return b"\x00" in chunk
        except Exception:
            return True

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped."""
        path = Path(file_path)

        # Skip binary files
        if self._is_binary(file_path):
            return True

        # Skip certain extensions
        if path.suffix.lower() in self.SKIP_EXTENSIONS:
            return True

        # Skip files in skip directories
        for part in path.parts:
            if part in self.SKIP_DIRS:
                return True

        # Skip hidden files
        if path.name.startswith("."):
            return True

        return False

    def _should_skip_directory(self, dir_path: str) -> bool:
        """Check if directory should be skipped."""
        path = Path(dir_path)
        for part in path.parts:
            if part in self.SKIP_DIRS:
                return True
        return False

    def _severity_meets_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets or exceeds threshold."""
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(threshold, 0)

    def _deduplicate_results(self, results: list[ScanResult]) -> list[ScanResult]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        for result in results:
            result_hash = result.get_hash()
            if result_hash not in seen:
                seen.add(result_hash)
                unique.append(result)
        return unique

    def _read_file_with_encoding(self, file_path: str) -> Optional[tuple[str, str]]:
        """Read file trying multiple encodings."""
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252", "iso-8859-1"]

        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    return f.read(), encoding
            except (UnicodeDecodeError, LookupError):
                continue

        return None

    def _match_pattern(self, code: str, pattern: str, language: str) -> list[dict]:
        """Match a pattern against code and return match details."""
        matches = []

        # Handle simple wildcard patterns
        if "$X" in pattern or "$Y" in pattern:
            # Convert pattern to regex
            regex_pattern = pattern
            regex_pattern = re.escape(regex_pattern)
            regex_pattern = regex_pattern.replace(r"\$X", r"([^\s()]+)")
            regex_pattern = regex_pattern.replace(r"\$Y", r"([^\s()]+)")
            regex_pattern = regex_pattern.replace(r"\"", r'"')
            regex_pattern = regex_pattern.replace(r"\'", r"'")

            try:
                compiled_pattern = re.compile(regex_pattern, re.MULTILINE)
            except re.error:
                return matches
        else:
            try:
                compiled_pattern = re.compile(re.escape(pattern), re.MULTILINE)
            except re.error:
                return matches

        lines = code.split("\n")
        for line_num, line in enumerate(lines, 1):
            for match in compiled_pattern.finditer(line):
                matches.append(
                    {
                        "line_number": line_num,
                        "column_start": match.start(),
                        "column_end": match.end(),
                        "matched_code": match.group(0),
                    }
                )

        return matches

    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID."""
        self.vuln_counter += 1
        return f"VULN-{self.vuln_counter:04d}"

    def _apply_rules(
        self, code: str, language: str, file_path: str, severity_threshold: str
    ) -> list[ScanResult]:
        """Apply rules for a specific language."""
        results = []

        for rule in self.rules:
            if rule.get("language") != language:
                continue

            if not self._severity_meets_threshold(rule.get("severity", "low"), severity_threshold):
                continue

            for pattern in rule.get("patterns", []):
                matches = self._match_pattern(code, pattern, language)

                for match in matches:
                    result = ScanResult(
                        rule_id=rule["id"],
                        name=rule["name"],
                        severity=rule["severity"],
                        language=language,
                        file_path=file_path,
                        line_number=match["line_number"],
                        column_start=match["column_start"],
                        column_end=match["column_end"],
                        matched_code=match["matched_code"],
                        description=rule.get("description", ""),
                        cwe=rule.get("cwe"),
                        remediation=rule.get("remediation"),
                        auto_fixable=rule.get("auto_fixable", False),
                        fix_template=rule.get("fix_template"),
                    )
                    results.append(result)

        return results

    def scan_file(self, file_path: str, severity_threshold: str = "medium") -> list[ScanResult]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan
            severity_threshold: Minimum severity level to report (critical, high, medium, low, info)

        Returns:
            List of ScanResult objects
        """
        file_path = os.path.abspath(file_path)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if self._should_skip_file(file_path):
            return []

        # Read file with encoding handling
        result = self._read_file_with_encoding(file_path)
        if result is None:
            return []

        code, _ = result
        results = []

        # Scan with secrets detector (runs on all files)
        secrets_results = self.secrets_detector.scan(code, file_path)
        for secret_result in secrets_results:
            if self._severity_meets_threshold(secret_result.severity, severity_threshold):
                results.append(secret_result)

        # Route to language-specific detector
        language = self._get_language(file_path)
        if language:
            rule_results = self._apply_rules(code, language, file_path, severity_threshold)
            results.extend(rule_results)

        return self._deduplicate_results(results)

    def scan_directory(
        self, directory: str, severity_threshold: str = "medium"
    ) -> list[ScanResult]:
        """Scan all files in a directory recursively.

        Args:
            directory: Path to the directory to scan
            severity_threshold: Minimum severity level to report

        Returns:
            List of ScanResult objects
        """
        directory = os.path.abspath(directory)

        if not os.path.isdir(directory):
            raise NotADirectoryError(f"Not a directory: {directory}")

        # Collect all files to scan
        files_to_scan = []
        for root, dirs, files in os.walk(directory):
            # Skip directories
            dirs[:] = [d for d in dirs if not self._should_skip_directory(os.path.join(root, d))]

            for filename in files:
                file_path = os.path.join(root, filename)
                if not self._should_skip_file(file_path):
                    files_to_scan.append(file_path)

        # Parallel scanning
        all_results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.scan_file, fp, severity_threshold): fp for fp in files_to_scan
            }

            for future in future_to_file:
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    # Log error but continue scanning other files
                    logger.error(f"Error scanning {future_to_file[future]}: {e}")

        return self._deduplicate_results(all_results)

    def scan_code(
        self, code: str, language: str, severity_threshold: str = "medium"
    ) -> list[ScanResult]:
        """Scan code snippet for vulnerabilities.

        Args:
            code: Source code to scan
            language: Programming language of the code
            severity_threshold: Minimum severity level to report

        Returns:
            List of ScanResult objects
        """
        results = []
        file_path = "<inline>"

        # Scan with secrets detector
        secrets_results = self.secrets_detector.scan(code, file_path)
        for secret_result in secrets_results:
            if self._severity_meets_threshold(secret_result.severity, severity_threshold):
                results.append(secret_result)

        # Apply language-specific rules
        rule_results = self._apply_rules(code, language, file_path, severity_threshold)
        results.extend(rule_results)

        return self._deduplicate_results(results)

    def get_rules(self) -> list[dict[str, Any]]:
        """Get all security rules."""
        formatted_rules = []
        for rule in self.rules:
            formatted_rules.append(
                {
                    "id": rule.get("id", "unknown"),
                    "name": rule.get("name", "Unnamed Rule"),
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "medium"),
                    "language": rule.get("language", "any"),
                    "enabled": rule.get("enabled", True),
                    "cwe": rule.get("cwe", "N/A"),
                }
            )
        return formatted_rules

    def configure_rules(self, config: dict[str, Any]) -> None:
        """Configure rule settings."""
        # Update enabled rules
        enabled_rules = config.get("enabled_rules", ["*"])
        if enabled_rules != ["*"]:
            for rule in self.rules:
                rule_id = rule.get("id", "")
                rule["enabled"] = rule_id in enabled_rules or "*" in enabled_rules

        # Update custom rules
        custom_rules = config.get("custom_rules", {})
        if custom_rules:
            for rule_id, rule_config in custom_rules.items():
                rule_config["id"] = rule_id
                # Check if rule exists
                existing = next((r for r in self.rules if r.get("id") == rule_id), None)
                if existing:
                    existing.update(rule_config)
                else:
                    self.rules.append(rule_config)

        logger.info("Rules configured successfully")

    def update_rules(self, rules_path: str, updates: dict[str, Any]) -> None:
        """Update security rules."""
        try:
            # Deep merge updates into current rules
            for rule_update in updates.get("rules", []):
                rule_id = rule_update.get("id")
                existing = next((r for r in self.rules if r.get("id") == rule_id), None)
                if existing:
                    existing.update(rule_update)
                else:
                    self.rules.append(rule_update)

            # Save updated rules
            with open(rules_path, "w") as f:
                yaml.dump({"rules": self.rules}, f, default_flow_style=False)

            logger.info(f"Rules updated at {rules_path}")
        except Exception as e:
            logger.error(f"Error updating rules: {e}")
            raise
