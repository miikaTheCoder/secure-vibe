"""
Base detector class for Secure Vibe.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """Represents a security finding."""

    rule_id: str
    severity: Severity
    message: str
    line: int
    column: int
    code_snippet: str
    remediation: str
    cwe_id: str
    file_path: str
    extra_data: Optional[Dict[str, Any]] = None
    auto_fixable: bool = False
    fixed_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "code": self.code_snippet,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "cwe": self.cwe_id,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "extra_data": self.extra_data,
            "auto_fixable": self.auto_fixable,
            "fixed_code": self.fixed_code,
        }


class BaseDetector(ABC):
    """Base class for vulnerability detectors."""

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.rules = rules or {}
        self.language = "generic"
        self.findings: List[Finding] = []

    @abstractmethod
    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in code."""
        pass

    def scan(self, file_path: str, code: str) -> List[Finding]:
        """Scan code for vulnerabilities and return list of findings.

        This is the primary method that should be implemented by detectors.
        The detect() method is kept for backward compatibility.
        """
        self.findings = []
        results = self.detect(code, file_path)
        if results and not self.findings:
            # Convert old-style dict results to Finding objects
            for result in results:
                self.findings.append(self._dict_to_finding(result, file_path))
        return self.findings

    def _dict_to_finding(self, data: Dict[str, Any], file_path: str) -> Finding:
        """Convert dictionary to Finding object."""
        severity_str = data.get("severity", "medium")
        try:
            severity = Severity(severity_str.lower())
        except ValueError:
            severity = Severity.MEDIUM

        return Finding(
            rule_id=data.get("rule_id", "UNKNOWN"),
            severity=severity,
            message=data.get("description", ""),
            line=data.get("line", 1),
            column=data.get("column", 1),
            code_snippet=data.get("code", ""),
            remediation=data.get("remediation", ""),
            cwe_id=data.get("cwe", "CWE-UNKNOWN"),
            file_path=file_path,
            auto_fixable=data.get("auto_fixable", False),
            fixed_code=data.get("fixed_code"),
        )

    def add_finding(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        line: int,
        column: int,
        code_snippet: str,
        remediation: str,
        cwe_id: str,
        file_path: str,
        extra_data: Optional[Dict[str, Any]] = None,
        auto_fixable: bool = False,
        fixed_code: Optional[str] = None,
    ) -> None:
        """Add a new finding to the results."""
        finding = Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            line=line,
            column=column,
            code_snippet=code_snippet,
            remediation=remediation,
            cwe_id=cwe_id,
            file_path=file_path,
            extra_data=extra_data,
            auto_fixable=auto_fixable,
            fixed_code=fixed_code,
        )
        self.findings.append(finding)

    def get_snippet(self, code: str, line: int, context: int = 3) -> str:
        """Extract code snippet around a specific line."""
        lines = code.split("\n")
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        return "\n".join(lines[start:end])

    def get_rules_for_language(self) -> List[Dict[str, Any]]:
        """Get rules specific to this detector's language."""
        all_rules = self.rules.get("rules", [])
        return [r for r in all_rules if r.get("language") == self.language]
