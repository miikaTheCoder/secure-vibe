"""Utility functions for the MCP server."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure logging for the MCP server."""
    logger = logging.getLogger("secure_vibe")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def generate_scan_id() -> str:
    """Generate a unique scan ID based on timestamp."""
    timestamp = datetime.utcnow().isoformat()
    return hashlib.sha256(timestamp.encode()).hexdigest()[:16]


def format_timestamp() -> str:
    """Return ISO format timestamp."""
    return datetime.utcnow().isoformat() + "Z"


def read_file_safe(file_path: str | Path, encoding: str = "utf-8") -> str | None:
    """Safely read file contents with error handling."""
    try:
        path = Path(file_path)
        if not path.exists():
            return None
        if not path.is_file():
            return None
        return path.read_text(encoding=encoding)
    except (IOError, UnicodeDecodeError, PermissionError):
        return None


def get_file_extension(file_path: str | Path) -> str:
    """Extract file extension from path."""
    return Path(file_path).suffix.lower()


def detect_language(file_path: str | Path) -> str | None:
    """Detect programming language from file extension."""
    ext = get_file_extension(file_path)
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".java": "java",
        ".cpp": "cpp",
        ".c": "c",
        ".h": "c",
        ".hpp": "cpp",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
    }
    return lang_map.get(ext)


def truncate_code_snippet(code: str, max_lines: int = 10) -> str:
    """Truncate code snippet to max lines."""
    lines = code.splitlines()
    if len(lines) <= max_lines:
        return code
    return "\n".join(lines[:max_lines]) + "\n..."


def format_vulnerability_result(
    vuln_id: str,
    severity: str,
    file_path: str,
    line: int,
    code_snippet: str,
    description: str,
    cwe: str,
    remediation: str,
    auto_fixable: bool = False,
    confidence: str = "medium",
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Format a single vulnerability result."""
    return {
        "id": vuln_id,
        "severity": severity,
        "file": file_path,
        "line": line,
        "code_snippet": truncate_code_snippet(code_snippet),
        "description": description,
        "cwe": cwe,
        "remediation": remediation,
        "auto_fixable": auto_fixable,
        "confidence": confidence,
        "rule_id": rule_id,
    }


def format_scan_result(
    scan_id: str,
    vulnerabilities: list[dict[str, Any]],
    scanned_files: int,
    duration_ms: float,
) -> dict[str, Any]:
    """Format complete scan result."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "scan_id": scan_id,
        "timestamp": format_timestamp(),
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "scanned_files": scanned_files,
            "duration_ms": round(duration_ms, 2),
        },
        "vulnerabilities": vulnerabilities,
    }


def severity_to_int(severity: str) -> int:
    """Convert severity string to numeric priority."""
    mapping = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return mapping.get(severity.lower(), 0)


def filter_by_severity(
    vulnerabilities: list[dict[str, Any]], threshold: str
) -> list[dict[str, Any]]:
    """Filter vulnerabilities by minimum severity threshold."""
    threshold_level = severity_to_int(threshold)
    return [
        v for v in vulnerabilities if severity_to_int(v.get("severity", "info")) >= threshold_level
    ]


def to_json(obj: Any, indent: int = 2) -> str:
    """Convert object to JSON string."""
    return json.dumps(obj, indent=indent, default=str)


def from_json(json_str: str) -> Any:
    """Parse JSON string to object."""
    return json.loads(json_str)


def load_config(config_path: str | Path) -> dict:
    """Load configuration from YAML or JSON file."""
    path = Path(config_path)
    if not path.exists():
        return {}
    content = read_file_safe(path)
    if content is None:
        return {}
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content) or {}
    elif path.suffix == ".json":
        return json.loads(content)
    return {}


def save_config(config: dict, config_path: str | Path) -> None:
    """Save configuration to file."""
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix in (".yaml", ".yml"):
        path.write_text(yaml.dump(config, default_flow_style=False))
    elif path.suffix == ".json":
        path.write_text(json.dumps(config, indent=2))


def int_to_severity(level: int) -> str:
    """Convert numeric level to severity string."""
    levels = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
    return levels.get(level, "info")


def get_file_extension_from_language(language: str) -> str:
    """Get file extension for a language."""
    ext_map = {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "go": ".go",
        "java": ".java",
    }
    return ext_map.get(language, ".txt")


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string to max length with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[: max_length - 3] + "..."


def sanitize_code_snippet(code: str, max_lines: int = 5) -> str:
    """Sanitize and truncate code snippet for display."""
    lines = code.split("\n")
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append("...")
    return "\n".join(lines)


def get_timestamp() -> str:
    """Get current ISO timestamp."""
    return format_timestamp()


def merge_dicts(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result
