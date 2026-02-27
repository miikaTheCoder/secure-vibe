"""
Secure Vibe MCP Server - FastMCP implementation
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from src.scanner.engine import ScanEngine
from src.patcher.engine import PatchingEngine
from src.utils.helpers import (
    format_scan_result as format_scan_result_fn,
    format_vulnerability_result as format_vuln_result,
    generate_scan_id,
    filter_by_severity,
    detect_language,
    read_file_safe,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("secure-vibe")

# Initialize engines
scan_engine = ScanEngine()
patch_engine = PatchingEngine()

# In-memory storage for scan results
scan_results: dict[str, dict[str, Any]] = {}

# Rule configuration
rule_config: dict[str, Any] = {
    "enabled_rules": ["*"],
    "severity_threshold": "medium",
    "custom_rules": {},
}


@mcp.tool()
async def scan_file(file_path: str, severity_threshold: str = "medium") -> dict[str, Any]:
    """
    Scan a single file for security vulnerabilities.

    Args:
        file_path: Absolute path to the file to scan
        severity_threshold: Minimum severity level to report (low, medium, high, critical)

    Returns:
        Structured scan result with vulnerabilities list
    """
    logger.info(f"Scanning file: {file_path} with threshold: {severity_threshold}")

    try:
        start_time = time.time()
        scan_id = generate_scan_id()

        # Check if file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return {
                "scan_id": scan_id,
                "timestamp": time.time(),
                "error": f"File not found: {file_path}",
                "summary": {
                    "total_vulnerabilities": 0,
                    "severity_counts": {},
                    "scanned_files": 0,
                    "duration_ms": 0,
                },
                "vulnerabilities": [],
            }

        # Perform scan using existing engine
        raw_result = scan_engine.scan_file(
            str(file_path_obj), severity_threshold=severity_threshold
        )
        duration_ms = (time.time() - start_time) * 1000

        # Format vulnerabilities
        vulnerabilities = []
        for i, vuln in enumerate(raw_result):
            vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else vuln
            formatted_vuln = format_vuln_result(
                vuln_id=vuln_dict.get("id", f"VULN-{i}"),
                severity=vuln_dict.get("severity", "medium"),
                file_path=vuln_dict.get("file", file_path),
                line=vuln_dict.get("line", 0),
                code_snippet=vuln_dict.get("code", ""),
                description=vuln_dict.get("description", ""),
                cwe=vuln_dict.get("cwe", "N/A"),
                remediation=vuln_dict.get("remediation", ""),
                auto_fixable=vuln_dict.get("auto_fixable", False),
                confidence=vuln_dict.get("confidence", "medium"),
                rule_id=vuln_dict.get("rule_id"),
            )
            vulnerabilities.append(formatted_vuln)

        # Filter by severity
        vulnerabilities = filter_by_severity(vulnerabilities, severity_threshold)

        # Build final result
        result = format_scan_result_fn(scan_id, vulnerabilities, 1, duration_ms)

        # Store for later retrieval
        scan_results[scan_id] = result

        logger.info(f"Scan completed: {scan_id} - Found {len(vulnerabilities)} vulnerabilities")
        return result

    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return {
            "scan_id": generate_scan_id(),
            "timestamp": time.time(),
            "error": str(e),
            "summary": {
                "total_vulnerabilities": 0,
                "severity_counts": {},
                "scanned_files": 0,
                "duration_ms": 0,
            },
            "vulnerabilities": [],
        }


@mcp.tool()
async def scan_directory(directory: str, severity_threshold: str = "medium") -> dict[str, Any]:
    """
    Scan an entire directory recursively for security vulnerabilities.

    Args:
        directory: Absolute path to the directory to scan
        severity_threshold: Minimum severity level to report (low, medium, high, critical)

    Returns:
        Structured scan result with vulnerabilities list
    """
    logger.info(f"Scanning directory: {directory} with threshold: {severity_threshold}")

    try:
        start_time = time.time()
        scan_id = generate_scan_id()

        # Check if directory exists
        dir_path = Path(directory)
        if not dir_path.exists():
            return {
                "scan_id": scan_id,
                "timestamp": time.time(),
                "error": f"Directory not found: {directory}",
                "summary": {
                    "total_vulnerabilities": 0,
                    "severity_counts": {},
                    "scanned_files": 0,
                    "duration_ms": 0,
                },
                "vulnerabilities": [],
            }

        # Perform scan using existing engine
        raw_result = scan_engine.scan_directory(
            str(dir_path), severity_threshold=severity_threshold
        )
        duration_ms = (time.time() - start_time) * 1000

        # Format vulnerabilities
        vulnerabilities = []
        for i, vuln in enumerate(raw_result):
            vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else vuln
            formatted_vuln = format_vuln_result(
                vuln_id=vuln_dict.get("id", f"VULN-{i}"),
                severity=vuln_dict.get("severity", "medium"),
                file_path=vuln_dict.get("file", ""),
                line=vuln_dict.get("line", 0),
                code_snippet=vuln_dict.get("code", ""),
                description=vuln_dict.get("description", ""),
                cwe=vuln_dict.get("cwe", "N/A"),
                remediation=vuln_dict.get("remediation", ""),
                auto_fixable=vuln_dict.get("auto_fixable", False),
                confidence=vuln_dict.get("confidence", "medium"),
                rule_id=vuln_dict.get("rule_id"),
            )
            vulnerabilities.append(formatted_vuln)

        # Filter by severity
        vulnerabilities = filter_by_severity(vulnerabilities, severity_threshold)

        # Count scanned files (estimate based on unique file paths)
        scanned_files = len(set(vuln.file for vuln in raw_result)) if raw_result else 0

        # Build final result
        result = format_scan_result_fn(scan_id, vulnerabilities, scanned_files, duration_ms)

        # Store for later retrieval
        scan_results[scan_id] = result

        logger.info(
            f"Directory scan completed: {scan_id} - Found {len(vulnerabilities)} vulnerabilities in {scanned_files} files"
        )
        return result

    except Exception as e:
        logger.error(f"Error scanning directory: {e}")
        return {
            "scan_id": generate_scan_id(),
            "timestamp": time.time(),
            "error": str(e),
            "summary": {
                "total_vulnerabilities": 0,
                "severity_counts": {},
                "scanned_files": 0,
                "duration_ms": 0,
            },
            "vulnerabilities": [],
        }


@mcp.tool()
async def scan_code(
    code: str, language: str = "auto", severity_threshold: str = "medium"
) -> dict[str, Any]:
    """
    Scan a code snippet inline for security vulnerabilities.

    Args:
        code: Code snippet to scan
        language: Programming language (auto, python, javascript, go)
        severity_threshold: Minimum severity level to report (low, medium, high, critical)

    Returns:
        Structured scan result with vulnerabilities list
    """
    logger.info(f"Scanning code snippet with language: {language}")

    try:
        start_time = time.time()
        scan_id = generate_scan_id()

        # Detect language if auto
        if language == "auto":
            # Try to detect from code patterns
            if "def " in code or "import " in code:
                language = "python"
            elif "function " in code or "const " in code or "let " in code:
                language = "javascript"
            elif "func " in code:
                language = "go"
            else:
                language = "generic"

        # Perform scan using existing engine
        raw_result = scan_engine.scan_code(
            code, language=language, severity_threshold=severity_threshold
        )
        duration_ms = (time.time() - start_time) * 1000

        # Format vulnerabilities
        vulnerabilities = []
        for i, vuln in enumerate(raw_result):
            vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else vuln
            formatted_vuln = format_vuln_result(
                vuln_id=vuln_dict.get("id", f"VULN-{i}"),
                severity=vuln_dict.get("severity", "medium"),
                file_path="<snippet>",
                line=vuln_dict.get("line", 0),
                code_snippet=vuln_dict.get("code", code[:200]),
                description=vuln_dict.get("description", ""),
                cwe=vuln_dict.get("cwe", "N/A"),
                remediation=vuln_dict.get("remediation", ""),
                auto_fixable=vuln_dict.get("auto_fixable", False),
                confidence=vuln_dict.get("confidence", "medium"),
                rule_id=vuln_dict.get("rule_id"),
            )
            vulnerabilities.append(formatted_vuln)

        # Filter by severity
        vulnerabilities = filter_by_severity(vulnerabilities, severity_threshold)

        # Build final result
        result = format_scan_result_fn(scan_id, vulnerabilities, 1, duration_ms)

        # Store for later retrieval
        scan_results[scan_id] = result

        logger.info(
            f"Code scan completed: {scan_id} - Found {len(vulnerabilities)} vulnerabilities"
        )
        return result

    except Exception as e:
        logger.error(f"Error scanning code: {e}")
        return {
            "scan_id": generate_scan_id(),
            "timestamp": time.time(),
            "error": str(e),
            "summary": {
                "total_vulnerabilities": 0,
                "severity_counts": {},
                "scanned_files": 0,
                "duration_ms": 0,
            },
            "vulnerabilities": [],
        }


@mcp.tool()
async def patch_vulnerability(file_path: str, vulnerability_id: str) -> dict[str, Any]:
    """
    Auto-fix a specific vulnerability in a file.

    Args:
        file_path: Path to the file containing the vulnerability
        vulnerability_id: ID of the vulnerability to patch

    Returns:
        Patch result with status, diff, and message
    """
    logger.info(f"Patching vulnerability {vulnerability_id} in {file_path}")

    try:
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return {
                "status": "error",
                "message": f"File not found: {file_path}",
                "vulnerability_id": vulnerability_id,
                "diff": None,
            }

        # Apply patch using patch engine
        patch_result = patch_engine.patch_vulnerability(
            str(file_path_obj), vulnerability_id, dry_run=False
        )

        return {
            "status": "success" if patch_result.get("success") else "error",
            "message": patch_result.get("message", "Patch applied"),
            "vulnerability_id": vulnerability_id,
            "file_path": file_path,
            "diff": patch_result.get("diff", ""),
            "patched_lines": patch_result.get("patched_lines", []),
        }

    except Exception as e:
        logger.error(f"Error patching vulnerability: {e}")
        return {
            "status": "error",
            "message": str(e),
            "vulnerability_id": vulnerability_id,
            "file_path": file_path,
            "diff": None,
        }


@mcp.tool()
async def get_security_report(scan_id: str) -> dict[str, Any]:
    """
    Get the full security report for a previous scan.

    Args:
        scan_id: The scan ID returned from a previous scan

    Returns:
        Full scan report or error if not found
    """
    logger.info(f"Retrieving security report for scan: {scan_id}")

    if scan_id in scan_results:
        return scan_results[scan_id]

    return {
        "error": f"Scan ID not found: {scan_id}",
        "available_scans": list(scan_results.keys())[-10:],  # Last 10 scan IDs
    }


@mcp.tool()
async def list_rules() -> dict[str, Any]:
    """
    List all available security rules and their configurations.

    Returns:
        List of rules with their metadata
    """
    logger.info("Listing security rules")

    try:
        rules = scan_engine.get_rules()

        return {
            "rules": rules,
            "total_rules": len(rules),
            "enabled_rules": rule_config.get("enabled_rules", ["*"]),
            "config": rule_config,
        }

    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        return {
            "error": str(e),
            "rules": [],
            "total_rules": 0,
        }


@mcp.tool()
async def configure_rules(config: dict[str, Any]) -> dict[str, Any]:
    """
    Update rule settings and configuration.

    Args:
        config: Configuration dictionary with rule settings
            - enabled_rules: List of rule IDs to enable (use ["*"] for all)
            - severity_threshold: Default severity threshold
            - custom_rules: Custom rule definitions

    Returns:
        Updated configuration
    """
    logger.info(f"Updating rule configuration: {config}")

    global rule_config

    try:
        # Update configuration
        if "enabled_rules" in config:
            rule_config["enabled_rules"] = config["enabled_rules"]
        if "severity_threshold" in config:
            rule_config["severity_threshold"] = config["severity_threshold"]
        if "custom_rules" in config:
            rule_config["custom_rules"].update(config["custom_rules"])

        # Apply to scan engine if supported
        scan_engine.configure_rules(rule_config)

        return {
            "status": "success",
            "config": rule_config,
            "message": "Configuration updated successfully",
        }

    except Exception as e:
        logger.error(f"Error configuring rules: {e}")
        return {
            "status": "error",
            "message": str(e),
            "config": rule_config,
        }


def main():
    """Run the MCP server."""
    logger.info("Starting Secure Vibe MCP Server...")
    mcp.run()


if __name__ == "__main__":
    main()
