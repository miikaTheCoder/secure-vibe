#!/usr/bin/env python3
"""
Secure Vibe MCP - Usage Examples

This file demonstrates how to use the Secure Vibe security scanner
programmatically in Python.

Examples include:
    - Scanning a single file
    - Scanning a directory
    - Getting security reports
    - Patching vulnerabilities
    - Working with results
"""

import asyncio
import json
from pathlib import Path
from typing import Optional

# Import Secure Vibe components
from secure_vibe import SecurityScanner, Config, ScanResult, Vulnerability, Severity
from secure_vibe.mcp_client import MCPClient


# ============================================================================
# Example 1: Basic File Scanning
# ============================================================================


def example_scan_file():
    """Demonstrates scanning a single file for vulnerabilities."""

    print("=" * 60)
    print("Example 1: Scanning a Single File")
    print("=" * 60)

    # Initialize scanner with configuration
    config = Config(
        severity_threshold="medium",  # Only report medium and above
        auto_patch=False,  # Don't auto-fix
        parallel_scanning=True,  # Enable parallel processing
        max_workers=4,
    )

    scanner = SecurityScanner(config)

    # Scan a file
    file_path = Path("app.js")

    try:
        result = scanner.scan_file(
            file_path=file_path,
            include_code=True,  # Include vulnerable code snippets
            include_remediation=True,  # Include fix suggestions
        )

        # Print summary
        print(f"\n📄 Scanned: {result.file_path}")
        print(f"🔍 Vulnerabilities found: {len(result.vulnerabilities)}")
        print(f"⚠️  Highest severity: {result.highest_severity}")
        print(f"📊 Risk score: {result.risk_score}/100")

        # Print each vulnerability
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n  [{i}] {vuln.rule_id}: {vuln.name}")
            print(f"      Severity: {vuln.severity}")
            print(f"      Line: {vuln.line_number}")
            print(f"      Code: {vuln.code_snippet[:50]}...")
            print(f"      Fix: {vuln.remediation}")

    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Error scanning file: {e}")


# ============================================================================
# Example 2: Directory Scanning
# ============================================================================


def example_scan_directory():
    """Demonstrates scanning an entire directory recursively."""

    print("\n" + "=" * 60)
    print("Example 2: Scanning a Directory")
    print("=" * 60)

    config = Config(
        severity_threshold="low",  # Report all severities
        enable_semantic_analysis=True,
        enable_dataflow_analysis=True,
    )

    scanner = SecurityScanner(config)

    # Scan directory
    directory_path = Path("./src")

    result = scanner.scan_directory(
        directory_path=directory_path,
        recursive=True,  # Scan subdirectories
        file_extensions=[".js", ".ts", ".py"],  # Only these extensions
        exclude_patterns=["node_modules", "__pycache__", ".git", "dist", "build"],
    )

    # Print summary
    print(f"\n📁 Directory: {result.directory_path}")
    print(f"📄 Files scanned: {result.total_files}")
    print(f"🔍 Total vulnerabilities: {result.total_vulnerabilities}")
    print(f"⏱️  Scan duration: {result.duration_ms}ms")

    # Group by severity
    print("\n📊 Severity breakdown:")
    for severity, count in result.severity_counts.items():
        icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡"
        print(f"  {icon} {severity.capitalize()}: {count}")

    # Group by category
    print("\n📂 Vulnerability categories:")
    for category, count in result.category_counts.items():
        print(f"  • {category}: {count}")


# ============================================================================
# Example 3: Security Report Generation
# ============================================================================


def example_security_report():
    """Demonstrates generating comprehensive security reports."""

    print("\n" + "=" * 60)
    print("Example 3: Security Report Generation")
    print("=" * 60)

    config = Config()
    scanner = SecurityScanner(config)

    # Generate comprehensive report
    report = scanner.generate_report(
        target_path=Path("./"),
        report_format="json",  # json, yaml, sarif, html
        include_statistics=True,
        include_remediation=True,
        include_trend_analysis=True,
        severity_filter=["high", "critical"],  # Only high/critical
        output_path=Path("security-report.json"),
    )

    # Print report summary
    print(f"\n📊 Report generated: {report.output_path}")
    print(f"📄 Format: {report.format}")
    print(f"🔍 Total issues: {report.total_issues}")
    print(f"📈 Risk score: {report.overall_risk_score}/100")

    # Export to different formats
    report.export(format="html", output_path="security-report.html")
    report.export(format="sarif", output_path="security-report.sarif")

    print("\n✅ Reports exported to:")
    print("  • security-report.json")
    print("  • security-report.html")
    print("  • security-report.sarif")


# ============================================================================
# Example 4: Patching Vulnerabilities
# ============================================================================


def example_patch_vulnerability():
    """Demonstrates auto-patching vulnerabilities."""

    print("\n" + "=" * 60)
    print("Example 4: Auto-Patching Vulnerabilities")
    print("=" * 60)

    config = Config(
        auto_patch=False,  # Manual control
        backup_enabled=True,
    )

    scanner = SecurityScanner(config)

    # Scan first to find vulnerabilities
    result = scanner.scan_file("app.js")

    if not result.vulnerabilities:
        print("\n✅ No vulnerabilities found to patch")
        return

    print(f"\n🔍 Found {len(result.vulnerabilities)} vulnerabilities")

    # Patch specific vulnerability
    target_vuln = result.vulnerabilities[0]

    print(f"\n🛠️  Patching: {target_vuln.rule_id}")
    print(f"   File: {target_vuln.file_path}")
    print(f"   Line: {target_vuln.line_number}")

    # Perform patch
    patch_result = scanner.patch_vulnerability(
        file_path=target_vuln.file_path,
        vulnerability_id=target_vuln.rule_id,
        line_number=target_vuln.line_number,
        backup=True,
        preview=True,  # Show what would change without applying
    )

    print(f"\n📋 Patch preview:")
    print(f"   Original: {patch_result.original_code}")
    print(f"   Patched:  {patch_result.patched_code}")
    print(f"   Confidence: {patch_result.confidence}%")

    # Apply patch if confident
    if patch_result.confidence >= 90:
        confirm = input("\nApply patch? (y/n): ")
        if confirm.lower() == "y":
            scanner.patch_vulnerability(
                file_path=target_vuln.file_path,
                vulnerability_id=target_vuln.rule_id,
                backup=True,
                preview=False,
            )
            print("✅ Patch applied successfully")
    else:
        print("⚠️  Patch confidence too low, manual review recommended")


# ============================================================================
# Example 5: Working with MCP Client
# ============================================================================


async def example_mcp_client():
    """Demonstrates using the MCP client for AI assistant integration."""

    print("\n" + "=" * 60)
    print("Example 5: MCP Client Integration")
    print("=" * 60)

    # Initialize MCP client
    client = MCPClient(server_url="http://localhost:8000", api_key="your-api-key")

    # Connect to MCP server
    await client.connect()
    print("\n🔗 Connected to MCP server")

    # Call scan_file tool
    result = await client.call_tool("scan_file", {"file_path": "app.js", "include_code": True})

    print(f"\n📄 Scan result: {result['scan_summary']['vulnerabilities_found']} issues")

    # Call get_security_report tool
    report = await client.call_tool(
        "get_security_report",
        {"target_path": "./src", "report_format": "json", "severity_filter": ["high", "critical"]},
    )

    print(f"\n📊 Report: {report['total_issues']} high/critical issues")

    # Disconnect
    await client.disconnect()
    print("\n👋 Disconnected from MCP server")


# ============================================================================
# Example 6: Custom Rule Loading
# ============================================================================


def example_custom_rules():
    """Demonstrates loading and using custom security rules."""

    print("\n" + "=" * 60)
    print("Example 6: Custom Security Rules")
    print("=" * 60)

    # Initialize scanner with custom rules
    config = Config(
        custom_rules_path="./custom-rules.yaml", builtin_rules_only=False, allow_custom_rules=True
    )

    scanner = SecurityScanner(config)

    # Load and display custom rules
    custom_rules = scanner.get_custom_rules()

    print(f"\n📋 Loaded {len(custom_rules)} custom rules:")
    for rule in custom_rules:
        print(f"  • {rule.id}: {rule.name} ({rule.severity})")

    # Scan with custom rules
    result = scanner.scan_file("app.js")

    # Filter for custom rule matches
    custom_vulns = [v for v in result.vulnerabilities if v.is_custom_rule]

    print(f"\n🔍 Custom rule matches: {len(custom_vulns)}")
    for vuln in custom_vulns:
        print(f"  • {vuln.rule_id}: {vuln.message}")


# ============================================================================
# Example 7: Batch Scanning with Progress
# ============================================================================


def example_batch_scanning():
    """Demonstrates batch scanning multiple files with progress tracking."""

    print("\n" + "=" * 60)
    print("Example 7: Batch Scanning with Progress")
    print("=" * 60)

    config = Config()
    scanner = SecurityScanner(config)

    # Files to scan
    files_to_scan = [Path("app.js"), Path("api.py"), Path("utils.ts"), Path("auth.go")]

    # Define progress callback
    def on_progress(current: int, total: int, file_path: Path):
        percent = (current / total) * 100
        print(f"\r  Progress: [{current}/{total}] {percent:.1f}% - {file_path}", end="")

    # Batch scan
    results = scanner.scan_batch(
        file_paths=files_to_scan, on_progress=on_progress, parallel=True, max_workers=4
    )

    print("\n\n📊 Batch scan complete:")

    total_vulns = 0
    for result in results:
        vuln_count = len(result.vulnerabilities)
        total_vulns += vuln_count
        status = "❌" if vuln_count > 0 else "✅"
        print(f"  {status} {result.file_path}: {vuln_count} issues")

    print(f"\n🔍 Total vulnerabilities across all files: {total_vulns}")


# ============================================================================
# Example 8: Filtering and Sorting Results
# ============================================================================


def example_filtering_results():
    """Demonstrates filtering and sorting scan results."""

    print("\n" + "=" * 60)
    print("Example 8: Filtering and Sorting Results")
    print("=" * 60)

    config = Config()
    scanner = SecurityScanner(config)

    # Scan directory
    result = scanner.scan_directory("./src")

    # Filter by severity
    critical_high = result.filter_by_severity(["critical", "high"])
    print(f"\n🔴 Critical/High issues: {len(critical_high)}")

    # Filter by category
    injection_vulns = result.filter_by_category("injection")
    print(f"💉 Injection issues: {len(injection_vulns)}")

    # Filter by file
    specific_file = result.filter_by_file("auth.js")
    print(f"📄 Issues in auth.js: {len(specific_file)}")

    # Sort by severity (critical first)
    sorted_by_severity = result.sort_by_severity()
    print("\n📊 Top 5 most severe issues:")
    for i, vuln in enumerate(sorted_by_severity[:5], 1):
        print(
            f"  {i}. [{vuln.severity.upper()}] {vuln.rule_id} in {vuln.file_path}:{vuln.line_number}"
        )

    # Sort by CVSS score
    sorted_by_cvss = result.sort_by_cvss()
    print("\n📈 Top 5 by CVSS score:")
    for i, vuln in enumerate(sorted_by_cvss[:5], 1):
        print(f"  {i}. CVSS {vuln.cvss_score} - {vuln.name}")


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run all examples."""

    print("\n" + "🚀" * 30)
    print("  Secure Vibe MCP - Usage Examples")
    print("🚀" * 30 + "\n")

    # Run synchronous examples
    example_scan_file()
    example_scan_directory()
    example_security_report()
    example_patch_vulnerability()
    example_custom_rules()
    example_batch_scanning()
    example_filtering_results()

    # Run async example
    print("\n" + "=" * 60)
    print("Running async MCP client example...")
    print("=" * 60)
    # asyncio.run(example_mcp_client())  # Uncomment when server is running
    print("(Skipped - requires running MCP server)")

    print("\n" + "=" * 60)
    print("✅ All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
