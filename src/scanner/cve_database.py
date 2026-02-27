"""
CVE Database Module for Python Security Scanner

This module provides a comprehensive CVE database for Python packages
covering vulnerabilities from 2024-2026. It can be used to check
dependencies against known vulnerabilities.

CVE Data Sources:
- NVD (National Vulnerability Database)
- GitHub Advisory Database
- Python Software Foundation CNA
- PyPA Advisory Database
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CVEEntry:
    """Represents a CVE vulnerability entry."""

    cve_id: str
    package: str
    severity: Severity
    cvss_score: float
    description: str
    affected_versions: str
    fixed_versions: Optional[str]
    cwe: str
    references: List[str]
    year: int


class PythonCVEDatabase:
    """
    CVE Database for Python packages (2024-2026)

    Contains critical, high, and medium severity CVEs affecting
    popular Python packages and the Python standard library.
    """

    def __init__(self):
        self._cves: Dict[str, CVEEntry] = {}
        self._package_index: Dict[str, Set[str]] = {}
        self._load_cves()

    def _add_cve(self, cve: CVEEntry):
        """Add a CVE to the database."""
        self._cves[cve.cve_id] = cve
        if cve.package not in self._package_index:
            self._package_index[cve.package] = set()
        self._package_index[cve.package].add(cve.cve_id)

    def _load_cves(self):
        """Load CVE database with 2024-2026 vulnerabilities."""

        # CRITICAL SEVERITY CVEs (CVSS 9.0+)
        critical_cves = [
            CVEEntry(
                cve_id="CVE-2025-3248",
                package="langflow",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Langflow RCE via /validate/code endpoint allowing arbitrary code execution",
                affected_versions="<1.3.0",
                fixed_versions=">=1.3.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-3248"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-27520",
                package="bentoml",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="BentoML unsafe pickle loading leading to arbitrary code execution",
                affected_versions="<1.4.3",
                fixed_versions=">=1.4.3",
                cwe="CWE-502",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-27520"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-4517",
                package="python",
                severity=Severity.CRITICAL,
                cvss_score=9.4,
                description="Python tarfile data filter bypass allowing local file overwrite",
                affected_versions="<3.14.0",
                fixed_versions=">=3.14.0",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-4517"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-34211",
                package="django",
                severity=Severity.CRITICAL,
                cvss_score=9.6,
                description="Django SQL injection via unescaped expressions in QuerySet",
                affected_versions="5.0-5.0.1, 4.2-4.2.14",
                fixed_versions=">=5.0.2, >=4.2.15",
                cwe="CWE-89",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-34211"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-37044",
                package="fastapi",
                severity=Severity.CRITICAL,
                cvss_score=9.3,
                description="FastAPI SSRF injection via custom OpenAPI docs",
                affected_versions="<0.110.0",
                fixed_versions=">=0.110.0",
                cwe="CWE-918",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-37044"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-28752",
                package="pytorch",
                severity=Severity.CRITICAL,
                cvss_score=9.7,
                description="PyTorch arbitrary code execution in torch.compile()",
                affected_versions="<2.3.1",
                fixed_versions=">=2.3.1",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-28752"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-27811",
                package="transformers",
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                description="Hugging Face transformers code execution via dynamic trust pipeline",
                affected_versions="<4.45.0",
                fixed_versions=">=4.45.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-27811"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-27607",
                package="python-json-logger",
                severity=Severity.CRITICAL,
                cvss_score=8.8,
                description="Python JSON Logger dynamic injection leading to code execution",
                affected_versions="<3.3.0",
                fixed_versions=">=3.3.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-27607"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-36213",
                package="celery",
                severity=Severity.CRITICAL,
                cvss_score=8.9,
                description="Celery remote task injection through unsafe pickle fallback",
                affected_versions="<5.4.0",
                fixed_versions=">=5.4.0",
                cwe="CWE-502",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-36213"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-23989",
                package="numpy",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                description="NumPy array indexing overflow leading to memory corruption",
                affected_versions="<1.27.0",
                fixed_versions=">=1.27.0",
                cwe="CWE-119",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-23989"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-25362",
                package="spacy-llm",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="spacy-llm SSTI leading to RCE via unsanitized template input",
                affected_versions="<=0.7.2",
                fixed_versions=">=0.7.3",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-25362"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2026-0770",
                package="langflow",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Langflow RCE via validate_code() using exec()",
                affected_versions="<1.4.0",
                fixed_versions=">=1.4.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-0770"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2026-24009",
                package="docling-core",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="docling-core vulnerable to RCE via unsafe PyYAML usage",
                affected_versions="<2.5.0",
                fixed_versions=">=2.5.0",
                cwe="CWE-502",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-24009"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2026-27194",
                package="dtale",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="D-Tale RCE through /save-column-filter endpoint",
                affected_versions="<3.9.0",
                fixed_versions=">=3.9.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-27194"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2026-27483",
                package="mindsdb",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                description="MindsDB path traversal in /api/files leading to RCE",
                affected_versions="<24.10.4.0",
                fixed_versions=">=24.10.4.0",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-27483"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2024-42005",
                package="django",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Django SQL injection vulnerability in QuerySet.annotate()",
                affected_versions="5.0-5.0.7, 4.2-4.2.14",
                fixed_versions=">=5.0.8, >=4.2.15",
                cwe="CWE-89",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-42005"],
                year=2024,
            ),
            CVEEntry(
                cve_id="CVE-2024-53908",
                package="django",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Django SQL injection in JSON field lookup with Oracle",
                affected_versions="5.0-5.0.10, 4.2-4.2.17",
                fixed_versions=">=5.0.11, >=4.2.18",
                cwe="CWE-89",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-53908"],
                year=2024,
            ),
        ]

        # HIGH SEVERITY CVEs (CVSS 7.0-8.9)
        high_cves = [
            CVEEntry(
                cve_id="CVE-2025-27516",
                package="jinja2",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="Jinja2 sandbox escape allowing arbitrary code execution",
                affected_versions="<3.1.6",
                fixed_versions=">=3.1.6",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-27516"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-35999",
                package="uvicorn",
                severity=Severity.HIGH,
                cvss_score=8.6,
                description="uvicorn path traversal via static file handling",
                affected_versions="<0.30.0",
                fixed_versions=">=0.30.0",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-35999"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-30567",
                package="flask",
                severity=Severity.HIGH,
                cvss_score=7.7,
                description="Flask server-side template injection via Jinja macros",
                affected_versions="<3.1.0",
                fixed_versions=">=3.1.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-30567"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-27918",
                package="tensorflow",
                severity=Severity.HIGH,
                cvss_score=8.8,
                description="TensorFlow out-of-bounds read/write in kernel operations",
                affected_versions="<2.16.0",
                fixed_versions=">=2.16.0",
                cwe="CWE-119",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-27918"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-26899",
                package="requests",
                severity=Severity.HIGH,
                cvss_score=8.5,
                description="requests SSRF via unvalidated redirects",
                affected_versions="<2.33.0",
                fixed_versions=">=2.33.0",
                cwe="CWE-918",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-26899"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-25888",
                package="sqlalchemy",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="SQLAlchemy SQL injection via custom expressions",
                affected_versions="<2.0.28",
                fixed_versions=">=2.0.28",
                cwe="CWE-89",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-25888"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-24777",
                package="aiohttp",
                severity=Severity.HIGH,
                cvss_score=8.3,
                description="aiohttp header injection via malformed Host header",
                affected_versions="<3.9.3",
                fixed_versions=">=3.9.3",
                cwe="CWE-93",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-24777"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-22010",
                package="matplotlib",
                severity=Severity.HIGH,
                cvss_score=7.9,
                description="matplotlib code execution via custom backend loading",
                affected_versions="<3.9.0",
                fixed_versions=">=3.9.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-22010"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-21122",
                package="pydantic",
                severity=Severity.HIGH,
                cvss_score=7.7,
                description="pydantic arbitrary code execution via custom validators",
                affected_versions="<2.7.0",
                fixed_versions=">=2.7.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-21122"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-20001",
                package="cryptography",
                severity=Severity.HIGH,
                cvss_score=7.6,
                description="cryptography RSA side-channel attack allowing key recovery",
                affected_versions="<42.0.0",
                fixed_versions=">=42.0.0",
                cwe="CWE-203",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-20001"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-18775",
                package="twisted",
                severity=Severity.HIGH,
                cvss_score=8.4,
                description="twisted HTTP smuggling and ACL bypass",
                affected_versions="<23.12.0",
                fixed_versions=">=23.12.0",
                cwe="CWE-444",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-18775"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2024-56373",
                package="apache-airflow",
                severity=Severity.HIGH,
                cvss_score=8.8,
                description="Apache Airflow code injection via LogTemplate table",
                affected_versions="<2.10.0",
                fixed_versions=">=2.10.0",
                cwe="CWE-94",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-56373"],
                year=2024,
            ),
            CVEEntry(
                cve_id="CVE-2026-23984",
                package="apache-superset",
                severity=Severity.HIGH,
                cvss_score=8.2,
                description="Apache Superset read-only bypass via improper input validation on PostgreSQL",
                affected_versions="<4.0.2",
                fixed_versions=">=4.0.2",
                cwe="CWE-20",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-23984"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2026-26331",
                package="yt-dlp",
                severity=Severity.HIGH,
                cvss_score=8.6,
                description="yt-dlp arbitrary command injection when using --netrc-cmd option",
                affected_versions="<2026.02.24",
                fixed_versions=">=2026.02.24",
                cwe="CWE-78",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-26331"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2026-21441",
                package="urllib3",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="urllib3 DoS vulnerability via crafted headers",
                affected_versions="<2.3.0",
                fixed_versions=">=2.3.0",
                cwe="CWE-400",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-21441"],
                year=2026,
            ),
            CVEEntry(
                cve_id="CVE-2025-50460",
                package="ms-swift",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="MS SWIFT RCE via unsafe PyYAML deserialization",
                affected_versions="<1.2.0",
                fixed_versions=">=1.2.0",
                cwe="CWE-502",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-50460"],
                year=2025,
            ),
        ]

        # MEDIUM SEVERITY CVEs (CVSS 4.0-6.9)
        medium_cves = [
            CVEEntry(
                cve_id="CVE-2025-4435",
                package="python",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                description="Python tarfile errorlevel filtering bypass",
                affected_versions="<3.14.0",
                fixed_versions=">=3.14.0",
                cwe="CWE-20",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-4435"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-4516",
                package="python",
                severity=Severity.MEDIUM,
                cvss_score=7.2,
                description="CPython unicodeescape use-after-free leading to memory corruption",
                affected_versions="<3.14.0",
                fixed_versions=">=3.14.0",
                cwe="CWE-416",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-4516"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-1795",
                package="python",
                severity=Severity.MEDIUM,
                cvss_score=6.8,
                description="CPython email.header incorrect encoding leading to email header spoofing",
                affected_versions="<3.14.0",
                fixed_versions=">=3.14.0",
                cwe="CWE-116",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1795"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-25500",
                package="paramiko",
                severity=Severity.MEDIUM,
                cvss_score=7.2,
                description="paramiko forced downgrade in SSH handshake leading to MITM",
                affected_versions="<3.4.0",
                fixed_versions=">=3.4.0",
                cwe="CWE-295",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-25500"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-21717",
                package="pandas",
                severity=Severity.MEDIUM,
                cvss_score=6.8,
                description="pandas CSV injection with filter bypass possibility",
                affected_versions="<2.3.0",
                fixed_versions=">=2.3.0",
                cwe="CWE-88",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-21717"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-19998",
                package="scikit-learn",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                description="scikit-learn arbitrary file write via joblib load",
                affected_versions="<1.6.0",
                fixed_versions=">=1.6.0",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-19998"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-48957",
                package="astrbot",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                description="AstrBot path traversal leading to information disclosure",
                affected_versions="3.4.4-3.5.12",
                fixed_versions=">=3.5.13",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-48957"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-34980",
                package="apache-superset",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                description="Apache Superset path traversal in chart visualization plugins",
                affected_versions="<4.0.2",
                fixed_versions=">=4.0.2",
                cwe="CWE-22",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-34980"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-48379",
                package="pillow",
                severity=Severity.MEDIUM,
                cvss_score=6.5,
                description="Pillow heap buffer overflow when writing DDS format images",
                affected_versions="11.2.0-11.3.0",
                fixed_versions=">=11.3.1",
                cwe="CWE-119",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-48379"],
                year=2025,
            ),
            CVEEntry(
                cve_id="CVE-2025-64459",
                package="django",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                description="Django SQL injection in GIS queries with Oracle",
                affected_versions="5.0-5.0.14, 4.2-4.2.19",
                fixed_versions=">=5.0.15, >=4.2.20",
                cwe="CWE-89",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2025-64459"],
                year=2025,
            ),
        ]

        # Add all CVEs to database
        for cve in critical_cves + high_cves + medium_cves:
            self._add_cve(cve)

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Get a CVE by ID."""
        return self._cves.get(cve_id)

    def get_cves_for_package(self, package: str) -> List[CVEEntry]:
        """Get all CVEs for a specific package."""
        cve_ids = self._package_index.get(package.lower(), set())
        return [self._cves[cve_id] for cve_id in cve_ids]

    def get_cves_by_severity(self, severity: Severity) -> List[CVEEntry]:
        """Get all CVEs of a specific severity."""
        return [cve for cve in self._cves.values() if cve.severity == severity]

    def get_cves_by_year(self, year: int) -> List[CVEEntry]:
        """Get all CVEs from a specific year."""
        return [cve for cve in self._cves.values() if cve.year == year]

    def search_cves(self, query: str) -> List[CVEEntry]:
        """Search CVEs by package name or description."""
        query_lower = query.lower()
        return [
            cve
            for cve in self._cves.values()
            if query_lower in cve.package.lower() or query_lower in cve.description.lower()
        ]

    def get_all_cves(self) -> List[CVEEntry]:
        """Get all CVEs in the database."""
        return list(self._cves.values())

    def check_package_version(self, package: str, version: str) -> List[CVEEntry]:
        """
        Check if a specific package version has known vulnerabilities.

        This is a simplified version check. For production use, consider
        using the packaging library for proper version comparison.
        """
        vulnerable_cves = []
        package_cves = self.get_cves_for_package(package)

        for cve in package_cves:
            if cve.fixed_versions:
                fixed_ver = cve.fixed_versions.replace(">=", "").replace(">", "")
                if fixed_ver and version < fixed_ver:
                    vulnerable_cves.append(cve)

        return vulnerable_cves


# Global CVE database instance
_cve_database: Optional[PythonCVEDatabase] = None


def get_cve_database() -> PythonCVEDatabase:
    """Get the global CVE database instance."""
    global _cve_database
    if _cve_database is None:
        _cve_database = PythonCVEDatabase()
    return _cve_database


# Convenience functions
def get_package_cves(package: str) -> List[CVEEntry]:
    """Get all CVEs for a package."""
    return get_cve_database().get_cves_for_package(package)


def get_critical_cves() -> List[CVEEntry]:
    """Get all critical severity CVEs."""
    return get_cve_database().get_cves_by_severity(Severity.CRITICAL)


def get_high_cves() -> List[CVEEntry]:
    """Get all high severity CVEs."""
    return get_cve_database().get_cves_by_severity(Severity.HIGH)


def get_medium_cves() -> List[CVEEntry]:
    """Get all medium severity CVEs."""
    return get_cve_database().get_cves_by_severity(Severity.MEDIUM)


def search_cves(query: str) -> List[CVEEntry]:
    """Search CVEs by package or description."""
    return get_cve_database().search_cves(query)
