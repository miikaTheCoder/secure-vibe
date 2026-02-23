"""
Python Security Vulnerability Detector

Uses tree-sitter-python for AST parsing and regex patterns for certain detections.
Detects various security vulnerabilities in Python code.
"""

import re
from typing import List, Optional, Dict, Any

from .base import BaseDetector, Finding, Severity

# Try to import tree-sitter, fallback to regex-only if not available
try:
    from tree_sitter import Language as TSLanguage, Parser as TSParser
    import tree_sitter_python as tspython

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
    TSLanguage = None  # type: ignore
    TSParser = None  # type: ignore
    tspython = None  # type: ignore


class PythonSecurityDetector(BaseDetector):
    """
    Detects security vulnerabilities in Python code.
    Uses tree-sitter for AST-based detection and regex for pattern matching.
    """

    # Rule definitions with all required fields
    RULES = {
        "PY001": {
            "name": "eval-usage",
            "severity": Severity.CRITICAL,
            "message": "Dangerous use of eval() detected. eval() executes arbitrary code.",
            "cwe": "CWE-95",
            "remediation": "Use ast.literal_eval() for safe evaluation of literals, or json.loads() for JSON data. Avoid eval() entirely if possible.",
        },
        "PY002": {
            "name": "exec-usage",
            "severity": Severity.CRITICAL,
            "message": "Dangerous use of exec() detected. exec() executes arbitrary code.",
            "cwe": "CWE-95",
            "remediation": "Avoid exec() entirely. Use safer alternatives like importlib for dynamic imports.",
        },
        "PY003": {
            "name": "literal-eval-misuse",
            "severity": Severity.MEDIUM,
            "message": "Potential misuse of ast.literal_eval() with untrusted input.",
            "cwe": "CWE-94",
            "remediation": "Ensure input to literal_eval() is validated before use. Note: literal_eval() is safe for literals but may still cause DoS with deeply nested structures.",
        },
        "PY004": {
            "name": "sql-injection-format",
            "severity": Severity.CRITICAL,
            "message": "Potential SQL injection via string formatting detected.",
            "cwe": "CWE-89",
            "remediation": "Use parameterized queries with prepared statements. Use SQLAlchemy or similar ORM with proper parameter binding.",
        },
        "PY005": {
            "name": "pickle-deserialization",
            "severity": Severity.CRITICAL,
            "message": "Insecure deserialization via pickle detected.",
            "cwe": "CWE-502",
            "remediation": "Avoid pickle for untrusted data. Use json, msgpack, or protobuf instead. If pickle is required, implement cryptographic signing.",
        },
        "PY006": {
            "name": "marshal-deserialization",
            "severity": Severity.CRITICAL,
            "message": "Insecure deserialization via marshal detected.",
            "cwe": "CWE-502",
            "remediation": "Avoid marshal for untrusted data. Use json or other safe serialization formats.",
        },
        "PY007": {
            "name": "yaml-unsafe-load",
            "severity": Severity.CRITICAL,
            "message": "Insecure YAML loading detected. yaml.load() without Loader is unsafe.",
            "cwe": "CWE-502",
            "remediation": "Use yaml.safe_load() instead of yaml.load(). Never load YAML from untrusted sources without safe_load().",
        },
        "PY008": {
            "name": "subprocess-shell-true",
            "severity": Severity.CRITICAL,
            "message": "Command injection risk: subprocess with shell=True detected.",
            "cwe": "CWE-78",
            "remediation": "Use shell=False (default) and pass command as list. Use shlex.quote() if shell=True is absolutely necessary.",
        },
        "PY009": {
            "name": "os-system-usage",
            "severity": Severity.HIGH,
            "message": "Command injection risk: os.system() usage detected.",
            "cwe": "CWE-78",
            "remediation": "Use subprocess module with shell=False. Pass command as list to avoid shell injection.",
        },
        "PY010": {
            "name": "os-popen-usage",
            "severity": Severity.HIGH,
            "message": "Command injection risk: os.popen() usage detected.",
            "cwe": "CWE-78",
            "remediation": "Use subprocess module with shell=False. Pass command as list to avoid shell injection.",
        },
        "PY011": {
            "name": "commands-module-usage",
            "severity": Severity.HIGH,
            "message": "Command injection risk: deprecated commands module usage detected.",
            "cwe": "CWE-78",
            "remediation": "Use subprocess module instead. The commands module is deprecated and insecure.",
        },
        "PY012": {
            "name": "hardcoded-password",
            "severity": Severity.CRITICAL,
            "message": "Hardcoded password or secret detected.",
            "cwe": "CWE-798",
            "remediation": "Use environment variables, secret management services (AWS Secrets Manager, Vault), or encrypted configuration files.",
        },
        "PY013": {
            "name": "hardcoded-api-key",
            "severity": Severity.CRITICAL,
            "message": "Hardcoded API key detected.",
            "cwe": "CWE-798",
            "remediation": "Use environment variables or secret management services. Never commit API keys to version control.",
        },
        "PY014": {
            "name": "debug-mode-enabled",
            "severity": Severity.HIGH,
            "message": "Debug mode enabled in production code.",
            "cwe": "CWE-489",
            "remediation": "Ensure debug mode is disabled in production. Use environment variables to control debug settings.",
        },
        "PY015": {
            "name": "insecure-temp-file",
            "severity": Severity.MEDIUM,
            "message": "Insecure temporary file creation via mktemp() detected.",
            "cwe": "CWE-377",
            "remediation": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead of mktemp().",
        },
        "PY016": {
            "name": "path-traversal",
            "severity": Severity.HIGH,
            "message": "Potential path traversal via open() with user input.",
            "cwe": "CWE-22",
            "remediation": "Validate and sanitize file paths. Use os.path.abspath(), os.path.realpath(), and check against allowed directories.",
        },
        "PY017": {
            "name": "assert-in-production",
            "severity": Severity.MEDIUM,
            "message": "assert statement detected - removed in optimized bytecode (-O flag).",
            "cwe": "CWE-617",
            "remediation": "Use proper error handling with if/raise instead of assert for security-critical checks.",
        },
        "PY018": {
            "name": "insecure-hash-md5",
            "severity": Severity.MEDIUM,
            "message": "Insecure hash algorithm: MD5 detected. MD5 is cryptographically broken.",
            "cwe": "CWE-327",
            "remediation": "Use hashlib.sha256() or stronger algorithms for cryptographic purposes.",
        },
        "PY019": {
            "name": "insecure-hash-sha1",
            "severity": Severity.MEDIUM,
            "message": "Insecure hash algorithm: SHA1 detected. SHA1 is cryptographically broken.",
            "cwe": "CWE-327",
            "remediation": "Use hashlib.sha256() or stronger algorithms for cryptographic purposes.",
        },
        "PY020": {
            "name": "python2-input",
            "severity": Severity.CRITICAL,
            "message": "Python 2 input() usage detected - executes arbitrary code.",
            "cwe": "CWE-78",
            "remediation": "Use raw_input() in Python 2 or input() in Python 3. Ensure code is Python 3 compatible.",
        },
        "PY021": {
            "name": "xxe-vulnerability",
            "severity": Severity.HIGH,
            "message": "XXE vulnerability: xml.etree.ElementTree.fromstring() with external entities.",
            "cwe": "CWE-611",
            "remediation": "Use defusedxml library or disable external entity resolution. Avoid parsing XML from untrusted sources.",
        },
        "PY022": {
            "name": "unverified-ssl-context",
            "severity": Severity.HIGH,
            "message": "SSL certificate verification disabled.",
            "cwe": "CWE-295",
            "remediation": "Use ssl.create_default_context() or verify certificates properly. Never disable verification in production.",
        },
        "PY023": {
            "name": "urllib-no-verify",
            "severity": Severity.HIGH,
            "message": "HTTPS request without certificate verification detected.",
            "cwe": "CWE-295",
            "remediation": "Set verify=True (default) in requests or use proper SSL context in urllib.",
        },
        "PY024": {
            "name": "hardcoded-jwt-secret",
            "severity": Severity.CRITICAL,
            "message": "Hardcoded JWT secret detected.",
            "cwe": "CWE-798",
            "remediation": "Load JWT secrets from environment variables or secure key management systems.",
        },
        "PY025": {
            "name": "weak-random-crypto",
            "severity": Severity.MEDIUM,
            "message": "Weak random number generator used for cryptographic purposes.",
            "cwe": "CWE-338",
            "remediation": "Use secrets module (Python 3.6+) or os.urandom() for cryptographic randomness.",
        },
        "PY026": {
            "name": "popen2-usage",
            "severity": Severity.HIGH,
            "message": "Command injection risk: popen2 module usage detected.",
            "cwe": "CWE-78",
            "remediation": "Use subprocess module with shell=False. The popen2 module is deprecated.",
        },
        "PY027": {
            "name": "json-load-without-validation",
            "severity": Severity.LOW,
            "message": "json.load() detected - ensure input is validated after loading.",
            "cwe": "CWE-20",
            "remediation": "Validate JSON data after loading. Consider using schema validation (jsonschema).",
        },
    }

    # Regex patterns for various detections
    PATTERNS = {
        "hardcoded_password": re.compile(
            r'(?i)(password|passwd|pwd|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
            re.MULTILINE,
        ),
        "hardcoded_api_key": re.compile(
            r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
            re.MULTILINE,
        ),
        "hardcoded_jwt_secret": re.compile(
            r'(?i)(jwt[_-]?secret|jwt[_-]?key|secret[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
            re.MULTILINE,
        ),
        "debug_true": re.compile(r"\b(debug|DEBUG)\s*=\s*True\b", re.MULTILINE),
        "sql_keywords": re.compile(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM)\s+", re.MULTILINE
        ),
    }

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        super().__init__(rules)
        self.language = "python"
        self._parser: Optional[Any] = None
        self._ts_language: Optional[Any] = None
        if _TREE_SITTER_AVAILABLE:
            try:
                self._ts_language = TSLanguage(tspython.language())
                self._parser = TSParser(self._ts_language)
            except Exception:
                pass

    def scan(self, file_path: str, code: str) -> List[Finding]:
        """
        Scan Python code for security vulnerabilities.

        Args:
            file_path: Path to the file being scanned
            code: Python source code to analyze

        Returns:
            List of Finding objects representing detected vulnerabilities
        """
        self.findings = []

        # AST-based detection
        if self._parser is not None:
            try:
                tree = self._parser.parse(bytes(code, "utf8"))
                self._scan_ast(file_path, code, tree)
            except Exception:
                pass

        # Regex-based detection
        self._scan_regex(file_path, code)

        # Deduplicate findings
        return self._deduplicate_findings(self.findings)

    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect vulnerabilities - returns dict format for backward compatibility."""
        findings = self.scan(file_path, code)
        return [f.to_dict() for f in findings]

    def _scan_ast(self, file_path: str, code: str, tree: Any) -> None:
        """Scan using tree-sitter AST."""
        root_node = tree.root_node

        def traverse(node: Any):
            # Check for call expressions
            if node.type == "call":
                self._check_call(node, code, file_path)

            # Check for assert statements
            if node.type == "assert_statement":
                finding = self._create_finding_from_ast("PY017", node, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Check for assignments
            if node.type in ("assignment", "augmented_assignment"):
                self._check_assignment(node, code, file_path)

            # Recurse into children
            for child in node.children:
                traverse(child)

        traverse(root_node)

    def _check_call(self, node: Any, code: str, file_path: str) -> None:
        """Check a call expression for vulnerabilities."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(func_node, code)
        func_name = func_text.lower()

        # Check for eval()
        if func_name == "eval" or func_text.endswith(".eval"):
            finding = self._create_finding_from_ast("PY001", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for exec()
        if func_name == "exec" or func_text.endswith(".exec"):
            finding = self._create_finding_from_ast("PY002", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for ast.literal_eval
        if "literal_eval" in func_text:
            finding = self._create_finding_from_ast("PY003", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for pickle
        if "pickle" in func_name or (
            func_text.endswith((".loads", ".load")) and "pickle" in func_text
        ):
            finding = self._create_finding_from_ast("PY005", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for marshal
        if "marshal" in func_name:
            finding = self._create_finding_from_ast("PY006", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for yaml.load
        if "yaml.load" in func_text and "safe_load" not in func_text:
            finding = self._create_finding_from_ast("PY007", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for subprocess with shell=True
        if "subprocess" in func_text or func_name in ("popen", "call", "run"):
            arguments = node.child_by_field_name("arguments")
            if arguments:
                for child in arguments.children:
                    if child.type == "keyword_argument":
                        arg_name = child.child_by_field_name("name")
                        arg_value = child.child_by_field_name("value")
                        if arg_name and arg_value:
                            name_text = self._get_node_text(arg_name, code)
                            value_text = self._get_node_text(arg_value, code)
                            if name_text == "shell" and value_text == "True":
                                finding = self._create_finding_from_ast(
                                    "PY008", node, code, file_path
                                )
                                if finding:
                                    self.findings.append(finding)
                                return

        # Check for os.system, os.popen
        if "os.system" in func_text or func_name == "system":
            finding = self._create_finding_from_ast("PY009", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return
        if "os.popen" in func_text or func_name == "popen":
            finding = self._create_finding_from_ast("PY010", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for tempfile.mktemp
        if "mktemp" in func_text:
            finding = self._create_finding_from_ast("PY015", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for open() - potential path traversal
        if func_name == "open":
            arguments = node.child_by_field_name("arguments")
            if arguments:
                first_arg = None
                for child in arguments.children:
                    if child.type not in ("(", ")", ","):
                        first_arg = child
                        break
                if first_arg and self._is_user_input(first_arg, code):
                    finding = self._create_finding_from_ast("PY016", node, code, file_path)
                    if finding:
                        self.findings.append(finding)
                    return

        # Check for hashlib.md5/sha1
        if "hashlib.md5" in func_text or func_name == "md5":
            finding = self._create_finding_from_ast("PY018", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return
        if "hashlib.sha1" in func_text or func_name == "sha1":
            finding = self._create_finding_from_ast("PY019", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for xml.etree.ElementTree.fromstring
        if "fromstring" in func_text and "xml" in func_text.lower():
            finding = self._create_finding_from_ast("PY021", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for ssl._create_unverified_context
        if "_create_unverified_context" in func_text:
            finding = self._create_finding_from_ast("PY022", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for random.random (weak crypto)
        if func_name in ("random", "randint", "choice") and "random" in func_text:
            finding = self._create_finding_from_ast("PY025", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for json.load
        if func_text.endswith(("json.load", "json.loads")):
            finding = self._create_finding_from_ast("PY027", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for Python 2 input()
        if func_name == "input":
            finding = self._create_finding_from_ast("PY020", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

    def _check_assignment(self, node: Any, code: str, file_path: str) -> None:
        """Check assignment statements for vulnerabilities."""
        # Check for debug = True
        text = self._get_node_text(node, code)
        if re.search(r"\b(debug|DEBUG)\s*=\s*True\b", text):
            finding = self._create_finding_from_ast("PY014", node, code, file_path)
            if finding:
                self.findings.append(finding)

    def _is_user_input(self, node: Any, code: str) -> bool:
        """Check if a node represents user input."""
        text = self._get_node_text(node, code)
        user_input_patterns = [
            "request.",
            "input(",
            "sys.argv",
            "input_",
            "user_",
            "params",
            "args",
            "form",
            "query",
        ]
        return any(pattern in text.lower() for pattern in user_input_patterns)

    def _scan_regex(self, file_path: str, code: str) -> None:
        """Scan using regex patterns."""
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Hardcoded passwords
            if self.PATTERNS["hardcoded_password"].search(line):
                if not self._is_likely_false_positive(line):
                    finding = self._create_finding_from_regex(
                        "PY012", line_num, line, code, file_path
                    )
                    if finding:
                        self.findings.append(finding)

            # Hardcoded API keys
            if self.PATTERNS["hardcoded_api_key"].search(line):
                if not self._is_likely_false_positive(line):
                    finding = self._create_finding_from_regex(
                        "PY013", line_num, line, code, file_path
                    )
                    if finding:
                        self.findings.append(finding)

            # Hardcoded JWT secrets
            if self.PATTERNS["hardcoded_jwt_secret"].search(line):
                if not self._is_likely_false_positive(line):
                    finding = self._create_finding_from_regex(
                        "PY024", line_num, line, code, file_path
                    )
                    if finding:
                        self.findings.append(finding)

            # SQL injection via string formatting
            if self._is_sql_injection_risk(line):
                finding = self._create_finding_from_regex("PY004", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # os.system (regex fallback)
            if re.search(r"\bos\.system\s*\(", line):
                finding = self._create_finding_from_regex("PY009", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # commands module
            if re.search(r"\bcommands\.(getoutput|getstatusoutput)\s*\(", line):
                finding = self._create_finding_from_regex("PY011", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # popen2
            if re.search(r"\bpopen2\.", line):
                finding = self._create_finding_from_regex("PY026", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # urllib without verification
            if re.search(r"(?i)(verify\s*=\s*False|cert_reqs\s*=\s*ssl\.CERT_NONE)", line):
                finding = self._create_finding_from_regex("PY023", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

    def _is_sql_injection_risk(self, line: str) -> bool:
        """Check if a line has SQL injection risk via string formatting."""
        has_sql = self.PATTERNS["sql_keywords"].search(line)
        has_formatting = any(
            pattern in line for pattern in [".format(", "%s", "%d", "%(", 'f"', "f'", "+", "{}"]
        )
        is_sql_context = any(
            keyword in line.lower()
            for keyword in ["query", "sql", "select", "insert", "update", "delete", "execute"]
        )
        return bool(has_sql and has_formatting and is_sql_context)

    def _is_likely_false_positive(self, line: str) -> bool:
        """Check if a line is likely a false positive."""
        false_positive_patterns = [
            r"password[_-]?field",
            r"get_password",
            r"set_password",
            r"change_password",
            r"check_password",
            r"encrypt",
            r"hash",
            r"placeholder",
            r"example",
            r"test",
            r"mock",
            r"fake",
            r"dummy",
            r"none",
            r"os\.environ",
            r"getenv",
            r"config\.get",
            r"secrets\.get",
        ]
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in false_positive_patterns)

    def _create_finding_from_ast(
        self, rule_id: str, node: Any, code: str, file_path: str
    ) -> Optional[Finding]:
        """Create a Finding from an AST node."""
        rule = self.RULES.get(rule_id)
        if not rule:
            return None

        lines = code.split("\n")
        line_num = node.start_point[0] + 1
        col_num = node.start_point[1]

        # Get code snippet (up to 3 lines for context)
        start_line = max(0, line_num - 2)
        end_line = min(len(lines), line_num + 1)
        snippet = "\n".join(lines[start_line:end_line])

        return Finding(
            rule_id=rule_id,
            severity=rule["severity"],
            message=rule["message"],
            line=line_num,
            column=col_num,
            code_snippet=snippet,
            remediation=rule["remediation"],
            cwe_id=rule["cwe"],
            file_path=file_path,
        )

    def _create_finding_from_regex(
        self, rule_id: str, line_num: int, line: str, code: str, file_path: str
    ) -> Optional[Finding]:
        """Create a Finding from regex match."""
        rule = self.RULES.get(rule_id)
        if not rule:
            return None

        lines = code.split("\n")
        col_num = line.index(line.strip()) if line.strip() else 0

        # Get code snippet with context
        start_line = max(0, line_num - 2)
        end_line = min(len(lines), line_num + 1)
        snippet = "\n".join(lines[start_line:end_line])

        return Finding(
            rule_id=rule_id,
            severity=rule["severity"],
            message=rule["message"],
            line=line_num,
            column=col_num,
            code_snippet=snippet,
            remediation=rule["remediation"],
            cwe_id=rule["cwe"],
            file_path=file_path,
        )

    def _get_node_text(self, node: Any, code: str) -> str:
        """Get the text content of a node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return code[start_byte:end_byte]

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on location."""
        seen = set()
        unique = []
        for finding in findings:
            key = (finding.file_path, finding.line, finding.column, finding.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return sorted(unique, key=lambda f: (f.file_path, f.line, f.column))


# Convenience function for simple usage
def scan_python(file_path: str, code: str) -> List[Finding]:
    """Scan Python code for security vulnerabilities."""
    detector = PythonSecurityDetector()
    return detector.scan(file_path, code)


# Example usage
if __name__ == "__main__":
    test_code = """
import os
import pickle
import subprocess
import hashlib
import yaml

def process_user_input(user_data):
    # CWE-95: eval usage
    result = eval(user_data)
    
    # CWE-78: os.system with user input
    os.system("echo " + user_data)
    
    # CWE-78: subprocess with shell=True
    subprocess.call(user_data, shell=True)
    
    # CWE-502: pickle deserialization
    data = pickle.loads(user_data)
    
    # CWE-89: SQL injection
    query = "SELECT * FROM users WHERE id = %s" % user_data
    
    # CWE-798: Hardcoded password
    password = "supersecret123"
    
    # CWE-798: Hardcoded API key
    api_key = "sk-1234567890abcdef"
    
    # CWE-327: Insecure hash
    hash_value = hashlib.md5(user_data.encode()).hexdigest()
    
    # CWE-502: yaml unsafe load
    config = yaml.load(user_data)
    
    # CWE-489: Debug mode
    debug = True
    
    assert user_data is not None
"""

    findings = scan_python("test.py", test_code)
    for finding in findings:
        print(f"[{finding.severity.value.upper()}] {finding.rule_id}: {finding.message}")
        print(f"  File: {finding.file_path}:{finding.line}:{finding.column}")
        print(f"  CWE: {finding.cwe_id}")
        print(f"  Remediation: {finding.remediation}")
        print(f"  Code:\n{finding.code_snippet}")
        print("-" * 60)
