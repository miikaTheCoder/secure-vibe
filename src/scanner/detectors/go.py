"""
Go vulnerability detector for Secure Vibe.
Uses tree-sitter for AST parsing when available, falls back to regex patterns.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from .base import BaseDetector


@dataclass
class Finding:
    """Represents a security finding."""

    rule_id: str
    severity: str
    message: str
    line: int
    column: int
    code_snippet: str
    remediation: str
    cwe_id: str
    file_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
        }


class GoDetector(BaseDetector):
    """Detects Go specific vulnerabilities with AST and regex analysis."""

    def __init__(self, rules: Dict[str, Any]):
        super().__init__(rules)
        self.language = "go"
        self.tree_sitter_available = self._check_tree_sitter()
        self._init_patterns()
        self._init_ast_queries()

    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter
            import tree_sitter_go

            return True
        except ImportError:
            return False

    def _init_ast_queries(self):
        """Initialize tree-sitter queries for AST analysis."""
        self.ast_queries = {}
        if self.tree_sitter_available:
            self.ast_queries = {
                "sql_injection": """
                    (call_expression
                      function: (selector_expression
                        operand: (identifier) @_db
                        field: (field_identifier) @_method
                        (#match? @_method "^(Query|Exec|QueryRow|Prepare)$"))
                      arguments: (argument_list
                        . [(call_expression) (binary_expression) (interpreted_string_literal)] @sql_arg))
                """,
                "defer_in_loop": """
                    (for_statement
                      body: (block
                        (defer_statement) @defer))
                """,
                "unsafe_pointer": """
                    (call_expression
                      function: (identifier) @_unsafe
                      (#eq? @_unsafe "Pointer")
                      (argument_list) @unsafe_call)
                """,
            }

    def _init_patterns(self):
        """Initialize detection patterns for regex-based analysis."""
        self.patterns = {
            "sql_concatenation": {
                "pattern": r"(?:Query|Exec|QueryRow|Prepare)\s*\(\s*fmt\.Sprintf",
                "severity": "critical",
                "cwe": "CWE-89",
                "message": "SQL query using fmt.Sprintf - potential SQL injection",
                "remediation": 'Use parameterized queries with placeholders (e.g., db.Query("SELECT * FROM users WHERE id = ?", id))',
                "rule_id": "go-sql-injection-fmt",
            },
            "sql_string_concat": {
                "pattern": r'(?:Query|Exec|QueryRow|Prepare)\s*\(\s*["`]SELECT.*\+',
                "severity": "critical",
                "cwe": "CWE-89",
                "message": "SQL query using string concatenation - potential SQL injection",
                "remediation": "Use parameterized queries with placeholders (?, $1, etc.)",
                "rule_id": "go-sql-injection-concat",
            },
            "sql_format_string": {
                "pattern": r'(?:Query|Exec|QueryRow|Prepare)\s*\(\s*["`].*?%s',
                "severity": "critical",
                "cwe": "CWE-89",
                "message": "SQL query using format strings - potential SQL injection",
                "remediation": "Use parameterized queries with placeholders (?, $1, etc.)",
                "rule_id": "go-sql-injection-format",
            },
            "sql_var_concat": {
                "pattern": r"(?:Query|Exec|QueryRow|Prepare)\s*\(\s*\w+\s*\+",
                "severity": "critical",
                "cwe": "CWE-89",
                "message": "SQL query using variable concatenation - potential SQL injection",
                "remediation": "Use parameterized queries with placeholders",
                "rule_id": "go-sql-injection-var-concat",
            },
            "exec_shell": {
                "pattern": r'exec\.Command(?:Context)?\s*\(\s*[^)]*["\']\s*sh\s*["\']\s*,\s*["\']-c["\']',
                "severity": "critical",
                "cwe": "CWE-78",
                "message": "Command execution through shell can lead to command injection",
                "remediation": "Use exec.Command with array arguments instead of shell",
                "rule_id": "go-exec-shell",
            },
            "exec_concat": {
                "pattern": r"exec\.Command(?:Context)?\s*\([^)]*\+",
                "severity": "critical",
                "cwe": "CWE-78",
                "message": "Command with string concatenation - potential command injection",
                "remediation": "Use exec.Command with array arguments",
                "rule_id": "go-exec-concat",
            },
            "exec_user_input": {
                "pattern": r"exec\.Command(?:Context)?\s*\(\s*(?:r\.(?:FormValue|URL\.Query\(\)\.Get|PostFormValue)|req\.(?:FormValue|PostFormValue)|request\.(?:FormValue|PostFormValue))",
                "severity": "critical",
                "cwe": "CWE-78",
                "message": "exec.Command with user input - potential command injection",
                "remediation": "Validate and sanitize user input before using in commands; use allowlists",
                "rule_id": "go-exec-user-input",
            },
            "insecure_tls": {
                "pattern": r"InsecureSkipVerify\s*:\s*true",
                "severity": "high",
                "cwe": "CWE-295",
                "message": "TLS certificate verification disabled - vulnerable to MITM attacks",
                "remediation": "Set InsecureSkipVerify to false and use proper certificate validation",
                "rule_id": "go-insecure-tls",
            },
            "math_rand_crypto": {
                "pattern": r"\brand\.(?:Int|Intn|Int63|Int31|Float64|Float32)\s*\(",
                "severity": "high",
                "cwe": "CWE-338",
                "message": "math/rand is not cryptographically secure - do not use for tokens, keys, or nonces",
                "remediation": "Use crypto/rand for generating tokens, keys, or nonces",
                "rule_id": "go-weak-random",
            },
            "math_rand_seed": {
                "pattern": r"\brand\.Seed\s*\(",
                "severity": "medium",
                "cwe": "CWE-338",
                "message": "math/rand is seeded - predictable random numbers",
                "remediation": "Use crypto/rand for security-sensitive operations",
                "rule_id": "go-predictable-random",
            },
            "serve_file_traversal": {
                "pattern": r"http\.ServeFile\s*\([^)]*(?:r\.(?:FormValue|URL\.Query)|req\.(?:FormValue|URL\.Query)|request\.(?:FormValue|URL\.Query))",
                "severity": "high",
                "cwe": "CWE-22",
                "message": "http.ServeFile with user input - potential path traversal",
                "remediation": "Validate and sanitize file paths using filepath.Clean() and filepath.IsLocal()",
                "rule_id": "go-path-traversal-servefile",
            },
            "serve_file_var": {
                "pattern": r"http\.ServeFile\s*\([^,]+,\s*[^,]+,\s*\w+",
                "severity": "medium",
                "cwe": "CWE-22",
                "message": "http.ServeFile with variable path - verify path sanitization",
                "remediation": "Validate and sanitize file paths using filepath.Clean() and filepath.IsLocal()",
                "rule_id": "go-path-traversal-servefile-var",
            },
            "weak_crypto_md5": {
                "pattern": r"(?:md5|MD5)\.(?:New|Sum|SumString)",
                "severity": "medium",
                "cwe": "CWE-327",
                "message": "MD5 is cryptographically broken and should not be used",
                "remediation": "Use SHA-256 or SHA-3 for cryptographic purposes",
                "rule_id": "go-weak-crypto-md5",
            },
            "weak_crypto_sha1": {
                "pattern": r"(?:sha1|SHA1)\.(?:New|Sum)",
                "severity": "medium",
                "cwe": "CWE-327",
                "message": "SHA-1 is cryptographically weak and should not be used",
                "remediation": "Use SHA-256 or SHA-3 for cryptographic purposes",
                "rule_id": "go-weak-crypto-sha1",
            },
            "weak_crypto_des": {
                "pattern": r"(?:des|DES)\.(?:NewCipher|NewTripleDESCipher)",
                "severity": "high",
                "cwe": "CWE-327",
                "message": "DES/Triple DES is cryptographically weak and should not be used",
                "remediation": "Use AES-GCM or ChaCha20-Poly1305 for encryption",
                "rule_id": "go-weak-crypto-des",
            },
            "weak_crypto_rc4": {
                "pattern": r"(?:rc4|RC4)\.(?:NewCipher|Cipher)",
                "severity": "high",
                "cwe": "CWE-327",
                "message": "RC4 is cryptographically broken and should not be used",
                "remediation": "Use AES-GCM or ChaCha20-Poly1305 for encryption",
                "rule_id": "go-weak-crypto-rc4",
            },
            "template_html_xss": {
                "pattern": r"template\.HTML\s*\(\s*(?:r\.|req\.|request\.|input|user|data)",
                "severity": "critical",
                "cwe": "CWE-79",
                "message": "template.HTML with user input - potential XSS vulnerability",
                "remediation": "Use html/template with auto-escaping instead of template.HTML; validate and sanitize input",
                "rule_id": "go-xss-template-html",
            },
            "template_html_var": {
                "pattern": r"template\.HTML\s*\(",
                "severity": "high",
                "cwe": "CWE-79",
                "message": "template.HTML usage - ensure content is properly sanitized",
                "remediation": "Use html/template with auto-escaping; avoid template.HTML with untrusted data",
                "rule_id": "go-xss-template-html-usage",
            },
            "file_perm_0777": {
                "pattern": r"(?:os\.Chmod|os\.Mkdir(?:All)?|os\.OpenFile)\s*\([^,]+,\s*[^,]*0?777",
                "severity": "medium",
                "cwe": "CWE-732",
                "message": "File permission 0777 allows read, write, and execute for all users",
                "remediation": "Use more restrictive permissions (e.g., 0755 for directories, 0644 for files)",
                "rule_id": "go-insecure-permissions-777",
            },
            "file_perm_0666": {
                "pattern": r"(?:os\.Chmod|os\.OpenFile)\s*\([^,]+,\s*[^,]*0?666",
                "severity": "low",
                "cwe": "CWE-732",
                "message": "File permission 0666 allows read and write for all users",
                "remediation": "Use more restrictive permissions (e.g., 0644)",
                "rule_id": "go-insecure-permissions-666",
            },
            "json_unmarshal_raw": {
                "pattern": r"json\.Unmarshal\s*\([^,]+,\s*&",
                "severity": "medium",
                "cwe": "CWE-502",
                "message": "json.Unmarshal without validation - potential deserialization issues",
                "remediation": "Validate JSON input before unmarshaling; use struct tags and validation libraries",
                "rule_id": "go-json-unvalidated",
            },
            "http_listen_no_tls": {
                "pattern": r'http\.ListenAndServe\s*\(\s*["\'][^"\']*["\']\s*,\s*[^)]+\)',
                "severity": "medium",
                "cwe": "CWE-319",
                "message": "http.ListenAndServe without TLS - insecure communication",
                "remediation": "Use http.ListenAndServeTLS with proper certificates for production",
                "rule_id": "go-insecure-http",
            },
            "unsafe_pointer": {
                "pattern": r"unsafe\.Pointer\s*\(",
                "severity": "medium",
                "cwe": "CWE-466",
                "message": "unsafe.Pointer usage bypasses Go's type safety - potential memory safety issues",
                "remediation": "Avoid unsafe.Pointer unless absolutely necessary; ensure proper bounds checking",
                "rule_id": "go-unsafe-pointer",
            },
            "unsafe_slice": {
                "pattern": r"unsafe\.Slice\s*\(",
                "severity": "medium",
                "cwe": "CWE-466",
                "message": "unsafe.Slice usage - potential out-of-bounds access",
                "remediation": "Validate length parameter and ensure bounds checking",
                "rule_id": "go-unsafe-slice",
            },
            "bind_all_interfaces": {
                "pattern": r'(?:Listen|ListenTCP|ListenAndServe)\s*\(\s*["\']tcp["\']?\s*,\s*["\']:\d+',
                "severity": "low",
                "cwe": "CWE-1327",
                "message": "Binding to all network interfaces (0.0.0.0)",
                "remediation": "Bind to specific interface (e.g., 127.0.0.1) or configure access controls",
                "rule_id": "go-bind-all-interfaces",
            },
            "error_not_checked": {
                "pattern": r"^\s+(?:db|rows|stmt)\.(?:Query|Exec|Prepare)\s*\([^)]+\)\s*$",
                "severity": "low",
                "cwe": "CWE-391",
                "message": "Database error not checked",
                "remediation": "Always check errors from database operations",
                "rule_id": "go-unchecked-error",
            },
            "insecure_http_get": {
                "pattern": r'http\.Get\s*\(\s*["\']http://',
                "severity": "medium",
                "cwe": "CWE-319",
                "message": "Insecure HTTP request detected",
                "remediation": "Use HTTPS instead of HTTP",
                "rule_id": "go-insecure-http-get",
            },
            "temp_file_race": {
                "pattern": r"ioutil\.TempFile\s*\(",
                "severity": "medium",
                "cwe": "CWE-377",
                "message": "Potential race condition in temporary file creation",
                "remediation": "Ensure proper file permissions and use secure temporary file creation",
                "rule_id": "go-insecure-temp-file",
            },
            "path_traversal_file": {
                "pattern": r"(?:os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*(?:\+|fmt\.Sprintf)",
                "severity": "high",
                "cwe": "CWE-22",
                "message": "Possible path traversal vulnerability",
                "remediation": "Validate and sanitize file paths using filepath.Clean() and filepath.IsLocal()",
                "rule_id": "go-path-traversal-file",
            },
            "syscall_exec": {
                "pattern": r"syscall\.Exec\s*\(",
                "severity": "high",
                "cwe": "CWE-78",
                "message": "syscall.Exec with potentially user-controlled arguments",
                "remediation": "Validate and sanitize all arguments to syscall.Exec",
                "rule_id": "go-syscall-exec",
            },
        }

    def scan(self, file_path: str, code: str) -> List[Dict[str, Any]]:
        """Main scan method - returns list of findings as dictionaries.

        Args:
            file_path: Path to the file being scanned
            code: Source code content

        Returns:
            List of findings as dictionaries
        """
        findings = []

        # Regex-based detections
        findings.extend(self._scan_regex(file_path, code))

        # Secret detection
        findings.extend(self._detect_secrets(file_path, code))

        # Connection string detection
        findings.extend(self._detect_connection_strings(file_path, code))

        # AST-based detections (if tree-sitter available)
        if self.tree_sitter_available:
            findings.extend(self._scan_ast(file_path, code))
        else:
            # Fallback for defer in loop detection
            findings.extend(self._detect_defer_in_loop_fallback(file_path, code))

        return [f.to_dict() for f in findings]

    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Legacy detect method for compatibility with BaseDetector."""
        return self.scan(file_path, code)

    def _scan_regex(self, file_path: str, code: str) -> List[Finding]:
        """Scan using regex patterns."""
        findings = []
        lines = code.split("\n")

        for vuln_type, config in self.patterns.items():
            for match in re.finditer(config["pattern"], code, re.IGNORECASE | re.MULTILINE):
                line_num = code[: match.start()].count("\n") + 1
                col_num = match.start() - code.rfind("\n", 0, match.start())

                line_idx = line_num - 1
                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = match.group(0)

                finding = Finding(
                    rule_id=config.get("rule_id", f"go-{vuln_type}"),
                    severity=config["severity"],
                    message=config["message"],
                    line=line_num,
                    column=col_num,
                    code_snippet=code_snippet,
                    remediation=config["remediation"],
                    cwe_id=config["cwe"],
                    file_path=file_path,
                )
                findings.append(finding)

        return findings

    def _scan_ast(self, file_path: str, code: str) -> List[Finding]:
        """Scan using tree-sitter AST analysis."""
        findings = []

        try:
            from tree_sitter import Language, Parser, Query
            import tree_sitter_go as ts_go

            # Initialize parser
            GO_LANGUAGE = Language(ts_go.language())
            parser = Parser(GO_LANGUAGE)

            tree = parser.parse(bytes(code, "utf8"))
            root_node = tree.root_node

            # Check for defer in loop
            findings.extend(self._ast_check_defer_in_loop(file_path, code, root_node, GO_LANGUAGE))

            # Check for unsafe pointer usage
            findings.extend(self._ast_check_unsafe_pointer(file_path, code, root_node, GO_LANGUAGE))

        except Exception as e:
            # Fallback to regex if AST parsing fails
            pass

        return findings

    def _ast_check_defer_in_loop(
        self, file_path: str, code: str, root_node, language
    ) -> List[Finding]:
        """Check for defer statements inside loops using AST."""
        findings = []
        lines = code.split("\n")

        def traverse(node, in_loop=False):
            if node.type in ("for_statement", "range_clause"):
                in_loop = True

            if in_loop and node.type == "defer_statement":
                start_line = node.start_point[0] + 1
                start_col = node.start_point[1] + 1

                line_idx = start_line - 1
                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = "defer ..."

                finding = Finding(
                    rule_id="go-defer-in-loop",
                    severity="medium",
                    message="defer inside loop - resources may not be released until function returns, causing resource exhaustion",
                    line=start_line,
                    column=start_col,
                    code_snippet=code_snippet,
                    remediation="Move defer outside loop or use an anonymous function closure",
                    cwe_id="CWE-772",
                    file_path=file_path,
                )
                findings.append(finding)

            for child in node.children:
                traverse(child, in_loop)

        traverse(root_node)
        return findings

    def _ast_check_unsafe_pointer(
        self, file_path: str, code: str, root_node, language
    ) -> List[Finding]:
        """Check for unsafe.Pointer usage using AST."""
        findings = []
        lines = code.split("\n")

        def traverse(node):
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and func_node.type == "selector_expression":
                    operand = func_node.child_by_field_name("operand")
                    field = func_node.child_by_field_name("field")

                    if (
                        operand
                        and field
                        and operand.text == b"unsafe"
                        and field.text
                        in [b"Pointer", b"Slice", b"String", b"StringData", b"SliceData"]
                    ):
                        start_line = node.start_point[0] + 1
                        start_col = node.start_point[1] + 1

                        line_idx = start_line - 1
                        if 0 <= line_idx < len(lines):
                            code_snippet = lines[line_idx].strip()
                        else:
                            code_snippet = "unsafe.Pointer(...)"

                        finding = Finding(
                            rule_id="go-unsafe-pointer-ast",
                            severity="medium",
                            message=f"unsafe.{field.text.decode()} bypasses Go's type safety - potential memory safety issues",
                            line=start_line,
                            column=start_col,
                            code_snippet=code_snippet,
                            remediation="Avoid unsafe package unless absolutely necessary; ensure proper bounds checking",
                            cwe_id="CWE-466",
                            file_path=file_path,
                        )
                        findings.append(finding)

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return findings

    def _detect_secrets(self, file_path: str, code: str) -> List[Finding]:
        """Detect hardcoded secrets and tokens."""
        findings = []
        lines = code.split("\n")

        secret_patterns = [
            {
                "pattern": r'(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["`]([a-zA-Z0-9_\-]{16,})["`]',
                "message": "Hardcoded API key detected",
                "rule_id": "go-hardcoded-api-key",
                "severity": "high",
            },
            {
                "pattern": r'(?:password|passwd|pwd|Password|PASSWORD)\s*[:=]\s*["`]([^"`]{3,})["`]',
                "message": "Hardcoded password detected",
                "rule_id": "go-hardcoded-password",
                "severity": "critical",
            },
            {
                "pattern": r'(?:secret|Secret|SECRET|token|Token|TOKEN)\s*[:=]\s*["`]([a-zA-Z0-9_\-\.]{16,})["`]',
                "message": "Hardcoded secret/token detected",
                "rule_id": "go-hardcoded-secret",
                "severity": "high",
            },
            {
                "pattern": r'(?:private[_-]?key|privateKey|PRIVATE_KEY)\s*[:=]\s*["`]([^"`]{20,})["`]',
                "message": "Hardcoded private key detected",
                "rule_id": "go-hardcoded-private-key",
                "severity": "critical",
            },
            {
                "pattern": r"sk-[a-zA-Z0-]{20,}",
                "message": "OpenAI API key detected",
                "rule_id": "go-openai-api-key",
                "severity": "high",
            },
            {
                "pattern": r"gh[pousr]_[a-zA-Z0-9]{36,}",
                "message": "GitHub token detected",
                "rule_id": "go-github-token",
                "severity": "high",
            },
            {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "message": "AWS Access Key ID detected",
                "rule_id": "go-aws-access-key",
                "severity": "high",
            },
            {
                "pattern": r'["\']?[a-f0-9]{32}["\']?',
                "message": "Potential MD5 hash or API key detected",
                "rule_id": "go-potential-secret",
                "severity": "low",
            },
        ]

        for config in secret_patterns:
            for match in re.finditer(config["pattern"], code, re.IGNORECASE):
                line_num = code[: match.start()].count("\n") + 1
                line_idx = line_num - 1
                col_num = match.start() - code.rfind("\n", 0, match.start())

                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = match.group(0)

                # Mask the secret value
                masked_snippet = re.sub(r'["`][^"`]+["`]', "`***REDACTED***`", code_snippet)

                finding = Finding(
                    rule_id=config["rule_id"],
                    severity=config["severity"],
                    message=config["message"],
                    line=line_num,
                    column=col_num,
                    code_snippet=masked_snippet,
                    remediation='Use environment variables (e.g., os.Getenv("SECRET_NAME")) or a secrets manager',
                    cwe_id="CWE-798",
                    file_path=file_path,
                )
                findings.append(finding)

        return findings

    def _detect_connection_strings(self, file_path: str, code: str) -> List[Finding]:
        """Detect hardcoded credentials in connection strings."""
        findings = []
        lines = code.split("\n")

        conn_patterns = [
            {
                "pattern": r'["`](?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^"`]+["`]',
                "message": "Hardcoded database connection string with credentials",
                "rule_id": "go-hardcoded-db-conn",
                "severity": "critical",
            },
            {
                "pattern": r'(?:connection[_-]?string|conn[_-]?str|dsn)\s*[:=]\s*["`][^"`]*password=[^"`&]+["`]',
                "message": "Hardcoded connection string with password",
                "rule_id": "go-hardcoded-conn-string",
                "severity": "critical",
            },
            {
                "pattern": r'dsn\s*:=\s*["`][^"`]*:[^"`]*@tcp\(',
                "message": "Hardcoded MySQL DSN with credentials",
                "rule_id": "go-hardcoded-mysql-dsn",
                "severity": "critical",
            },
        ]

        for config in conn_patterns:
            for match in re.finditer(config["pattern"], code, re.IGNORECASE):
                line_num = code[: match.start()].count("\n") + 1
                line_idx = line_num - 1
                col_num = match.start() - code.rfind("\n", 0, match.start())

                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = match.group(0)

                # Mask credentials
                masked_snippet = re.sub(r":[^@]+@", ":***@", code_snippet)

                finding = Finding(
                    rule_id=config["rule_id"],
                    severity=config["severity"],
                    message=config["message"],
                    line=line_num,
                    column=col_num,
                    code_snippet=masked_snippet,
                    remediation="Use environment variables or a secrets manager for connection credentials",
                    cwe_id="CWE-798",
                    file_path=file_path,
                )
                findings.append(finding)

        return findings

    def _detect_defer_in_loop_fallback(self, file_path: str, code: str) -> List[Finding]:
        """Fallback method to detect defer in loops using regex."""
        findings = []
        lines = code.split("\n")

        in_for_loop = False
        brace_count = 0
        loop_start_line = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect for loop start
            if re.match(r"^\s*for\s", stripped):
                in_for_loop = True
                brace_count = stripped.count("{")
                loop_start_line = i + 1
                continue

            if in_for_loop:
                brace_count += stripped.count("{")
                brace_count -= stripped.count("}")

                # Check for defer in loop
                if "defer " in stripped and brace_count > 0:
                    col = line.find("defer") + 1
                    finding = Finding(
                        rule_id="go-defer-in-loop",
                        severity="medium",
                        message="defer inside loop - resources may not be released until function returns, causing resource exhaustion",
                        line=i + 1,
                        column=col,
                        code_snippet=stripped,
                        remediation="Move defer outside loop or use an anonymous function closure",
                        cwe_id="CWE-772",
                        file_path=file_path,
                    )
                    findings.append(finding)

                # End of loop
                if brace_count == 0 and stripped.endswith("}"):
                    in_for_loop = False

        return findings
