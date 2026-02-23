"""
JavaScript/TypeScript vulnerability detector for Secure Vibe.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseDetector, Finding, Severity


class JavaScriptDetector(BaseDetector):
    """Detects JavaScript/TypeScript specific vulnerabilities."""

    name = "JavaScript/TypeScript Vulnerability Detector"
    language = "javascript"

    # Tree-sitter availability
    try:
        from tree_sitter import Language, Parser
        from tree_sitter_javascript import language as js_language

        HAVE_TREE_SITTER = True
    except ImportError:
        HAVE_TREE_SITTER = False

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        super().__init__(rules)
        self.language = "javascript"
        self.parser = None
        if self.HAVE_TREE_SITTER:
            try:
                from tree_sitter import Language, Parser
                from tree_sitter_javascript import language as js_language

                JS_LANGUAGE = Language(js_language())
                self.parser = Parser(JS_LANGUAGE)
            except Exception:
                pass
        self._init_patterns()

    def _init_patterns(self):
        """Initialize detection patterns."""
        self.patterns = {
            "eval_usage": {
                "pattern": r"\beval\s*\(",
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-95",
                "message": "Use of eval() can lead to code injection",
                "remediation": "Use JSON.parse() for JSON data or avoid dynamic code execution",
                "auto_fixable": False,
            },
            "new_function": {
                "pattern": r"new\s+Function\s*\(",
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-95",
                "message": "Use of new Function() is similar to eval() and can lead to code injection",
                "remediation": "Avoid new Function(). Use safer alternatives or thoroughly sanitize dynamic code generation.",
                "auto_fixable": False,
            },
            "innerhtml_xss": {
                "pattern": r"\.(innerHTML|outerHTML)\s*=",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-79",
                "message": "innerHTML/outerHTML assignment can lead to XSS vulnerabilities",
                "remediation": "Use textContent or sanitize input with DOMPurify",
                "auto_fixable": True,
            },
            "document_write": {
                "pattern": r"document\.(write|writeln)\s*\(",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-79",
                "message": "document.write/writeln can lead to XSS vulnerabilities",
                "remediation": "Use DOM manipulation methods like createElement() and appendChild() instead",
                "auto_fixable": False,
            },
            "sql_injection": {
                "pattern": r'(?:query|exec|execute)\s*\(\s*[`\'"].*?\$\{.*?\}',
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-89",
                "message": "Possible SQL injection through string interpolation",
                "remediation": "Use parameterized queries or prepared statements",
                "auto_fixable": False,
            },
            "sql_concatenation": {
                "pattern": r"(?:query|exec|execute)\s*\([^)]*\+",
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-89",
                "message": "Possible SQL injection through string concatenation",
                "remediation": "Use parameterized queries or prepared statements",
                "auto_fixable": False,
            },
            "insecure_random": {
                "pattern": r"\bMath\.random\s*\(",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-338",
                "message": "Math.random() is not cryptographically secure",
                "remediation": "Use crypto.getRandomValues() for security-sensitive operations",
                "auto_fixable": True,
            },
            "prototype_pollution": {
                "pattern": r'\[\s*[\'"]__proto__[\'"]\s*\]|\[\s*[\'"]constructor[\'"]\s*\]\.prototype',
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-915",
                "message": "Possible prototype pollution vulnerability",
                "remediation": "Use Object.freeze(), validate property keys, or use Object.create(null)",
                "auto_fixable": False,
            },
            "insecure_http": {
                "pattern": r'["\']http://[^"\']+["\']',
                "severity": Severity.MEDIUM,
                "cwe_id": "CWE-319",
                "message": "Insecure HTTP URL detected",
                "remediation": "Use HTTPS instead of HTTP",
                "auto_fixable": True,
            },
            "path_traversal": {
                "pattern": r"readFile(?:Sync)?\s*\([^)]*\+",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-22",
                "message": "Possible path traversal vulnerability",
                "remediation": "Validate and sanitize file paths, use path.resolve()",
                "auto_fixable": False,
            },
            "child_process_exec": {
                "pattern": r"(?:exec|execSync)\s*\([^)]*\+",
                "severity": Severity.CRITICAL,
                "cwe_id": "CWE-78",
                "message": "Command injection through string concatenation",
                "remediation": "Use execFile() with array arguments instead of string concatenation",
                "auto_fixable": False,
            },
            "timer_with_string": {
                "pattern": r"(?:setTimeout|setInterval)\s*\(\s*['\"`].+['\"`]",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-95",
                "message": "setTimeout/setInterval with string argument acts like eval()",
                "remediation": "Use function reference instead of string",
                "auto_fixable": True,
            },
            "dangerously_set_inner_html": {
                "pattern": r"dangerouslySetInnerHTML",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-79",
                "message": "dangerouslySetInnerHTML can lead to XSS if content is not sanitized",
                "remediation": "Ensure HTML content is sanitized using DOMPurify before using dangerouslySetInnerHTML",
                "auto_fixable": False,
            },
            "postmessage_no_origin": {
                "pattern": r"addEventListener\s*\(\s*['\"]message['\"]",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-345",
                "message": "postMessage handler without origin verification",
                "remediation": "Always verify event.origin in message event handlers before processing data",
                "auto_fixable": False,
            },
            "localstorage_secrets": {
                "pattern": r"(?:localStorage|sessionStorage)\.(?:setItem|[^)]+\s*=)",
                "severity": Severity.MEDIUM,
                "cwe_id": "CWE-312",
                "message": "Sensitive data stored in localStorage/sessionStorage",
                "remediation": "Avoid storing sensitive data in localStorage. Use secure httpOnly cookies",
                "auto_fixable": False,
            },
            "md5_usage": {
                "pattern": r"(?:require|import).*?(?:md5|sha1)\b",
                "severity": Severity.MEDIUM,
                "cwe_id": "CWE-327",
                "message": "Use of deprecated/insecure hashing algorithm",
                "remediation": "Use modern alternatives like bcrypt, argon2, or native crypto module",
                "auto_fixable": False,
            },
        }

    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect JavaScript vulnerabilities."""
        self.findings = []

        # Try AST-based detection first
        if self.parser:
            self._scan_with_ast(file_path, code)

        # Regex-based detection as fallback/supplement
        self._scan_with_regex(file_path, code)

        # Check for hardcoded secrets
        self._detect_secrets(code, file_path)

        return [f.to_dict() for f in self.findings]

    def scan(self, file_path: str, code: str) -> List[Finding]:
        """Scan code for vulnerabilities and return list of findings."""
        self.findings = []
        self.detect(code, file_path)
        return self.findings

    def _scan_with_ast(self, file_path: str, code: str) -> None:
        """Scan using tree-sitter AST parsing."""
        try:
            tree = self.parser.parse(code.encode())
            root = tree.root_node
            self._walk_ast(file_path, code, root)
        except Exception:
            pass

    def _walk_ast(self, file_path: str, code: str, node: Any, depth: int = 0) -> None:
        """Recursively walk AST nodes."""
        if node is None:
            return

        node_type = node.type

        # Check for eval() calls
        if node_type == "call_expression":
            self._check_eval_call(file_path, code, node)
            self._check_dangerous_functions(file_path, code, node)
            self._check_sql_queries(file_path, code, node)
            self._check_child_process(file_path, code, node)
            self._check_math_random(file_path, code, node)
            self._check_json_parse(file_path, code, node)

        # Check for dangerous property assignments
        if node_type == "assignment_expression":
            self._check_innerhtml_assignment(file_path, code, node)
            self._check_prototype_pollution(file_path, code, node)

        # Check for member expressions (e.g., document.write)
        if node_type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node and func_node.type == "member_expression":
                self._check_document_write(file_path, code, node, func_node)

        # Check for JSX/React specific patterns
        if node_type == "jsx_attribute":
            self._check_dangerously_set_inner_html_ast(file_path, code, node)

        # Recurse into children
        for child in node.children:
            self._walk_ast(file_path, code, child, depth + 1)

    def _get_node_text(self, code: str, node: Any) -> str:
        """Extract text from AST node."""
        return code[node.start_byte : node.end_byte]

    def _get_location(self, node: Any) -> Tuple[int, int]:
        """Get line and column from node."""
        return (node.start_point[0] + 1, node.start_point[1] + 1)

    def _check_eval_call(self, file_path: str, code: str, node: Any) -> None:
        """Detect eval() and new Function() calls."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)

        # Check for eval
        if func_text == "eval":
            line, col = self._get_location(node)
            snippet = self.get_snippet(code, line)
            self.add_finding(
                rule_id="JS-EVAL-001",
                severity=Severity.CRITICAL,
                message="Use of eval() detected. This can lead to code injection attacks.",
                line=line,
                column=col,
                code_snippet=snippet,
                remediation="Avoid eval(). Use safer alternatives like JSON.parse() for data parsing, or sanitize input thoroughly if absolutely necessary.",
                cwe_id="CWE-95",
                file_path=file_path,
            )

        # Check for new Function()
        parent = node.parent
        if func_text == "Function" or (
            parent and parent.type == "new_expression" and "Function" in func_text
        ):
            line, col = self._get_location(node)
            snippet = self.get_snippet(code, line)
            self.add_finding(
                rule_id="JS-EVAL-002",
                severity=Severity.CRITICAL,
                message="Use of new Function() detected. This is similar to eval() and can lead to code injection.",
                line=line,
                column=col,
                code_snippet=snippet,
                remediation="Avoid new Function(). Use safer alternatives or thoroughly sanitize dynamic code generation.",
                cwe_id="CWE-95",
                file_path=file_path,
            )

    def _check_dangerous_functions(self, file_path: str, code: str, node: Any) -> None:
        """Detect dangerous function calls."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)
        line, col = self._get_location(node)
        snippet = self.get_snippet(code, line)

        # Check for setTimeout/setInterval with string
        if func_text in ("setTimeout", "setInterval"):
            args = node.child_by_field_name("arguments")
            if args and args.child_count > 0:
                first_arg = args.children[0]
                if first_arg.type in ("string", "template_string"):
                    self.add_finding(
                        rule_id="JS-TIMER-001",
                        severity=Severity.HIGH,
                        message=f"Use of {func_text}() with string argument detected. This executes code like eval().",
                        line=line,
                        column=col,
                        code_snippet=snippet,
                        remediation=f"Use a function reference instead: {func_text}(function() {{ ... }}, delay).",
                        cwe_id="CWE-95",
                        file_path=file_path,
                    )

    def _check_innerhtml_assignment(self, file_path: str, code: str, node: Any) -> None:
        """Detect innerHTML/outerHTML assignments."""
        left = node.child_by_field_name("left")
        if not left:
            return

        left_text = self._get_node_text(code, left)

        if ".innerHTML" in left_text or ".outerHTML" in left_text:
            right = node.child_by_field_name("right")
            if right and right.type != "string":
                line, col = self._get_location(node)
                snippet = self.get_snippet(code, line)
                prop = "innerHTML" if ".innerHTML" in left_text else "outerHTML"
                self.add_finding(
                    rule_id="JS-XSS-001",
                    severity=Severity.HIGH,
                    message=f"Potential XSS via {prop} assignment with dynamic content",
                    line=line,
                    column=col,
                    code_snippet=snippet,
                    remediation=f"Use textContent instead of {prop}, or sanitize HTML using DOMPurify.",
                    cwe_id="CWE-79",
                    file_path=file_path,
                )

    def _check_document_write(self, file_path: str, code: str, node: Any, func_node: Any) -> None:
        """Detect document.write/writeln calls."""
        func_text = self._get_node_text(code, func_node)

        if "document.write" in func_text or "document.writeln" in func_text:
            line, col = self._get_location(node)
            snippet = self.get_snippet(code, line)
            self.add_finding(
                rule_id="JS-XSS-002",
                severity=Severity.HIGH,
                message="document.write/writeln can lead to XSS vulnerabilities",
                line=line,
                column=col,
                code_snippet=snippet,
                remediation="Use DOM methods like createElement() and appendChild() instead. Avoid document.write().",
                cwe_id="CWE-79",
                file_path=file_path,
            )

    def _check_sql_queries(self, file_path: str, code: str, node: Any) -> None:
        """Detect potential SQL injection."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)

        # Check for common SQL method names
        sql_methods = ["query", "execute", "run", "exec", "prepare", "all", "get"]
        if any(method in func_text for method in sql_methods):
            args = node.child_by_field_name("arguments")
            if args:
                for arg in args.children:
                    if arg.type in ("template_string", "binary_expression"):
                        arg_text = self._get_node_text(code, arg)
                        if "${" in arg_text or "+" in arg_text:
                            line, col = self._get_location(node)
                            snippet = self.get_snippet(code, line)
                            self.add_finding(
                                rule_id="JS-SQLI-001",
                                severity=Severity.CRITICAL,
                                message="Potential SQL injection via string concatenation",
                                line=line,
                                column=col,
                                code_snippet=snippet,
                                remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
                                cwe_id="CWE-89",
                                file_path=file_path,
                            )
                            break

    def _check_child_process(self, file_path: str, code: str, node: Any) -> None:
        """Detect dangerous child_process usage."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)

        # Check for exec/execSync with dynamic input
        if "exec" in func_text or "execSync" in func_text:
            args = node.child_by_field_name("arguments")
            if args:
                for arg in args.children:
                    if arg.type in ("template_string", "binary_expression", "identifier"):
                        line, col = self._get_location(node)
                        snippet = self.get_snippet(code, line)
                        self.add_finding(
                            rule_id="JS-EXEC-001",
                            severity=Severity.CRITICAL,
                            message="Potential command injection via child_process.exec/execSync",
                            line=line,
                            column=col,
                            code_snippet=snippet,
                            remediation="Use child_process.spawn() or execFile() with array args. Avoid exec() with dynamic input.",
                            cwe_id="CWE-78",
                            file_path=file_path,
                        )
                        break

    def _check_math_random(self, file_path: str, code: str, node: Any) -> None:
        """Detect Math.random() used for cryptographic purposes."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)

        if "Math.random" in func_text:
            # Check context - look for crypto-related variable names
            parent = node.parent
            context_text = self._get_node_text(code, parent) if parent else ""
            crypto_keywords = [
                "token",
                "password",
                "secret",
                "key",
                "salt",
                "nonce",
                "uuid",
                "id",
                "random",
            ]

            if any(keyword in context_text.lower() for keyword in crypto_keywords):
                line, col = self._get_location(node)
                snippet = self.get_snippet(code, line)
                self.add_finding(
                    rule_id="JS-CRYPTO-001",
                    severity=Severity.HIGH,
                    message="Math.random() should not be used for cryptographic purposes",
                    line=line,
                    column=col,
                    code_snippet=snippet,
                    remediation="Use crypto.randomBytes() or crypto.getRandomValues() for secure random generation.",
                    cwe_id="CWE-338",
                    file_path=file_path,
                )

    def _check_json_parse(self, file_path: str, code: str, node: Any) -> None:
        """Detect JSON.parse without try-catch."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(code, func_node)

        if func_text == "JSON.parse":
            # Check if inside try block
            current = node.parent
            in_try = False
            while current:
                if current.type == "try_statement":
                    in_try = True
                    break
                current = current.parent

            if not in_try:
                line, col = self._get_location(node)
                snippet = self.get_snippet(code, line)
                self.add_finding(
                    rule_id="JS-JSON-001",
                    severity=Severity.MEDIUM,
                    message="JSON.parse() without try-catch can crash on malformed input",
                    line=line,
                    column=col,
                    code_snippet=snippet,
                    remediation="Wrap JSON.parse() in try-catch to handle parsing errors gracefully.",
                    cwe_id="CWE-248",
                    file_path=file_path,
                )

    def _check_prototype_pollution(self, file_path: str, code: str, node: Any) -> None:
        """Detect potential prototype pollution."""
        left = node.child_by_field_name("left")
        if not left:
            return

        left_text = self._get_node_text(code, left)

        if "__proto__" in left_text or "constructor.prototype" in left_text:
            line, col = self._get_location(node)
            snippet = self.get_snippet(code, line)
            self.add_finding(
                rule_id="JS-PROTO-001",
                severity=Severity.CRITICAL,
                message="Potential prototype pollution vulnerability detected",
                line=line,
                column=col,
                code_snippet=snippet,
                remediation="Avoid modifying __proto__ or constructor.prototype. Use Object.create() for inheritance.",
                cwe_id="CWE-915",
                file_path=file_path,
            )

    def _check_dangerously_set_inner_html_ast(self, file_path: str, code: str, node: Any) -> None:
        """Detect dangerouslySetInnerHTML in React via AST."""
        attr_name = None
        for child in node.children:
            if child.type == "property_identifier":
                attr_name = self._get_node_text(code, child)
                break

        if attr_name == "dangerouslySetInnerHTML":
            line, col = self._get_location(node)
            snippet = self.get_snippet(code, line)
            self.add_finding(
                rule_id="JS-REACT-001",
                severity=Severity.HIGH,
                message="dangerouslySetInnerHTML can lead to XSS if content is not sanitized",
                line=line,
                column=col,
                code_snippet=snippet,
                remediation="Ensure HTML content is sanitized using DOMPurify before using dangerouslySetInnerHTML.",
                cwe_id="CWE-79",
                file_path=file_path,
            )

    def _scan_with_regex(self, file_path: str, code: str) -> None:
        """Scan using regex patterns for additional detections."""
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            self._check_regex_patterns(file_path, code, line, line_num)
            self._check_redos(file_path, code, line, line_num)

    def _check_regex_patterns(self, file_path: str, code: str, line: str, line_num: int) -> None:
        """Apply regex-based pattern detection."""
        for pattern_name, config in self.patterns.items():
            for match in re.finditer(config["pattern"], line, re.IGNORECASE):
                col_num = match.start() + 1
                snippet = self.get_snippet(code, line_num)

                # Generate fixed code if auto-fixable
                fixed_code = None
                if config.get("auto_fixable"):
                    fixed_code = self._generate_fix(line, pattern_name)

                self.add_finding(
                    rule_id=f"JS-{pattern_name.upper().replace('_', '-')}",
                    severity=config["severity"],
                    message=config["message"],
                    line=line_num,
                    column=col_num,
                    code_snippet=snippet,
                    remediation=config["remediation"],
                    cwe_id=config["cwe_id"],
                    file_path=file_path,
                    auto_fixable=config.get("auto_fixable", False),
                    fixed_code=fixed_code,
                )

    def _check_redos(self, file_path: str, code: str, line: str, line_num: int) -> None:
        """Detect potentially vulnerable regex patterns (ReDoS)."""
        # Check for regex literals with nested quantifiers
        regex_patterns = [
            r"\(.*\+.*\*.*\)",  # (a+)* pattern
            r"\(.*\*.*\+.*\)",  # (a*)+ pattern
            r"\(.*\+.*\).*\+",  # Nested quantifiers with +
            r"\(.*\*.*\).*\*",  # Nested quantifiers with *
        ]

        # Check for regex literals
        if re.search(r"\/[^/]+\/[gimuy]*", line):
            for pattern in regex_patterns:
                if re.search(pattern, line):
                    snippet = self.get_snippet(code, line_num)
                    self.add_finding(
                        rule_id="JS-REGEX-001",
                        severity=Severity.MEDIUM,
                        message="Potential ReDoS vulnerability in regular expression",
                        line=line_num,
                        column=1,
                        code_snippet=snippet,
                        remediation="Avoid nested quantifiers (+, *, {n,}) that can cause catastrophic backtracking. Use atomic groups.",
                        cwe_id="CWE-400",
                        file_path=file_path,
                    )
                    break

    def _detect_secrets(self, code: str, file_path: str) -> None:
        """Detect hardcoded secrets in JavaScript code."""
        lines = code.split("\n")

        secret_patterns = [
            (
                r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'`]([a-zA-Z0-9_\-]{16,})["\'`]',
                "Hardcoded API key detected",
            ),
            (
                r'(?:password|passwd|pwd)\s*[=:]\s*["\'`]([^"\'`]+)["\'`]',
                "Hardcoded password detected",
            ),
            (
                r'(?:secret|token)\s*[=:]\s*["\'`]([a-zA-Z0-9_\-\.]{16,})["\'`]',
                "Hardcoded secret/token detected",
            ),
            (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key detected"),
            (
                r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
                "JWT token pattern detected",
            ),
        ]

        for pattern, description in secret_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[: match.start()].count("\n") + 1
                line_idx = line_num - 1

                if 0 <= line_idx < len(lines):
                    code_snippet = lines[line_idx].strip()
                else:
                    code_snippet = match.group(0)

                # Mask the secret value in the code snippet
                masked_snippet = re.sub(r'["\'`][^"\'`]+["\'`]', '"***REDACTED***"', code_snippet)

                col_num = match.start() - code.rfind("\n", 0, match.start()) + 1

                self.add_finding(
                    rule_id="JS-HARDCODED-SECRET",
                    severity=Severity.HIGH,
                    message=description,
                    line=line_num,
                    column=col_num,
                    code_snippet=masked_snippet,
                    remediation="Use environment variables or a secrets manager (e.g., process.env.API_KEY)",
                    cwe_id="CWE-798",
                    file_path=file_path,
                    auto_fixable=True,
                    fixed_code=self._generate_secret_fix(code_snippet),
                )

    def _generate_fix(self, code_snippet: str, vuln_type: str) -> Optional[str]:
        """Generate a fix for auto-fixable vulnerabilities."""
        if vuln_type == "innerhtml_xss" or "innerHTML" in vuln_type:
            return code_snippet.replace("innerHTML", "textContent")
        elif vuln_type == "insecure_random":
            return code_snippet.replace(
                "Math.random()", "crypto.getRandomValues(new Uint32Array(1))[0] / 2**32"
            )
        elif vuln_type == "insecure_http":
            return code_snippet.replace("http://", "https://")
        elif vuln_type == "timer_with_string":
            return code_snippet.replace("'", "() => ").replace('"', "() => ")
        return None

    def _generate_secret_fix(self, code_snippet: str) -> str:
        """Generate a fix for hardcoded secrets."""
        # Extract variable name
        match = re.search(r"(\w+)\s*[=:]", code_snippet)
        if match:
            var_name = match.group(1).upper()
            return f"const {var_name} = process.env.{var_name};"
        return code_snippet
