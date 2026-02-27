"""
Rust Security Vulnerability Detector

Uses tree-sitter-rust for AST parsing when available, falls back to regex patterns.
Detects various security vulnerabilities in Rust code.
"""

import re
from typing import Any, Dict, List, Optional

from .base import BaseDetector, Finding, Severity

# Try to import tree-sitter, fallback to regex-only if not available
try:
    from tree_sitter import Language as TSLanguage, Parser as TSParser
    import tree_sitter_rust as tsrust

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
    TSLanguage = None  # type: ignore
    TSParser = None  # type: ignore
    tsrust = None  # type: ignore


class RustSecurityDetector(BaseDetector):
    """
    Detects security vulnerabilities in Rust code.
    Uses tree-sitter for AST-based detection and regex for pattern matching.
    """

    # Rule definitions with all required fields
    RULES = {
        "RS001": {
            "name": "unsafe-block-usage",
            "severity": Severity.HIGH,
            "message": "Usage of unsafe block detected. Unsafe blocks bypass Rust's memory safety guarantees.",
            "cwe": "CWE-758",
            "remediation": "Minimize unsafe code. Document safety invariants and use safe abstractions when possible.",
        },
        "RS002": {
            "name": "unsafe-function-usage",
            "severity": Severity.HIGH,
            "message": "Usage of unsafe function detected. Unsafe functions require unsafe blocks to call.",
            "cwe": "CWE-758",
            "remediation": "Avoid unsafe functions unless absolutely necessary. Ensure all safety preconditions are met.",
        },
        "RS003": {
            "name": "raw-pointer-dereference",
            "severity": Severity.CRITICAL,
            "message": "Raw pointer dereference detected. This is undefined behavior if the pointer is invalid.",
            "cwe": "CWE-476",
            "remediation": "Validate pointers before dereferencing. Consider using safe alternatives like references or Box.",
        },
        "RS004": {
            "name": "sql-injection-string-format",
            "severity": Severity.CRITICAL,
            "message": "Potential SQL injection via string formatting detected.",
            "cwe": "CWE-89",
            "remediation": "Use parameterized queries with prepared statements. Use sqlx or similar libraries with compile-time query checking.",
        },
        "RS005": {
            "name": "sql-injection-format-macro",
            "severity": Severity.CRITICAL,
            "message": "Potential SQL injection via format! macro detected.",
            "cwe": "CWE-89",
            "remediation": "Use parameterized queries. Avoid building SQL queries with format! or string concatenation.",
        },
        "RS006": {
            "name": "command-injection",
            "severity": Severity.CRITICAL,
            "message": "Potential command injection via user input in command execution.",
            "cwe": "CWE-78",
            "remediation": "Use Command::arg() instead of Command::new() with shell. Validate and sanitize all user inputs.",
        },
        "RS007": {
            "name": "std-process-command-shell",
            "severity": Severity.HIGH,
            "message": "Usage of std::process::Command with shell execution detected.",
            "cwe": "CWE-78",
            "remediation": "Use Command::arg() and Command::args() instead of shell execution. Never pass user input to shell commands.",
        },
        "RS008": {
            "name": "path-traversal-file-open",
            "severity": Severity.HIGH,
            "message": "Potential path traversal vulnerability in file operations.",
            "cwe": "CWE-22",
            "remediation": "Validate file paths using std::path::Path::is_relative() and ensure paths don't escape intended directories.",
        },
        "RS009": {
            "name": "panic-on-user-input",
            "severity": Severity.HIGH,
            "message": "panic!() with user input detected - potential denial of service.",
            "cwe": "CWE-400",
            "remediation": "Use proper error handling (Result) instead of panic. Log errors gracefully.",
        },
        "RS010": {
            "name": "unwrap-on-result",
            "severity": Severity.MEDIUM,
            "message": "unwrap() on Result detected - may panic on error.",
            "cwe": "CWE-754",
            "remediation": "Use proper error handling: match, if let, or ? operator. Use unwrap_or/unwrap_or_else for defaults.",
        },
        "RS011": {
            "name": "expect-on-result",
            "severity": Severity.MEDIUM,
            "message": "expect() on Result detected - may panic with custom message on error.",
            "cwe": "CWE-754",
            "remediation": "Use proper error handling. Only use expect() for truly unreachable cases with a meaningful message.",
        },
        "RS012": {
            "name": "unwrap-on-option",
            "severity": Severity.MEDIUM,
            "message": "unwrap() on Option detected - may panic on None.",
            "cwe": "CWE-754",
            "remediation": "Use proper error handling: match, if let, or ? operator. Consider unwrap_or/unwrap_or_else.",
        },
        "RS013": {
            "name": "hardcoded-password",
            "severity": Severity.CRITICAL,
            "message": "Hardcoded password or secret detected.",
            "cwe": "CWE-798",
            "remediation": "Use environment variables, secret management services, or encrypted configuration files.",
        },
        "RS014": {
            "name": "hardcoded-api-key",
            "severity": Severity.CRITICAL,
            "message": "Hardcoded API key detected.",
            "cwe": "CWE-798",
            "remediation": "Use environment variables or secret management services. Never commit API keys to version control.",
        },
        "RS015": {
            "name": "insecure-tls-verify-disabled",
            "severity": Severity.HIGH,
            "message": "TLS certificate verification disabled - vulnerable to MITM attacks.",
            "cwe": "CWE-295",
            "remediation": "Never disable TLS verification in production. Use proper certificate validation.",
        },
        "RS016": {
            "name": "weak-random-number-generator",
            "severity": Severity.HIGH,
            "message": "Weak random number generator used for cryptographic purposes.",
            "cwe": "CWE-338",
            "remediation": "Use rand::rngs::OsRng or rand::thread_rng() from the rand crate for cryptographic randomness.",
        },
        "RS017": {
            "name": "insecure-hash-md5",
            "severity": Severity.MEDIUM,
            "message": "Insecure hash algorithm: MD5 detected. MD5 is cryptographically broken.",
            "cwe": "CWE-327",
            "remediation": "Use SHA-256 (sha2 crate) or stronger algorithms for cryptographic purposes.",
        },
        "RS018": {
            "name": "insecure-hash-sha1",
            "severity": Severity.MEDIUM,
            "message": "Insecure hash algorithm: SHA1 detected. SHA1 is cryptographically broken.",
            "cwe": "CWE-327",
            "remediation": "Use SHA-256 (sha2 crate) or stronger algorithms for cryptographic purposes.",
        },
        "RS019": {
            "name": "deserialization-without-validation",
            "severity": Severity.HIGH,
            "message": "Deserialization detected without apparent input validation.",
            "cwe": "CWE-502",
            "remediation": "Validate all deserialized data. Use serde with deny_unknown_fields. Consider using a schema validator.",
        },
        "RS020": {
            "name": "debug-assertions",
            "severity": Severity.LOW,
            "message": "debug_assert! or debug_assert_eq! detected - removed in release builds.",
            "cwe": "CWE-617",
            "remediation": "Use assert! for security-critical checks that must run in all build configurations.",
        },
        "RS021": {
            "name": "insecure-temporary-file",
            "severity": Severity.MEDIUM,
            "message": "Insecure temporary file creation pattern detected.",
            "cwe": "CWE-377",
            "remediation": "Use tempfile crate or std::env::temp_dir() with proper permissions.",
        },
        "RS022": {
            "name": "dangerous-transmute",
            "severity": Severity.CRITICAL,
            "message": "std::mem::transmute detected - potential undefined behavior.",
            "cwe": "CWE-843",
            "remediation": "Avoid transmute when possible. Use safe alternatives like From/Into traits, or pointer casts with care.",
        },
        "RS023": {
            "name": "forget-memory-leak",
            "severity": Severity.MEDIUM,
            "message": "std::mem::forget detected - may cause memory/resource leaks.",
            "cwe": "CWE-401",
            "remediation": "Use ManuallyDrop if you need to prevent destructor from running. Ensure resources are properly managed.",
        },
        "RS024": {
            "name": "uninitialized-memory",
            "severity": Severity.CRITICAL,
            "message": "std::mem::uninitialized or MaybeUninit without proper initialization detected.",
            "cwe": "CWE-457",
            "remediation": "Use MaybeUninit::assume_init() only after proper initialization. Prefer safe initialization patterns.",
        },
        "RS025": {
            "name": "drop-unsafe-manually",
            "severity": Severity.HIGH,
            "message": "Manual call to std::ptr::drop_in_place detected.",
            "cwe": "CWE-415",
            "remediation": "Use safe drop patterns. Ensure no use-after-free or double-free bugs are possible.",
        },
        "RS026": {
            "name": "ffi-boundary-unsafe",
            "severity": Severity.HIGH,
            "message": "FFI (Foreign Function Interface) usage detected at boundary.",
            "cwe": "CWE-78",
            "remediation": "Validate all inputs crossing FFI boundaries. Ensure proper encoding and null-termination.",
        },
        "RS027": {
            "name": "environment-variable-unsafe",
            "severity": Severity.LOW,
            "message": "Environment variable usage without validation detected.",
            "cwe": "CWE-15",
            "remediation": "Validate and sanitize environment variables before use. Don't use them for security-critical decisions without checks.",
        },
        "RS028": {
            "name": "static-mutable-state",
            "severity": Severity.MEDIUM,
            "message": "Mutable static variable detected - potential data race.",
            "cwe": "CWE-362",
            "remediation": "Use lazy_static! with Mutex or RwLock, or thread_local! for thread-safe mutable state.",
        },
        "RS029": {
            "name": "tokio-blocking-in-async",
            "severity": Severity.MEDIUM,
            "message": "Potentially blocking operation in async context detected.",
            "cwe": "CWE-400",
            "remediation": "Use tokio::task::spawn_blocking for blocking operations. Avoid blocking the async runtime.",
        },
        "RS030": {
            "name": "insecure-ssl-tls-version",
            "severity": Severity.HIGH,
            "message": "Insecure SSL/TLS version (SSLv2, SSLv3, TLSv1.0, TLSv1.1) usage detected.",
            "cwe": "CWE-319",
            "remediation": "Use TLSv1.2 or TLSv1.3 only. Disable older insecure protocol versions.",
        },
        "RS031": {
            "name": "windows-batch-command-injection",
            "severity": Severity.CRITICAL,
            "message": "Potential command injection via Windows batch file execution (CVE-2024-24576/CVE-2024-43402).",
            "cwe": "CWE-78",
            "remediation": "Avoid executing batch files (.bat, .cmd) with untrusted arguments on Windows. Use proper escaping or avoid batch files entirely.",
        },
        "RS032": {
            "name": "deeply-nested-json-deserialization",
            "severity": Severity.HIGH,
            "message": "Deeply nested JSON deserialization detected - potential stack overflow (CVE-2024-58264).",
            "cwe": "CWE-674",
            "remediation": "Limit JSON nesting depth. Use serde_json::from_str with careful validation of input size and structure.",
        },
        "RS033": {
            "name": "unmaintained-unsound-yaml",
            "severity": Severity.MEDIUM,
            "message": "Using serde_yml which is unsound and unmaintained (RUSTSEC-2025-0068).",
            "cwe": "CWE-1104",
            "remediation": "Replace serde_yml with a maintained YAML library like yaml-rust or serde_yaml.",
        },
        "RS034": {
            "name": "sqlx-binary-protocol-misinterpretation",
            "severity": Severity.HIGH,
            "message": "Potential binary protocol misinterpretation in sqlx (RUSTSEC-2024-0363).",
            "cwe": "CWE-681",
            "remediation": "Update sqlx to latest patched version. Validate query results carefully.",
        },
        "RS035": {
            "name": "typosquatted-dependency",
            "severity": Severity.CRITICAL,
            "message": "Potential typosquatted malicious crate detected in dependencies.",
            "cwe": "CWE-829",
            "remediation": "Verify crate names carefully. Use cargo-audit to scan for known malicious crates.",
        },
        "RS036": {
            "name": "malicious-crate-usage",
            "severity": Severity.CRITICAL,
            "message": "Known malicious crate usage detected - may steal crypto keys or exfiltrate data.",
            "cwe": "CWE-506",
            "remediation": "Remove malicious crates immediately. Audit your Cargo.lock and rotate any exposed secrets.",
        },
        "RS037": {
            "name": "build-script-command-execution",
            "severity": Severity.HIGH,
            "message": "build.rs executing shell commands - potential supply chain attack vector.",
            "cwe": "CWE-78",
            "remediation": "Review all build scripts carefully. Avoid executing untrusted commands in build.rs.",
        },
        "RS038": {
            "name": "proc-macro-code-execution",
            "severity": Severity.HIGH,
            "message": "Procedural macro with potential code execution detected.",
            "cwe": "CWE-94",
            "remediation": "Audit procedural macros carefully. They execute at compile time with full system access.",
        },
        "RS039": {
            "name": "open-redirect-vulnerability",
            "severity": Severity.MEDIUM,
            "message": "Potential open redirect vulnerability - Location header with user input.",
            "cwe": "CWE-601",
            "remediation": "Validate and sanitize redirect URLs. Use allowlists for valid redirect destinations.",
        },
        "RS040": {
            "name": "format-injection",
            "severity": Severity.MEDIUM,
            "message": "Potential format string injection detected.",
            "cwe": "CWE-134",
            "remediation": "Use proper format strings. Avoid passing user input directly to format macros.",
        },
        "RS041": {
            "name": "xss-via-html-escape",
            "severity": Severity.HIGH,
            "message": "Potential XSS vulnerability - user input rendered without proper escaping.",
            "cwe": "CWE-79",
            "remediation": "Use template engines with auto-escaping. Sanitize all user input before rendering HTML.",
        },
        "RS042": {
            "name": "ssrf-vulnerability",
            "severity": Severity.HIGH,
            "message": "Potential Server-Side Request Forgery (SSRF) - HTTP client with user-controlled URL.",
            "cwe": "CWE-918",
            "remediation": "Validate and sanitize URLs. Use allowlists for allowed domains/IPs. Block internal network access.",
        },
        "RS043": {
            "name": "jwt-validation-bypass",
            "severity": Severity.CRITICAL,
            "message": "Potential JWT validation bypass - algorithm confusion or weak secret.",
            "cwe": "CWE-287",
            "remediation": "Use strong JWT secrets. Validate algorithm header. Use established JWT libraries correctly.",
        },
        "RS044": {
            "name": "toctou-race-condition",
            "severity": Severity.MEDIUM,
            "message": "Potential Time-of-Check to Time-of-Use (TOCTOU) race condition in file operations.",
            "cwe": "CWE-367",
            "remediation": "Use atomic file operations. Consider using tempfile with proper permissions.",
        },
        "RS045": {
            "name": "signal-handler-safety",
            "severity": Severity.HIGH,
            "message": "Unsafe signal handler detected - using non-async-signal-safe functions.",
            "cwe": "CWE-828",
            "remediation": "Use only async-signal-safe functions in signal handlers. Set flags and handle in main loop.",
        },
        "RS046": {
            "name": "lazy-static-mutable",
            "severity": Severity.MEDIUM,
            "message": "Mutable state in lazy_static! without proper synchronization.",
            "cwe": "CWE-362",
            "remediation": "Use Mutex or RwLock with lazy_static for mutable state. Consider using once_cell instead.",
        },
        "RS047": {
            "name": "idna-punycode-spoofing",
            "severity": Severity.HIGH,
            "message": "IDNA/punycode domain validation issue - potential homograph attack (CVE-2024-12224).",
            "cwe": "CWE-838",
            "remediation": "Use idna crate >= 1.0.0. Validate domain names carefully before use.",
        },
        "RS048": {
            "name": "axum-dos-extractor",
            "severity": Severity.MEDIUM,
            "message": "Axum extractor without size limits - potential DoS via large request body.",
            "cwe": "CWE-400",
            "remediation": "Set request size limits on extractors. Use DefaultBodyLimit or custom limits.",
        },
        "RS049": {
            "name": "tonic-grpc-misconfiguration",
            "severity": Severity.MEDIUM,
            "message": "Tonic gRPC without proper message size limits - potential DoS.",
            "cwe": "CWE-400",
            "remediation": "Configure max_decoding_message_size and max_encoding_message_size on gRPC servers.",
        },
        "RS050": {
            "name": "cors-misconfiguration",
            "severity": Severity.MEDIUM,
            "message": "Overly permissive CORS configuration detected.",
            "cwe": "CWE-942",
            "remediation": "Restrict CORS to specific origins. Avoid using allow_any_origin in production.",
        },

    }

    # Regex patterns for various detections
    PATTERNS = {
        "unsafe_block": re.compile(
            r"\bunsafe\s*\{",
            re.MULTILINE,
        ),
        "unsafe_function": re.compile(
            r"\bunsafe\s+(?:fn|impl|trait)",
            re.MULTILINE,
        ),
        "raw_pointer_deref": re.compile(
            r"\*\s*(?:const|mut)\s+\w+",
            re.MULTILINE,
        ),
        "sql_format_macro": re.compile(
            r"(?:format!|format_args!)\s*\(\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "sql_string_concat": re.compile(
            r"(?:Query|query|execute|exec).*?\+.*?['\"].*?(?:SELECT|INSERT|UPDATE|DELETE)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "command_shell": re.compile(
            r"(?:Command::new|std::process::Command::new)\s*\(\s*['\"]sh['\"]",
            re.MULTILINE,
        ),
        "command_user_input": re.compile(
            r"(?:Command::new|Command::arg)\s*\(\s*(?:user|input|req|request|data)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "path_traversal": re.compile(
            r"(?:File::open|std::fs::File::open|read_to_string|write)\s*\([^)]*(?:user|input|req|request)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "panic_user_input": re.compile(
            r"panic!\s*\([^)]*(?:user|input|data)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "unwrap_result": re.compile(
            r"\.unwrap\s*\(\s*\)",
            re.MULTILINE,
        ),
        "expect_result": re.compile(
            r"\.expect\s*\(",
            re.MULTILINE,
        ),
        "hardcoded_password": re.compile(
            r"(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
            re.MULTILINE,
        ),
        "hardcoded_api_key": re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
            re.MULTILINE,
        ),
        "tls_verify_disabled": re.compile(
            r"danger_accept_invalid_certs\s*[=:]\s*true|danger_accept_invalid_hostnames\s*[=:]\s*true",
            re.MULTILINE,
        ),
        "weak_random": re.compile(
            r"rand::(?:random|thread_rng)\s*\(\s*\)",
            re.MULTILINE,
        ),
        "md5_usage": re.compile(
            r"(?:md5::|Md5::|md5_)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "sha1_usage": re.compile(
            r"(?:sha1::|Sha1::|sha1_)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "deserialize_unvalidated": re.compile(
            r"(?:serde_json::from_str|serde::Deserialize).*?(?:user|input|req|request|data)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "debug_assert": re.compile(
            r"\bdebug_assert(?:_eq|_ne)?!",
            re.MULTILINE,
        ),
        "transmute": re.compile(
            r"\bstd::mem::transmute\s*\(|\bmem::transmute\s*\(",
            re.MULTILINE,
        ),
        "forget": re.compile(
            r"\bstd::mem::forget\s*\(|\bmem::forget\s*\(",
            re.MULTILINE,
        ),
        "uninitialized": re.compile(
            r"\bstd::mem::uninitialized\s*\(|\bmem::uninitialized\s*\(|MaybeUninit::uninit\(\)\.assume_init",
            re.MULTILINE,
        ),
        "drop_in_place": re.compile(
            r"\bstd::ptr::drop_in_place\s*\(|\bptr::drop_in_place\s*\(",
            re.MULTILINE,
        ),
        "ffi_usage": re.compile(
            r"\bextern\s+['\"](?:C|system)['\"]|#\[link\(|std::ffi::",
            re.MULTILINE,
        ),
        "env_var": re.compile(
            r"\bstd::env::var|env::var|std::env::var_os",
            re.MULTILINE,
        ),
        "static_mut": re.compile(
            r"\bstatic\s+mut\s+",
            re.MULTILINE,
        ),
        "blocking_in_async": re.compile(
            r"(?:std::thread::sleep|std::fs::|File::open|TcpStream::connect).*?\.await",
            re.MULTILINE,
        ),
        "insecure_tls_version": re.compile(
            r"(?:SslMethod::ssl|SslMethod::tls|TlsVersion::TLSv1_0|TlsVersion::TLSv1_1)",
            re.MULTILINE,
        ),
    }

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        super().__init__(rules)
        self.language = "rust"
        self._parser: Optional[Any] = None
        self._ts_language: Optional[Any] = None
        if _TREE_SITTER_AVAILABLE:
            try:
                self._ts_language = TSLanguage(tsrust.language())
                self._parser = TSParser(self._ts_language)
            except Exception:
                pass

    def scan(self, file_path: str, code: str) -> List[Finding]:
        """
        Scan Rust code for security vulnerabilities.

        Args:
            file_path: Path to the file being scanned
            code: Rust source code to analyze

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
            # Check for unsafe blocks
            if node.type == "unsafe_block":
                finding = self._create_finding_from_ast("RS001", node, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Check for unsafe function definitions
            if node.type == "function_item":
                self._check_function_item(node, code, file_path)

            # Check for call expressions (unwrap, expect, etc.)
            if node.type == "call_expression":
                self._check_call_expression(node, code, file_path)

            # Check for let declarations (hardcoded secrets)
            if node.type == "let_declaration":
                self._check_let_declaration(node, code, file_path)

            # Check for static declarations
            if node.type == "static_item":
                self._check_static_item(node, code, file_path)

            # Check for macro invocations
            if node.type == "macro_invocation":
                self._check_macro_invocation(node, code, file_path)

            # Recurse into children
            for child in node.children:
                traverse(child)

        traverse(root_node)

    def _check_function_item(self, node: Any, code: str, file_path: str) -> None:
        """Check function definitions for unsafe keyword."""
        # Check if function has unsafe modifier
        for child in node.children:
            if child.type == "function_modifiers":
                modifiers_text = self._get_node_text(child, code)
                if "unsafe" in modifiers_text:
                    finding = self._create_finding_from_ast("RS002", node, code, file_path)
                    if finding:
                        self.findings.append(finding)
                    break

    def _check_call_expression(self, node: Any, code: str, file_path: str) -> None:
        """Check call expressions for security issues."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        func_text = self._get_node_text(func_node, code)

        # Check for unwrap()
        if func_text == "unwrap" or func_text.endswith(".unwrap"):
            finding = self._create_finding_from_ast("RS010", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for expect()
        if func_text == "expect" or func_text.endswith(".expect"):
            finding = self._create_finding_from_ast("RS011", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for transmute
        if "transmute" in func_text:
            finding = self._create_finding_from_ast("RS022", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for forget
        if "forget" in func_text and ("mem" in func_text or func_text.startswith("std::mem")):
            finding = self._create_finding_from_ast("RS023", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for uninitialized
        if "uninitialized" in func_text:
            finding = self._create_finding_from_ast("RS024", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

        # Check for drop_in_place
        if "drop_in_place" in func_text:
            finding = self._create_finding_from_ast("RS025", node, code, file_path)
            if finding:
                self.findings.append(finding)
            return

    def _check_let_declaration(self, node: Any, code: str, file_path: str) -> None:
        """Check let declarations for hardcoded secrets."""
        text = self._get_node_text(node, code)
        
        # Check for hardcoded passwords
        if self.PATTERNS["hardcoded_password"].search(text):
            if not self._is_likely_false_positive(text):
                finding = self._create_finding_from_ast("RS013", node, code, file_path)
                if finding:
                    self.findings.append(finding)

        # Check for hardcoded API keys
        if self.PATTERNS["hardcoded_api_key"].search(text):
            if not self._is_likely_false_positive(text):
                finding = self._create_finding_from_ast("RS014", node, code, file_path)
                if finding:
                    self.findings.append(finding)

    def _check_static_item(self, node: Any, code: str, file_path: str) -> None:
        """Check static declarations for mutable static."""
        text = self._get_node_text(node, code)
        if "static mut" in text:
            finding = self._create_finding_from_ast("RS028", node, code, file_path)
            if finding:
                self.findings.append(finding)

    def _check_macro_invocation(self, node: Any, code: str, file_path: str) -> None:
        """Check macro invocations for security issues."""
        macro_node = node.child_by_field_name("macro")
        if not macro_node:
            return

        macro_name = self._get_node_text(macro_node, code)
        
        # Check for panic! with user input
        if "panic" in macro_name:
            args_node = node.child_by_field_name("token_tree")
            if args_node:
                args_text = self._get_node_text(args_node, code)
                user_input_patterns = ["user", "input", "data", "req", "request"]
                if any(pattern in args_text.lower() for pattern in user_input_patterns):
                    finding = self._create_finding_from_ast("RS009", node, code, file_path)
                    if finding:
                        self.findings.append(finding)

        # Check for debug_assert!
        if "debug_assert" in macro_name:
            finding = self._create_finding_from_ast("RS020", node, code, file_path)
            if finding:
                self.findings.append(finding)

        # Check for format! with SQL
        if "format" in macro_name:
            args_node = node.child_by_field_name("token_tree")
            if args_node:
                args_text = self._get_node_text(args_node, code)
                sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
                if any(kw in args_text.upper() for kw in sql_keywords):
                    finding = self._create_finding_from_ast("RS005", node, code, file_path)
                    if finding:
                        self.findings.append(finding)

    def _scan_regex(self, file_path: str, code: str) -> None:
        """Scan using regex patterns."""
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Unsafe blocks
            if self.PATTERNS["unsafe_block"].search(line):
                finding = self._create_finding_from_regex("RS001", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Unsafe functions
            if self.PATTERNS["unsafe_function"].search(line):
                finding = self._create_finding_from_regex("RS002", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Raw pointer dereference
            if self.PATTERNS["raw_pointer_deref"].search(line):
                finding = self._create_finding_from_regex("RS003", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # SQL injection via format! macro
            if self.PATTERNS["sql_format_macro"].search(line):
                finding = self._create_finding_from_regex("RS005", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # SQL string concatenation
            if self.PATTERNS["sql_string_concat"].search(line):
                finding = self._create_finding_from_regex("RS004", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Command shell execution
            if self.PATTERNS["command_shell"].search(line):
                finding = self._create_finding_from_regex("RS007", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Command with user input
            if self.PATTERNS["command_user_input"].search(line):
                finding = self._create_finding_from_regex("RS006", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Path traversal
            if self.PATTERNS["path_traversal"].search(line):
                finding = self._create_finding_from_regex("RS008", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Panic with user input
            if self.PATTERNS["panic_user_input"].search(line):
                finding = self._create_finding_from_regex("RS009", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # unwrap()
            if self.PATTERNS["unwrap_result"].search(line):
                finding = self._create_finding_from_regex("RS010", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # expect()
            if self.PATTERNS["expect_result"].search(line):
                finding = self._create_finding_from_regex("RS011", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Hardcoded passwords
            if self.PATTERNS["hardcoded_password"].search(line):
                if not self._is_likely_false_positive(line):
                    finding = self._create_finding_from_regex("RS013", line_num, line, code, file_path)
                    if finding:
                        self.findings.append(finding)

            # Hardcoded API keys
            if self.PATTERNS["hardcoded_api_key"].search(line):
                if not self._is_likely_false_positive(line):
                    finding = self._create_finding_from_regex("RS014", line_num, line, code, file_path)
                    if finding:
                        self.findings.append(finding)

            # TLS verification disabled
            if self.PATTERNS["tls_verify_disabled"].search(line):
                finding = self._create_finding_from_regex("RS015", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Weak random number generator
            if self.PATTERNS["weak_random"].search(line):
                finding = self._create_finding_from_regex("RS016", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # MD5 usage
            if self.PATTERNS["md5_usage"].search(line):
                finding = self._create_finding_from_regex("RS017", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # SHA1 usage
            if self.PATTERNS["sha1_usage"].search(line):
                finding = self._create_finding_from_regex("RS018", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Deserialization without validation
            if self.PATTERNS["deserialize_unvalidated"].search(line):
                finding = self._create_finding_from_regex("RS019", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # debug_assert
            if self.PATTERNS["debug_assert"].search(line):
                finding = self._create_finding_from_regex("RS020", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # transmute
            if self.PATTERNS["transmute"].search(line):
                finding = self._create_finding_from_regex("RS022", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # forget
            if self.PATTERNS["forget"].search(line):
                finding = self._create_finding_from_regex("RS023", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # uninitialized
            if self.PATTERNS["uninitialized"].search(line):
                finding = self._create_finding_from_regex("RS024", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # drop_in_place
            if self.PATTERNS["drop_in_place"].search(line):
                finding = self._create_finding_from_regex("RS025", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # FFI usage
            if self.PATTERNS["ffi_usage"].search(line):
                finding = self._create_finding_from_regex("RS026", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Environment variable usage
            if self.PATTERNS["env_var"].search(line):
                finding = self._create_finding_from_regex("RS027", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Mutable static
            if self.PATTERNS["static_mut"].search(line):
                finding = self._create_finding_from_regex("RS028", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Blocking in async
            if self.PATTERNS["blocking_in_async"].search(line):
                finding = self._create_finding_from_regex("RS029", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Insecure TLS version
            if self.PATTERNS["insecure_tls_version"].search(line):
                finding = self._create_finding_from_regex("RS030", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Windows batch command injection (CVE-2024-24576/43402)
            if "windows_batch_cmd" in self.PATTERNS and self.PATTERNS["windows_batch_cmd"].search(line):
                finding = self._create_finding_from_regex("RS031", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Deeply nested JSON (CVE-2024-58264)
            if "deeply_nested_json" in self.PATTERNS and self.PATTERNS["deeply_nested_json"].search(line):
                finding = self._create_finding_from_regex("RS032", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # serde_yml usage (RUSTSEC-2025-0068)
            if "serde_yml_usage" in self.PATTERNS and self.PATTERNS["serde_yml_usage"].search(line):
                finding = self._create_finding_from_regex("RS033", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Malicious crate patterns
            if "malicious_crate_patterns" in self.PATTERNS and self.PATTERNS["malicious_crate_patterns"].search(line):
                finding = self._create_finding_from_regex("RS036", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # build.rs command execution
            if "build_rs_command" in self.PATTERNS and self.PATTERNS["build_rs_command"].search(line):
                finding = self._create_finding_from_regex("RS037", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Open redirect
            if "open_redirect" in self.PATTERNS and self.PATTERNS["open_redirect"].search(line):
                finding = self._create_finding_from_regex("RS039", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Format injection
            if "format_injection" in self.PATTERNS and self.PATTERNS["format_injection"].search(line):
                finding = self._create_finding_from_regex("RS040", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # XSS via HTML rendering
            if "xss_html_render" in self.PATTERNS and self.PATTERNS["xss_html_render"].search(line):
                finding = self._create_finding_from_regex("RS041", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # SSRF vulnerability
            if "ssrf_http_client" in self.PATTERNS and self.PATTERNS["ssrf_http_client"].search(line):
                finding = self._create_finding_from_regex("RS042", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # JWT weak secret
            if "jwt_weak_secret" in self.PATTERNS and self.PATTERNS["jwt_weak_secret"].search(line):
                finding = self._create_finding_from_regex("RS043", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # TOCTOU race condition
            if "toctou_file_check" in self.PATTERNS and self.PATTERNS["toctou_file_check"].search(line):
                finding = self._create_finding_from_regex("RS044", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Unsafe signal handler
            if "unsafe_signal_handler" in self.PATTERNS and self.PATTERNS["unsafe_signal_handler"].search(line):
                finding = self._create_finding_from_regex("RS045", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # IDNA punycode
            if "idna_domain" in self.PATTERNS and self.PATTERNS["idna_domain"].search(line):
                finding = self._create_finding_from_regex("RS047", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Axum without limits
            if "axum_no_limit" in self.PATTERNS and self.PATTERNS["axum_no_limit"].search(line):
                finding = self._create_finding_from_regex("RS048", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # Tonic gRPC
            if "tonic_grpc" in self.PATTERNS and self.PATTERNS["tonic_grpc"].search(line):
                finding = self._create_finding_from_regex("RS049", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

            # CORS allow any
            if "cors_allow_any" in self.PATTERNS and self.PATTERNS["cors_allow_any"].search(line):
                finding = self._create_finding_from_regex("RS050", line_num, line, code, file_path)
                if finding:
                    self.findings.append(finding)

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
            r"env::var",
            r"std::env",
            r"config",
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
def scan_rust(file_path: str, code: str) -> List[Finding]:
    """Scan Rust code for security vulnerabilities."""
    detector = RustSecurityDetector()
    return detector.scan(file_path, code)


# Example usage
if __name__ == "__main__":
    test_code = '''
use std::process::Command;
use std::fs::File;
use std::env;

static mut COUNTER: i32 = 0;

fn process_user_input(user_data: &str) {
    // CWE-89: SQL injection via format!
    let query = format!("SELECT * FROM users WHERE id = {}", user_data);
    
    // CWE-78: Command injection
    let output = Command::new("sh")
        .arg("-c")
        .arg(user_data)
        .output()
        .expect("Failed to execute");
    
    // CWE-22: Path traversal
    let file = File::open(user_data).unwrap();
    
    // CWE-400: Panic on user input
    panic!("Error: {}", user_data);
    
    // CWE-754: unwrap on user input
    let num: i32 = user_data.parse().unwrap();
    
    // CWE-798: Hardcoded password
    let password = "supersecret123";
    
    // CWE-798: Hardcoded API key
    let api_key = "sk-1234567890abcdef";
    
    // CWE-758: Unsafe block
    unsafe {
        let ptr = 0x1234 as *const i32;
        let val = *ptr;
    }
    
    // CWE-327: Insecure hash
    let hash = md5::compute(user_data);
    
    // CWE-502: Deserialization without validation
    let data: User = serde_json::from_str(user_data).unwrap();
}

unsafe fn dangerous_function() {
    // Unsafe function
}
'''

    findings = scan_rust("test.rs", test_code)
    for finding in findings:
        print(f"[{finding.severity.value.upper()}] {finding.rule_id}: {finding.message}")
        print(f"  File: {finding.file_path}:{finding.line}:{finding.column}")
        print(f"  CWE: {finding.cwe_id}")
        print(f"  Remediation: {finding.remediation}")
        print(f"  Code:\\n{finding.code_snippet}")
        print("-" * 60)
