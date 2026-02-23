"""Fix templates for various vulnerability types across languages."""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
import re


@dataclass
class FixTemplate:
    """Template for fixing a specific vulnerability type."""

    name: str
    description: str
    languages: List[str]
    severity: str
    pattern: str  # Regex or AST pattern to match
    replacement: str  # Replacement template
    ast_transform: Optional[Callable] = None  # AST-based transformation function
    requires_manual_review: bool = False


class FixTemplates:
    """Collection of fix templates for various vulnerabilities."""

    TEMPLATES: Dict[str, FixTemplate] = {
        # JavaScript Templates
        "js_eval_dangerous": FixTemplate(
            name="eval_dangerous",
            description="Replace dangerous eval() with safer alternatives",
            languages=["javascript", "typescript"],
            severity="critical",
            pattern=r"eval\s*\(\s*([^)]+)\s*\)",
            replacement=r"JSON.parse(\1)",  # Default, context-dependent
        ),
        "js_innerhtml_xss": FixTemplate(
            name="innerhtml_xss",
            description="Replace innerHTML with textContent to prevent XSS",
            languages=["javascript", "typescript"],
            severity="high",
            pattern=r"\.innerHTML\s*=",
            replacement=".textContent =",
        ),
        "js_math_random_insecure": FixTemplate(
            name="math_random_insecure",
            description="Replace Math.random() with crypto.getRandomValues()",
            languages=["javascript", "typescript"],
            severity="medium",
            pattern=r"Math\.random\s*\(\s*\)",
            replacement="crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296",
        ),
        "js_console_log_secrets": FixTemplate(
            name="console_log_secrets",
            description="Remove console.log statements that may leak secrets",
            languages=["javascript", "typescript"],
            severity="medium",
            pattern=r"console\.(log|debug|info|warn|error)\s*\(\s*[^)]*(?:password|secret|token|key|auth)[^)]*\s*\)\s*;?",
            replacement="",
        ),
        "js_document_write_xss": FixTemplate(
            name="document_write_xss",
            description="Replace document.write() with safer DOM manipulation",
            languages=["javascript", "typescript"],
            severity="high",
            pattern=r"document\.write\s*\(\s*([^)]+)\s*\)",
            replacement=r'const tempDiv = document.createElement("div"); tempDiv.textContent = \1; document.body.appendChild(tempDiv)',
        ),
        "js_exec_command_injection": FixTemplate(
            name="exec_command_injection",
            description="Replace exec with execFile to prevent command injection",
            languages=["javascript", "typescript"],
            severity="critical",
            pattern=r"(child_process\.)?exec\s*\(",
            replacement="execFile(",
        ),
        # Python Templates
        "py_eval_dangerous": FixTemplate(
            name="eval_dangerous",
            description="Replace dangerous eval() with ast.literal_eval or remove",
            languages=["python"],
            severity="critical",
            pattern=r"eval\s*\(\s*([^)]+)\s*\)",
            replacement=r"ast.literal_eval(\1)",
        ),
        "py_sql_injection_string": FixTemplate(
            name="sql_injection_string",
            description="Replace string formatting in SQL with parameterized queries",
            languages=["python"],
            severity="critical",
            pattern=r'(?:execute|query)\s*\(\s*["\'][^"\']*%s[^"\']*["\']',
            replacement='execute("SELECT ...", params)',
        ),
        "py_sql_injection_format": FixTemplate(
            name="sql_injection_format",
            description="Replace .format() in SQL with parameterized queries",
            languages=["python"],
            severity="critical",
            pattern=r'(?:execute|query)\s*\(\s*["\'][^"\']*\{[^}]*\}[^"\']*["\']\.format',
            replacement='execute("SELECT ...", params)',
        ),
        "py_sql_injection_fstring": FixTemplate(
            name="sql_injection_fstring",
            description="Replace f-strings in SQL with parameterized queries",
            languages=["python"],
            severity="critical",
            pattern=r'(?:execute|query)\s*\(\s*f["\']',
            replacement='execute("SELECT ...", params)',
        ),
        "py_os_system_command_injection": FixTemplate(
            name="os_system_command_injection",
            description="Replace os.system with subprocess.run",
            languages=["python"],
            severity="critical",
            pattern=r"os\.system\s*\(",
            replacement="subprocess.run([",
        ),
        "py_yaml_unsafe": FixTemplate(
            name="yaml_unsafe",
            description="Replace yaml.load with yaml.safe_load",
            languages=["python"],
            severity="high",
            pattern=r"yaml\.load\s*\(",
            replacement="yaml.safe_load(",
        ),
        "py_pickle_unsafe": FixTemplate(
            name="pickle_unsafe",
            description="Replace pickle with json when possible",
            languages=["python"],
            severity="high",
            pattern=r"pickle\.(loads?|dumps?)",
            replacement=r"json.\1",  # Note: requires manual review for compatibility
            requires_manual_review=True,
        ),
        "py_debug_true": FixTemplate(
            name="debug_true",
            description="Set debug=False in production",
            languages=["python"],
            severity="medium",
            pattern=r"debug\s*=\s*True",
            replacement="debug=False",
        ),
        "py_assert_usage": FixTemplate(
            name="assert_usage",
            description="Replace assert with proper validation",
            languages=["python"],
            severity="low",
            pattern=r"assert\s+([^,]+)(?:,\s*(.+))?",
            replacement=r'if not (\1): raise ValueError(\2 if \2 else "Assertion failed")',
        ),
        # Go Templates
        "go_sql_injection": FixTemplate(
            name="sql_injection",
            description="Replace string concatenation in SQL with parameterized queries",
            languages=["go"],
            severity="critical",
            pattern=r'(?:db|tx|stmt)\.Query\s*\(\s*[^"]*\+',
            replacement='db.Query("SELECT ...", params)',
        ),
        "go_math_rand_insecure": FixTemplate(
            name="math_rand_insecure",
            description="Replace math/rand with crypto/rand for security-sensitive operations",
            languages=["go"],
            severity="medium",
            pattern=r'"math/rand"',
            replacement='"crypto/rand"',
        ),
        "go_http_no_tls": FixTemplate(
            name="http_no_tls",
            description="Replace http.ListenAndServe with TLS version",
            languages=["go"],
            severity="high",
            pattern=r'http\.ListenAndServe\s*\(\s*"[^"]*"\s*,',
            replacement='http.ListenAndServeTLS("addr", "cert.pem", "key.pem",',
            requires_manual_review=True,
        ),
        "go_insecure_skip_verify": FixTemplate(
            name="insecure_skip_verify",
            description="Remove InsecureSkipVerify and use proper certificate validation",
            languages=["go"],
            severity="high",
            pattern=r"InsecureSkipVerify\s*:\s*true",
            replacement="InsecureSkipVerify: false",
        ),
    }

    @classmethod
    def get_template(cls, template_name: str) -> Optional[FixTemplate]:
        """Get a fix template by name."""
        return cls.TEMPLATES.get(template_name)

    @classmethod
    def get_templates_for_language(cls, language: str) -> List[FixTemplate]:
        """Get all templates applicable to a language."""
        return [
            template
            for template in cls.TEMPLATES.values()
            if language.lower() in [lang.lower() for lang in template.languages]
        ]

    @classmethod
    def get_template_for_vulnerability(
        cls, vulnerability_type: str, language: str
    ) -> Optional[FixTemplate]:
        """Find appropriate template for a vulnerability type."""
        vuln_lower = vulnerability_type.lower()
        lang_lower = language.lower()

        # Map common vulnerability names to templates
        vuln_mapping = {
            "eval": {
                "python": "py_eval_dangerous",
                "javascript": "js_eval_dangerous",
                "typescript": "js_eval_dangerous",
            },
            "command injection": {
                "python": "py_os_system_command_injection",
                "javascript": "js_exec_command_injection",
            },
            "sql injection": {
                "python": "py_sql_injection_string",
                "go": "go_sql_injection",
            },
            "xss": {
                "javascript": "js_innerhtml_xss",
                "typescript": "js_innerhtml_xss",
            },
            "insecure randomness": {
                "javascript": "js_math_random_insecure",
                "go": "go_math_rand_insecure",
            },
            "deserialization": {
                "python": "py_pickle_unsafe",
            },
            "yaml load": {
                "python": "py_yaml_unsafe",
            },
            "hardcoded credentials": {
                "javascript": "js_console_log_secrets",
            },
            "insecure tls": {
                "go": "go_insecure_skip_verify",
            },
            "debug mode enabled": {
                "python": "py_debug_true",
            },
        }

        if vuln_lower in vuln_mapping:
            if lang_lower in vuln_mapping[vuln_lower]:
                return cls.TEMPLATES.get(vuln_mapping[vuln_lower][lang_lower])

        # Fallback: search by partial match
        for name, template in cls.TEMPLATES.items():
            if lang_lower in [l.lower() for l in template.languages]:
                if any(keyword in vuln_lower for keyword in name.split("_")):
                    return template

        return None

    @classmethod
    def list_all_templates(cls) -> List[str]:
        """List all available template names."""
        return list(cls.TEMPLATES.keys())


# AST Transformation Functions


def js_eval_to_json_parse(node) -> str:
    """Transform eval() call to JSON.parse() or Function() based on context."""
    # This would be called with AST node information
    # For now, return a safe default
    return "JSON.parse(...)"


def py_eval_to_literal_eval(node) -> str:
    """Transform eval() to ast.literal_eval()."""
    return "ast.literal_eval(...)"


def py_sql_to_parameterized(node) -> str:
    """Transform SQL string formatting to parameterized query."""
    return 'cursor.execute("SELECT ...", params)'


def go_sql_to_parameterized(node) -> str:
    """Transform Go SQL string building to parameterized query."""
    return 'db.Query("SELECT ...", params)'


# Template application helpers


def apply_regex_fix(content: str, template: FixTemplate, match_start: int, match_end: int) -> str:
    """Apply a regex-based fix to content at specific position."""
    pattern = re.compile(template.pattern, re.IGNORECASE | re.MULTILINE)

    # Find the match in the content
    for match in pattern.finditer(content):
        if match.start() == match_start and match.end() == match_end:
            # Apply replacement
            if template.replacement:
                return content[: match.start()] + template.replacement + content[match.end() :]

    return content


def generate_fix_preview(original: str, template: FixTemplate) -> Optional[str]:
    """Generate a preview of what the fix would look like."""
    pattern = re.compile(template.pattern, re.IGNORECASE | re.MULTILINE)

    if pattern.search(original):
        # Return first replacement as preview
        return pattern.sub(template.replacement, original, count=1)

    return None
