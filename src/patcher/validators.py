"""Validators for checking patch correctness."""

import re
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple


class ValidationResult:
    """Result of a validation check."""

    def __init__(self, is_valid: bool, message: str = "", line_number: Optional[int] = None):
        self.is_valid = is_valid
        self.message = message
        self.line_number = line_number

    def __bool__(self):
        return self.is_valid

    def __repr__(self):
        status = "✓ VALID" if self.is_valid else "✗ INVALID"
        line_info = f" (line {self.line_number})" if self.line_number else ""
        return f"[{status}]{line_info} {self.message}"


class BaseValidator(ABC):
    """Base class for all validators."""

    @abstractmethod
    def validate(self, original: str, patched: str, language: str) -> ValidationResult:
        """Validate the patch."""
        pass


class SyntaxValidator(BaseValidator):
    """Validate that patched code has valid syntax."""

    def __init__(self):
        self._parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        """Initialize tree-sitter parsers for supported languages."""
        try:
            from tree_sitter import Language, Parser

            # Try to load language libraries
            languages_to_load = [
                ("python", "tree_sitter_python"),
                ("javascript", "tree_sitter_javascript"),
                ("typescript", "tree_sitter_typescript"),
                ("go", "tree_sitter_go"),
            ]

            for lang_name, module_name in languages_to_load:
                try:
                    module = __import__(module_name)
                    language = Language(module.language())
                    parser = Parser()
                    parser.set_language(language)
                    self._parsers[lang_name] = parser
                except ImportError:
                    pass
        except ImportError:
            pass

    def validate(self, original: str, patched: str, language: str) -> ValidationResult:
        """Check that patched code parses correctly."""
        language = language.lower()

        # Use tree-sitter if available
        if language in self._parsers:
            return self._validate_with_treesitter(patched, language)

        # Fallback to language-specific validators
        if language == "python":
            return self._validate_python_syntax(patched)
        elif language in ["javascript", "typescript"]:
            return self._validate_js_syntax(patched)
        elif language == "go":
            return self._validate_go_syntax(patched)

        return ValidationResult(True, f"No syntax validator available for {language}")

    def _validate_with_treesitter(self, code: str, language: str) -> ValidationResult:
        """Validate syntax using tree-sitter."""
        parser = self._parsers.get(language)
        if not parser:
            return ValidationResult(False, f"Parser not available for {language}")

        try:
            tree = parser.parse(bytes(code, "utf8"))

            # Check for ERROR nodes
            error_nodes = self._find_error_nodes(tree.root_node)

            if error_nodes:
                first_error = error_nodes[0]
                return ValidationResult(
                    False,
                    f"Syntax error detected at line {first_error.start_point[0] + 1}",
                    line_number=first_error.start_point[0] + 1,
                )

            return ValidationResult(True, "Syntax is valid")

        except Exception as e:
            return ValidationResult(False, f"Parsing error: {str(e)}")

    def _find_error_nodes(self, node) -> List:
        """Recursively find all ERROR nodes in the tree."""
        errors = []
        if node.type == "ERROR":
            errors.append(node)
        for child in node.children:
            errors.extend(self._find_error_nodes(child))
        return errors

    def _validate_python_syntax(self, code: str) -> ValidationResult:
        """Validate Python syntax using compile()."""
        try:
            compile(code, "<string>", "exec")
            return ValidationResult(True, "Python syntax is valid")
        except SyntaxError as e:
            return ValidationResult(False, f"Python syntax error: {e.msg}", line_number=e.lineno)

    def _validate_js_syntax(self, code: str) -> ValidationResult:
        """Validate JavaScript syntax."""
        # Basic checks since we don't have a JS parser
        issues = []

        # Check for unmatched braces
        open_braces = code.count("{")
        close_braces = code.count("}")
        if open_braces != close_braces:
            issues.append(f"Unmatched braces: {open_braces} open, {close_braces} close")

        # Check for unmatched parentheses
        open_parens = code.count("(")
        close_parens = code.count(")")
        if open_parens != close_parens:
            issues.append(f"Unmatched parentheses: {open_parens} open, {close_parens} close")

        # Check for unmatched brackets
        open_brackets = code.count("[")
        close_brackets = code.count("]")
        if open_brackets != close_brackets:
            issues.append(f"Unmatched brackets: {open_brackets} open, {close_brackets} close")

        # Check for common issues
        if re.search(r"\b(if|while|for|function)\s*\([^)]*\)\s*[^;{}]", code):
            # Check if missing braces after control structures
            pass  # This is too complex for basic validation

        if issues:
            return ValidationResult(False, "; ".join(issues))

        return ValidationResult(True, "JavaScript syntax appears valid (basic checks)")

    def _validate_go_syntax(self, code: str) -> ValidationResult:
        """Validate Go syntax."""
        issues = []

        # Check for unmatched braces
        open_braces = code.count("{")
        close_braces = code.count("}")
        if open_braces != close_braces:
            issues.append(f"Unmatched braces: {open_braces} open, {close_braces} close")

        # Check for common Go issues
        if re.search(r"func\s+\w+\s*\([^)]*\)\s*[^\{]", code):
            issues.append("Function definition missing opening brace")

        if issues:
            return ValidationResult(False, "; ".join(issues))

        return ValidationResult(True, "Go syntax appears valid (basic checks)")


class IndentationValidator(BaseValidator):
    """Validate that indentation is preserved after patching."""

    def validate(self, original: str, patched: str, language: str) -> ValidationResult:
        """Check that indentation structure is maintained."""
        original_lines = original.split("\n")
        patched_lines = patched.split("\n")

        # Compare indentation patterns
        original_indents = [self._get_indent_level(line) for line in original_lines]
        patched_indents = [self._get_indent_level(line) for line in patched_lines]

        # For patches that change line count significantly, just check basic consistency
        if len(original_indents) != len(patched_indents):
            # Check that indentation is consistent in the patched version
            if not self._check_consistent_indentation(patched_lines):
                return ValidationResult(False, "Inconsistent indentation in patched code")
            return ValidationResult(True, "Line count changed but indentation is consistent")

        # Check for drastic indentation changes
        changes = []
        for i, (orig, new) in enumerate(zip(original_indents, patched_indents)):
            if abs(orig - new) > 4:  # More than 4 spaces difference
                changes.append(i + 1)

        if changes:
            return ValidationResult(
                False,
                f"Significant indentation changes at lines: {changes[:5]}",
                line_number=changes[0],
            )

        return ValidationResult(True, "Indentation preserved")

    def _get_indent_level(self, line: str) -> int:
        """Get the indentation level of a line."""
        stripped = line.lstrip()
        if not stripped:
            return 0
        return len(line) - len(stripped)

    def _check_consistent_indentation(self, lines: List[str]) -> bool:
        """Check that indentation is consistent throughout."""
        indents = []
        for line in lines:
            stripped = line.lstrip()
            if stripped and not stripped.startswith("#"):
                indent = len(line) - len(stripped)
                if indent > 0:
                    indents.append(indent)

        if not indents:
            return True

        # Find the most common indent step
        unique_indents = sorted(set(indents))
        if len(unique_indents) < 2:
            return True

        # Check that indents are multiples of a common step
        min_indent = unique_indents[0]
        if min_indent == 0:
            min_indent = unique_indents[1] if len(unique_indents) > 1 else 4

        for indent in unique_indents:
            if indent % min_indent != 0:
                return False

        return True


class SecurityValidator(BaseValidator):
    """Validate that the patch doesn't introduce new security issues."""

    DANGEROUS_PATTERNS = {
        "python": [
            (r"eval\s*\(", "Use of eval()"),
            (r"exec\s*\(", "Use of exec()"),
            (r"__import__\s*\(", "Dynamic import"),
            (r"os\.system\s*\(", "os.system call"),
            (r"subprocess\.call\s*\([^)]*shell\s*=\s*True", "subprocess with shell=True"),
            (r"input\s*\(", "Unsanitized input()"),
            (r"yaml\.load\s*\(", "Unsafe yaml.load"),
            (r"pickle\.loads?\s*\(", "Unsafe pickle"),
            (r"\.format\s*\([^)]*user", "Potential format string vulnerability"),
        ],
        "javascript": [
            (r"eval\s*\(", "Use of eval()"),
            (r"new\s+Function\s*\(", "Use of Function constructor"),
            (r'setTimeout\s*\(\s*["\']', "setTimeout with string"),
            (r'setInterval\s*\(\s*["\']', "setInterval with string"),
            (r"innerHTML\s*=", "Use of innerHTML"),
            (r"document\.write\s*\(", "Use of document.write()"),
            (r"child_process\.exec\s*\(", "Command execution"),
        ],
        "go": [
            (r"InsecureSkipVerify\s*:\s*true", "TLS certificate verification disabled"),
            (r"http\.ListenAndServe\s*\([^,]+\)", "HTTP without TLS"),
            (r"exec\.Command\s*\([^)]*\+", "Command concatenation"),
        ],
    }

    def validate(self, original: str, patched: str, language: str) -> ValidationResult:
        """Check that the patch doesn't introduce new dangerous patterns."""
        language = language.lower()
        patterns = self.DANGEROUS_PATTERNS.get(language, [])

        new_issues = []

        for pattern, description in patterns:
            original_matches = len(re.findall(pattern, original, re.IGNORECASE))
            patched_matches = len(re.findall(pattern, patched, re.IGNORECASE))

            if patched_matches > original_matches:
                new_issues.append(f"Introduced {description}")

        if new_issues:
            return ValidationResult(False, f"New security issues: {'; '.join(new_issues[:3])}")

        return ValidationResult(True, "No new security issues detected")


class CompositeValidator(BaseValidator):
    """Validator that runs multiple validators."""

    def __init__(self, validators: Optional[List[BaseValidator]] = None):
        self.validators = validators or [
            SyntaxValidator(),
            IndentationValidator(),
            SecurityValidator(),
        ]

    def validate(self, original: str, patched: str, language: str) -> List[ValidationResult]:
        """Run all validators and return their results."""
        results = []
        for validator in self.validators:
            result = validator.validate(original, patched, language)
            results.append(result)
        return results

    def is_valid(self, original: str, patched: str, language: str) -> bool:
        """Check if all validators pass."""
        results = self.validate(original, patched, language)
        return all(result.is_valid for result in results)
