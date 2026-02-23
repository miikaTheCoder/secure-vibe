"""Main patching engine for automated vulnerability remediation."""

import difflib
import hashlib
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from datetime import datetime

from .fixes.templates import FixTemplates, FixTemplate, apply_regex_fix
from .validators import (
    SyntaxValidator,
    IndentationValidator,
    SecurityValidator,
    CompositeValidator,
    ValidationResult,
)


@dataclass
class PatchResult:
    """Result of a patching operation."""

    success: bool
    file_path: str
    vulnerability_type: str
    line_number: int
    original_code: str
    patched_code: str
    diff: str
    backup_path: Optional[str] = None
    dry_run: bool = False
    validations: List[ValidationResult] = field(default_factory=list)
    error_message: Optional[str] = None
    requires_manual_review: bool = False

    def __repr__(self):
        status = "✓ SUCCESS" if self.success else "✗ FAILED"
        mode = " (dry-run)" if self.dry_run else ""
        return f"[{status}]{mode} {self.file_path}:{self.line_number} - {self.vulnerability_type}"


class PatchingEngine:
    """Engine for automated vulnerability patching."""

    def __init__(
        self,
        backup_dir: Optional[str] = None,
        validators: Optional[List] = None,
        dry_run: bool = False,
    ):
        self.backup_dir = backup_dir or ".backups"
        self.dry_run = dry_run
        self.validators = validators or CompositeValidator()
        self.templates = FixTemplates()
        self.patch_history: List[PatchResult] = []

        # Create backup directory if it doesn't exist
        if not self.dry_run:
            os.makedirs(self.backup_dir, exist_ok=True)

    def can_patch(self, vulnerability_type: str, language: str) -> bool:
        """Check if the engine can patch a specific vulnerability type."""
        template = self.templates.get_template_for_vulnerability(vulnerability_type, language)
        return template is not None

    def get_patchable_vulnerabilities(self, language: str) -> List[str]:
        """Get list of vulnerability types that can be patched for a language."""
        templates = self.templates.get_templates_for_language(language)
        return [t.name for t in templates]

    def patch(
        self,
        file_path: str,
        vulnerability_type: str,
        language: str,
        line_number: Optional[int] = None,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        context_lines: int = 3,
        custom_fix: Optional[Callable[[str], str]] = None,
    ) -> PatchResult:
        """
        Apply a patch to fix a vulnerability.

        Args:
            file_path: Path to the file to patch
            vulnerability_type: Type of vulnerability to fix
            language: Programming language
            line_number: Line number where vulnerability starts
            column_start: Starting column of the vulnerable code
            column_end: Ending column of the vulnerable code
            context_lines: Number of context lines to include
            custom_fix: Optional custom fix function

        Returns:
            PatchResult with details of the operation
        """
        try:
            # Read the original file
            with open(file_path, "r", encoding="utf-8") as f:
                original_content = f.read()

            # Get the appropriate template
            template = self.templates.get_template_for_vulnerability(vulnerability_type, language)

            if not template:
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    vulnerability_type=vulnerability_type,
                    line_number=line_number or 0,
                    original_code="",
                    patched_code="",
                    diff="",
                    error_message=f"No fix template available for {vulnerability_type} in {language}",
                )

            # Extract the vulnerable code section
            if line_number:
                original_section = self._extract_section(
                    original_content, line_number, context_lines
                )
            else:
                original_section = original_content

            # Apply the fix
            if custom_fix:
                patched_section = custom_fix(original_section)
            else:
                patched_section = self._apply_template_fix(original_section, template, line_number)

            # Generate diff
            diff = self._generate_diff(original_section, patched_section, file_path)

            # Validate the patch
            validations = self.validators.validate(
                original_content,
                self._rebuild_content(original_content, original_section, patched_section),
                language,
            )

            # Check if all validations pass
            all_valid = all(v.is_valid for v in validations)

            if not all_valid:
                failed = [v for v in validations if not v.is_valid]
                return PatchResult(
                    success=False,
                    file_path=file_path,
                    vulnerability_type=vulnerability_type,
                    line_number=line_number or 0,
                    original_code=original_section,
                    patched_code=patched_section,
                    diff=diff,
                    validations=validations,
                    error_message=f"Validation failed: {'; '.join(v.message for v in failed)}",
                )

            # Create backup if not in dry-run mode
            backup_path = None
            if not self.dry_run:
                backup_path = self._create_backup(file_path)

                # Apply the patch
                patched_content = self._rebuild_content(
                    original_content, original_section, patched_section
                )

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(patched_content)

            result = PatchResult(
                success=True,
                file_path=file_path,
                vulnerability_type=vulnerability_type,
                line_number=line_number or 0,
                original_code=original_section,
                patched_code=patched_section,
                diff=diff,
                backup_path=backup_path,
                dry_run=self.dry_run,
                validations=validations,
                requires_manual_review=template.requires_manual_review,
            )

            self.patch_history.append(result)
            return result

        except Exception as e:
            return PatchResult(
                success=False,
                file_path=file_path,
                vulnerability_type=vulnerability_type,
                line_number=line_number or 0,
                original_code="",
                patched_code="",
                diff="",
                error_message=str(e),
            )

    def patch_file(
        self, file_path: str, vulnerabilities: List[Dict[str, Any]], language: str
    ) -> List[PatchResult]:
        """
        Apply multiple patches to a file.

        Args:
            file_path: Path to the file
            vulnerabilities: List of vulnerability dictionaries with keys:
                - type: vulnerability type
                - line: line number
                - column_start: optional start column
                - column_end: optional end column
            language: Programming language

        Returns:
            List of PatchResult objects
        """
        results = []

        # Sort vulnerabilities by line number (descending) to avoid offset issues
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get("line", 0), reverse=True)

        for vuln in sorted_vulns:
            result = self.patch(
                file_path=file_path,
                vulnerability_type=vuln.get("type", ""),
                language=language,
                line_number=vuln.get("line"),
                column_start=vuln.get("column_start"),
                column_end=vuln.get("column_end"),
            )
            results.append(result)

        return results

    def preview_patch(
        self,
        file_path: str,
        vulnerability_type: str,
        language: str,
        line_number: Optional[int] = None,
    ) -> Optional[str]:
        """
        Preview what a patch would look like without applying it.

        Returns:
            Diff string showing the proposed changes
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            template = self.templates.get_template_for_vulnerability(vulnerability_type, language)

            if not template:
                return None

            if line_number:
                section = self._extract_section(content, line_number, 3)
            else:
                section = content

            patched = self._apply_template_fix(section, template, line_number)
            return self._generate_diff(section, patched, file_path)

        except Exception:
            return None

    def revert(self, file_path: str, backup_path: Optional[str] = None) -> bool:
        """Revert a file to its backup."""
        if backup_path and os.path.exists(backup_path):
            shutil.copy2(backup_path, file_path)
            return True

        # Try to find a backup
        backups = self._find_backups(file_path)
        if backups:
            shutil.copy2(backups[0], file_path)
            return True

        return False

    def list_available_fixes(self) -> Dict[str, List[str]]:
        """List all available fix templates by language."""
        fixes = {}
        for template_name, template in self.templates.TEMPLATES.items():
            for lang in template.languages:
                if lang not in fixes:
                    fixes[lang] = []
                fixes[lang].append(template_name)
        return fixes

    def _extract_section(self, content: str, line_number: int, context_lines: int) -> str:
        """Extract a section of code with context."""
        lines = content.split("\n")
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return "\n".join(lines[start:end])

    def _apply_template_fix(
        self, section: str, template: FixTemplate, line_number: Optional[int] = None
    ) -> str:
        """Apply a fix template to a code section."""
        if template.ast_transform:
            # Use AST-based transformation if available
            return template.ast_transform(section)
        else:
            # Use regex-based replacement
            pattern = re.compile(template.pattern, re.IGNORECASE | re.MULTILINE)
            return pattern.sub(template.replacement, section)

    def _rebuild_content(
        self, original_content: str, original_section: str, patched_section: str
    ) -> str:
        """Rebuild full content with patched section."""
        return original_content.replace(original_section, patched_section, 1)

    def _generate_diff(self, original: str, patched: str, file_path: str) -> str:
        """Generate unified diff between original and patched code."""
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        # Ensure lines end with newline for proper diff
        if original_lines and not original_lines[-1].endswith("\n"):
            original_lines[-1] += "\n"
        if patched_lines and not patched_lines[-1].endswith("\n"):
            patched_lines[-1] += "\n"

        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )

        return "".join(diff)

    def _create_backup(self, file_path: str) -> str:
        """Create a backup of the original file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        file_name = Path(file_path).name

        backup_name = f"{file_name}.{file_hash}.{timestamp}.bak"
        backup_path = os.path.join(self.backup_dir, backup_name)

        shutil.copy2(file_path, backup_path)
        return backup_path

    def _find_backups(self, file_path: str) -> List[str]:
        """Find all backups for a file."""
        import fnmatch

        file_name = Path(file_path).name
        pattern = f"{file_name}.*.bak"

        backups = []
        for filename in os.listdir(self.backup_dir):
            if fnmatch.fnmatch(filename, pattern):
                backups.append(os.path.join(self.backup_dir, filename))

        return sorted(backups, reverse=True)

    def get_patch_summary(self) -> Dict[str, Any]:
        """Get a summary of all patching operations."""
        total = len(self.patch_history)
        successful = sum(1 for r in self.patch_history if r.success)
        failed = total - successful
        dry_runs = sum(1 for r in self.patch_history if r.dry_run)

        return {
            "total_patches": total,
            "successful": successful,
            "failed": failed,
            "dry_runs": dry_runs,
            "files_patched": list(set(r.file_path for r in self.patch_history)),
            "vulnerability_types": list(set(r.vulnerability_type for r in self.patch_history)),
        }
