"""Rule loader and parser for security scanning rules."""

import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml


class RuleLoader:
    """Loads and parses security scanning rules from YAML files."""

    def __init__(self, rules_path: Optional[str] = None):
        """Initialize the rule loader.

        Args:
            rules_path: Path to rules YAML file. If None, uses default location.
        """
        if rules_path is None:
            # Default to rules.yaml in the same directory as this file
            self.rules_path = Path(__file__).parent / "rules.yaml"
        else:
            self.rules_path = Path(rules_path)

    def load_rules(self) -> list[dict[str, Any]]:
        """Load and parse rules from YAML file.

        Returns:
            List of rule dictionaries
        """
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        rules = data["rules"]

        # Validate and process each rule
        processed_rules = []
        for rule in rules:
            processed_rule = self._process_rule(rule)
            if processed_rule:
                processed_rules.append(processed_rule)

        return processed_rules

    def _process_rule(self, rule: dict) -> dict | None:
        """Process and validate a single rule.

        Args:
            rule: Raw rule dictionary from YAML

        Returns:
            Processed rule dictionary or None if invalid
        """
        # Required fields
        required_fields = ["id", "name", "language", "severity", "patterns"]
        for field in required_fields:
            if field not in rule:
                print(f"Warning: Rule missing required field '{field}', skipping")
                return None

        # Validate severity
        valid_severities = {"critical", "high", "medium", "low", "info"}
        if rule["severity"] not in valid_severities:
            print(
                f"Warning: Invalid severity '{rule['severity']}' for rule {rule['id']}, defaulting to 'medium'"
            )
            rule["severity"] = "medium"

        # Ensure patterns is a list
        if isinstance(rule["patterns"], str):
            rule["patterns"] = [rule["patterns"]]

        # Compile patterns for efficiency
        rule["_compiled_patterns"] = []
        for pattern in rule["patterns"]:
            try:
                compiled = self._compile_pattern(pattern)
                rule["_compiled_patterns"].append(compiled)
            except re.error as e:
                print(f"Warning: Invalid pattern '{pattern}' in rule {rule['id']}: {e}")

        return rule

    def _compile_pattern(self, pattern: str) -> dict:
        """Compile a pattern for matching.

        Args:
            pattern: Pattern string with optional wildcards ($X, $Y)

        Returns:
            Dictionary with original pattern and compiled regex info
        """
        # Convert pattern to regex
        # $X and $Y are wildcards that match non-whitespace characters
        regex_pattern = pattern

        # Escape special regex characters except our wildcards
        regex_pattern = re.escape(regex_pattern)

        # Unescape our wildcards and convert to regex
        regex_pattern = regex_pattern.replace(r"\$X", r"([^\s(){}[\]]+)")
        regex_pattern = regex_pattern.replace(r"\$Y", r"([^\s(){}[\]]+)")

        # Unescape quotes that were escaped by re.escape
        regex_pattern = regex_pattern.replace(r"\"", r'"')
        regex_pattern = regex_pattern.replace(r"\'", r"'")

        try:
            compiled = re.compile(regex_pattern)
        except re.error:
            # If regex compilation fails, use simple string matching
            compiled = None

        return {
            "original": pattern,
            "regex_pattern": regex_pattern,
            "compiled": compiled,
            "has_wildcards": "$X" in pattern or "$Y" in pattern,
        }

    def get_rules_for_language(self, language: str) -> list[dict]:
        """Get all rules for a specific language.

        Args:
            language: Programming language to filter by

        Returns:
            List of rules for the specified language
        """
        rules = self.load_rules()
        return [r for r in rules if r["language"] == language]

    def get_rule_by_id(self, rule_id: str) -> dict | None:
        """Get a specific rule by ID.

        Args:
            rule_id: Unique identifier of the rule

        Returns:
            Rule dictionary or None if not found
        """
        rules = self.load_rules()
        for rule in rules:
            if rule["id"] == rule_id:
                return rule
        return None

    def reload_rules(self) -> list[dict]:
        """Reload rules from file.

        Returns:
            List of refreshed rule dictionaries
        """
        return self.load_rules()
