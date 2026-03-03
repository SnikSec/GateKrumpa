"""
WaaaghGate — Finding suppression (.gatekrumpa-ignore).

Manages a suppression file that allows teams to mark findings as
false-positives or accepted-risk, preventing them from failing the gate.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from krumpa.core import Finding

logger = logging.getLogger("krumpa.waaaghgate.suppression")


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------

@dataclass
class SuppressionRule:
    """A single suppression / ignore entry."""
    id: str                    # user-defined ID or auto-generated
    reason: str = ""           # why this is suppressed (FP, accepted-risk, ...)
    finding_title: str = ""    # exact or regex match against finding title
    finding_pattern: str = ""  # regex match against finding title
    module: str = ""           # limit to specific module
    cwe: Optional[int] = None  # suppress by CWE
    target_pattern: str = ""   # regex match against target URL
    tags: List[str] = field(default_factory=list)  # suppress if finding has any of these tags
    expires: Optional[str] = None  # ISO-8601 expiry date
    author: str = ""
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_expired(self) -> bool:
        if not self.expires:
            return False
        try:
            exp = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except (ValueError, TypeError):
            return False


@dataclass
class SuppressionResult:
    """Outcome of applying suppression rules."""
    original_count: int
    suppressed_count: int
    active_findings: List[Finding]
    suppressed_findings: List[Finding]
    matched_rules: Dict[str, int] = field(default_factory=dict)  # rule_id → match count


# ------------------------------------------------------------------
# Suppression engine
# ------------------------------------------------------------------

class SuppressionManager:
    """
    Load and apply suppression rules from a ``.gatekrumpa-ignore`` file.
    """

    SEARCH_PATHS = [
        ".gatekrumpa-ignore",
        ".gatekrumpa-ignore.json",
        ".gatekrumpa-ignore.yml",
        ".gatekrumpa-ignore.yaml",
    ]

    def __init__(
        self,
        *,
        rules: Optional[List[SuppressionRule]] = None,
        ignore_file: Optional[Union[str, Path]] = None,
    ) -> None:
        self._rules: List[SuppressionRule] = rules or []
        self._file = Path(ignore_file) if ignore_file else None

    @property
    def rules(self) -> List[SuppressionRule]:
        return list(self._rules)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, project_root: Optional[Union[str, Path]] = None) -> int:
        """
        Load suppression rules from file.  Returns the number of rules loaded.
        """
        path = self._resolve_path(project_root)
        if not path or not path.is_file():
            logger.debug("No suppression file found")
            return 0

        text = path.read_text(encoding="utf-8")
        self._rules = self._parse(text, path.suffix)
        logger.info("Loaded %d suppression rules from %s", len(self._rules), path)
        return len(self._rules)

    def load_from_string(self, text: str, *, fmt: str = "json") -> int:
        """Parse rules from a string."""
        self._rules = self._parse(text, f".{fmt}")
        return len(self._rules)

    def load_from_list(self, data: List[Dict[str, Any]]) -> int:
        """Load rules from a list of dicts."""
        self._rules = [self._dict_to_rule(d) for d in data]
        return len(self._rules)

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def apply(self, findings: List[Finding]) -> SuppressionResult:
        """
        Apply all rules to findings, splitting them into active and suppressed.
        """
        active: List[Finding] = []
        suppressed: List[Finding] = []
        matched: Dict[str, int] = {}

        active_rules = [r for r in self._rules if not r.is_expired()]

        for finding in findings:
            rule = self._match(finding, active_rules)
            if rule:
                suppressed.append(finding)
                matched[rule.id] = matched.get(rule.id, 0) + 1
            else:
                active.append(finding)

        return SuppressionResult(
            original_count=len(findings),
            suppressed_count=len(suppressed),
            active_findings=active,
            suppressed_findings=suppressed,
            matched_rules=matched,
        )

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    @staticmethod
    def _match(finding: Finding, rules: List[SuppressionRule]) -> Optional[SuppressionRule]:
        """Return the first matching rule, or None."""
        for rule in rules:
            if _rule_matches(rule, finding):
                return rule
        return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialize current rules to JSON."""
        return json.dumps(
            {"version": "1", "rules": [_rule_to_dict(r) for r in self._rules]},
            indent=2,
        )

    def save(self, path: Union[str, Path]) -> None:
        """Write rules to a file."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    # ------------------------------------------------------------------
    # Internal parsing
    # ------------------------------------------------------------------

    def _resolve_path(self, project_root: Optional[Union[str, Path]]) -> Optional[Path]:
        if self._file:
            return self._file

        root = Path(project_root) if project_root else Path.cwd()
        for rel in self.SEARCH_PATHS:
            candidate = root / rel
            if candidate.is_file():
                return candidate
        return None

    def _parse(self, text: str, suffix: str) -> List[SuppressionRule]:
        text = text.strip()
        if not text:
            return []

        if suffix in (".json",):
            return self._parse_json(text)
        if suffix in (".yml", ".yaml"):
            return self._parse_yaml(text)

        # Try JSON first, fall back to line-based
        try:
            return self._parse_json(text)
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._parse_lines(text)

    @staticmethod
    def _parse_json(text: str) -> List[SuppressionRule]:
        data = json.loads(text)
        rules_data = data.get("rules", []) if isinstance(data, dict) else data
        return [SuppressionManager._dict_to_rule(d) for d in rules_data]

    @staticmethod
    def _parse_yaml(text: str) -> List[SuppressionRule]:
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text) or {}
        except ImportError:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
        rules_data = data.get("rules", []) if isinstance(data, dict) else []
        return [SuppressionManager._dict_to_rule(d) for d in rules_data]

    @staticmethod
    def _parse_lines(text: str) -> List[SuppressionRule]:
        """
        Simple line-based format::

            # Comment
            title:SQL injection*  reason:false-positive
            cwe:79  reason:accepted-risk  expires:2025-12-31
        """
        rules: List[SuppressionRule] = []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = re.findall(r'(\w+):([^\s]+)', line)
            if not parts:
                continue

            kv = {k: v for k, v in parts}
            rule = SuppressionRule(
                id=kv.get("id", f"line-{i}"),
                reason=kv.get("reason", ""),
                finding_title=kv.get("title", ""),
                finding_pattern=kv.get("pattern", ""),
                module=kv.get("module", ""),
                cwe=int(kv["cwe"]) if "cwe" in kv else None,
                target_pattern=kv.get("target", ""),
                expires=kv.get("expires"),
            )
            rules.append(rule)

        return rules

    @staticmethod
    def _dict_to_rule(d: Dict[str, Any]) -> SuppressionRule:
        return SuppressionRule(
            id=d.get("id", ""),
            reason=d.get("reason", ""),
            finding_title=d.get("finding_title", d.get("title", "")),
            finding_pattern=d.get("finding_pattern", d.get("pattern", "")),
            module=d.get("module", ""),
            cwe=d.get("cwe"),
            target_pattern=d.get("target_pattern", d.get("target", "")),
            tags=d.get("tags", []),
            expires=d.get("expires"),
            author=d.get("author", ""),
            created=d.get("created", ""),
        )


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------

def _rule_matches(rule: SuppressionRule, finding: Finding) -> bool:
    """Check whether a rule matches a finding."""
    # Exact title match
    if rule.finding_title and rule.finding_title != finding.title:
        if rule.finding_title not in finding.title:
            return False

    # Title regex
    if rule.finding_pattern:
        try:
            if not re.search(rule.finding_pattern, finding.title, re.IGNORECASE):
                return False
        except re.error:
            return False

    # Module filter
    if rule.module and rule.module.lower() != finding.module.lower():
        return False

    # CWE filter
    if rule.cwe is not None and rule.cwe != finding.cwe:
        return False

    # Target URL pattern
    if rule.target_pattern and finding.target:
        try:
            if not re.search(rule.target_pattern, finding.target.url, re.IGNORECASE):
                return False
        except re.error:
            return False

    # Tag filter — suppress if finding has ANY of the rule's tags
    if rule.tags:
        if not set(rule.tags) & set(finding.tags):
            return False

    # At least one criterion must have been specified
    has_criteria = any([
        rule.finding_title, rule.finding_pattern, rule.module,
        rule.cwe is not None, rule.target_pattern, rule.tags,
    ])
    return has_criteria


def _rule_to_dict(rule: SuppressionRule) -> Dict[str, Any]:
    d: Dict[str, Any] = {"id": rule.id}
    if rule.reason:
        d["reason"] = rule.reason
    if rule.finding_title:
        d["finding_title"] = rule.finding_title
    if rule.finding_pattern:
        d["finding_pattern"] = rule.finding_pattern
    if rule.module:
        d["module"] = rule.module
    if rule.cwe is not None:
        d["cwe"] = rule.cwe
    if rule.target_pattern:
        d["target_pattern"] = rule.target_pattern
    if rule.tags:
        d["tags"] = rule.tags
    if rule.expires:
        d["expires"] = rule.expires
    if rule.author:
        d["author"] = rule.author
    if rule.created:
        d["created"] = rule.created
    return d
