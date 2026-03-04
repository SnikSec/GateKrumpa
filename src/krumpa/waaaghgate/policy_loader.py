"""
WaaaghGate — Policy-as-code loader.

Load quality-gate policies from YAML/JSON files with per-environment
support (dev / staging / prod), severity overrides, and tag-based rules.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from krumpa.core import Severity
from krumpa.waaaghgate.gate import GatePolicy

logger = logging.getLogger("krumpa.waaaghgate.policy_loader")


# ------------------------------------------------------------------
# Default policy template (used when no file is found)
# ------------------------------------------------------------------

DEFAULT_POLICY: Dict[str, Any] = {
    "version": "1",
    "description": "GateKrumpa default quality-gate policy",
    "environments": {
        "dev": {
            "fail_on": {"critical": 0, "high": 10, "medium": 50},
            "warn_on": {"high": 5, "medium": 20},
            "fail_on_total": 200,
        },
        "staging": {
            "fail_on": {"critical": 0, "high": 3, "medium": 20},
            "warn_on": {"high": 1, "medium": 10},
            "fail_on_total": 100,
        },
        "prod": {
            "fail_on": {"critical": 0, "high": 0, "medium": 5},
            "warn_on": {"medium": 1, "low": 10},
            "fail_on_total": 20,
        },
    },
    "ignore_tags": [],
}


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

class PolicyLoader:
    """
    Load ``GatePolicy`` instances from YAML/JSON files with optional
    environment selection.
    """

    SEARCH_PATHS = [
        ".gatekrumpa-policy.yml",
        ".gatekrumpa-policy.yaml",
        ".gatekrumpa-policy.json",
        "gatekrumpa-policy.yml",
        "gatekrumpa-policy.yaml",
        "gatekrumpa-policy.json",
        "configs/gate-policy.yml",
        "configs/gate-policy.yaml",
        "configs/gate-policy.json",
    ]

    def __init__(
        self,
        *,
        policy_file: Optional[Union[str, Path]] = None,
        environment: str = "prod",
    ) -> None:
        self._file = Path(policy_file) if policy_file else None
        self._environment = environment
        self._raw: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, project_root: Optional[Union[str, Path]] = None) -> GatePolicy:
        """
        Locate and parse a policy file, returning a ``GatePolicy``.

        Falls back to ``DEFAULT_POLICY`` if no file is found.
        """
        raw = self._load_raw(project_root)
        return self._build_policy(raw)

    def load_from_dict(self, data: Dict[str, Any]) -> GatePolicy:
        """Build a GatePolicy directly from a dict (useful in tests)."""
        self._raw = data
        return self._build_policy(data)

    def load_from_string(self, text: str, *, fmt: str = "yaml") -> GatePolicy:
        """Parse a YAML or JSON string into a GatePolicy."""
        data = self._parse_text(text, fmt)
        self._raw = data
        return self._build_policy(data)

    @property
    def raw(self) -> Optional[Dict[str, Any]]:
        return self._raw

    # ------------------------------------------------------------------
    # Internal — loading
    # ------------------------------------------------------------------

    def _load_raw(self, project_root: Optional[Union[str, Path]]) -> Dict[str, Any]:
        path = self._resolve_path(project_root)
        if path and path.is_file():
            logger.info("Loading policy from %s", path)
            text = path.read_text(encoding="utf-8")
            fmt = "json" if path.suffix == ".json" else "yaml"
            data = self._parse_text(text, fmt)
            self._raw = data
            return data

        logger.info("No policy file found, using defaults (env=%s)", self._environment)
        self._raw = DEFAULT_POLICY
        return DEFAULT_POLICY

    def _resolve_path(self, project_root: Optional[Union[str, Path]]) -> Optional[Path]:
        if self._file:
            return self._file

        root = Path(project_root) if project_root else Path.cwd()
        for rel in self.SEARCH_PATHS:
            candidate = root / rel
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _parse_text(text: str, fmt: str) -> Dict[str, Any]:
        if fmt == "json":
            return json.loads(text)

        # YAML parsing — try pyyaml, fall back to basic json-compat parse
        try:
            import yaml
            return yaml.safe_load(text) or {}
        except ImportError:
            # Minimal YAML subset: if it looks like JSON, parse as JSON
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                logger.warning("PyYAML not installed and file is not JSON-compatible")
                return {}

    # ------------------------------------------------------------------
    # Internal — policy construction
    # ------------------------------------------------------------------

    def _build_policy(self, data: Dict[str, Any]) -> GatePolicy:
        """Convert parsed dict → GatePolicy, selecting the right environment."""
        environments = data.get("environments", {})
        env_config = environments.get(self._environment, {})

        # Fall back to top-level keys if no environments block
        if not env_config:
            env_config = data

        fail_on = self._parse_severity_map(env_config.get("fail_on", {}))
        warn_on = self._parse_severity_map(env_config.get("warn_on", {}))
        fail_on_total = env_config.get("fail_on_total")
        ignore_tags = data.get("ignore_tags", [])

        return GatePolicy(
            fail_on=fail_on or {Severity.CRITICAL: 0, Severity.HIGH: 5},
            warn_on=warn_on,
            fail_on_total=fail_on_total,
            ignore_tags=ignore_tags,
        )

    @staticmethod
    def _parse_severity_map(raw: Dict[str, int]) -> Dict[Severity, int]:
        """Convert string severity keys to Severity enum."""
        result: Dict[Severity, int] = {}
        for key, val in raw.items():
            try:
                sev = Severity(key.lower())
                result[sev] = int(val)
            except (ValueError, KeyError):
                logger.warning("Unknown severity '%s' in policy, skipping", key)
        return result


def list_environments(data: Dict[str, Any]) -> List[str]:
    """Return environment names from a parsed policy dict."""
    return list(data.get("environments", {}).keys())


def validate_policy(data: Dict[str, Any]) -> List[str]:
    """Basic validation of a policy dict, returning a list of error messages."""
    errors: List[str] = []

    if "version" not in data:
        errors.append("Missing 'version' field")

    envs = data.get("environments", {})
    if envs and not isinstance(envs, dict):
        errors.append("'environments' must be a mapping")

    for env_name, env_cfg in envs.items():
        if not isinstance(env_cfg, dict):
            errors.append(f"Environment '{env_name}' must be a mapping")
            continue
        fail_on = env_cfg.get("fail_on", {})
        for key in fail_on:
            try:
                Severity(key.lower())
            except ValueError:
                errors.append(f"Unknown severity '{key}' in {env_name}.fail_on")

    return errors
