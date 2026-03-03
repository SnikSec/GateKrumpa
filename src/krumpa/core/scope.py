"""
GateKrumpa core — URL scope enforcement.

``ScopeManager`` controls which hosts / paths the scanner is allowed to
contact.  Include patterns whitelist targets; exclude patterns blacklist
them.  Both accept Python regular expressions (case-insensitive).
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional, Pattern

logger = logging.getLogger("krumpa.scope")


class ScopeManager:
    """Regex-based URL scope enforcement.

    Parameters
    ----------
    include_patterns:
        If provided, a URL must match **at least one** include pattern to
        be considered in-scope.  If empty/None, all URLs are in-scope by
        default.
    exclude_patterns:
        If a URL matches **any** exclude pattern it is out-of-scope,
        regardless of include patterns.

    Both lists accept Python regex strings (matched with ``re.search``).
    """

    def __init__(
        self,
        *,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        self._includes: List[Pattern[str]] = [
            self._safe_compile(p) for p in (include_patterns or [])
        ]
        self._excludes: List[Pattern[str]] = [
            self._safe_compile(p) for p in (exclude_patterns or [])
        ]

    @staticmethod
    def _safe_compile(pattern: str) -> Pattern[str]:
        """Compile a regex with basic validation to mitigate ReDoS risk."""
        if len(pattern) > 500:
            raise ValueError(
                f"Scope pattern too long ({len(pattern)} chars, max 500): "
                f"{pattern[:60]}..."
            )
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid scope regex: {pattern!r} — {exc}") from exc

    # -- public interface ---------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Return ``True`` if *url* passes both include and exclude filters."""
        if any(p.search(url) for p in self._excludes):
            logger.debug("URL excluded by scope rule: %s", url)
            return False

        if self._includes:
            in_scope = any(p.search(url) for p in self._includes)
            if not in_scope:
                logger.debug("URL not matched by any include rule: %s", url)
            return in_scope

        return True  # no includes → everything in scope

    def __repr__(self) -> str:
        return (
            f"ScopeManager(includes={len(self._includes)}, "
            f"excludes={len(self._excludes)})"
        )
