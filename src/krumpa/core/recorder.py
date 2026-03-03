"""
GateKrumpa core — request / response recorder.

``RequestRecorder`` captures HTTP traffic flowing through the shared
``HttpClient`` so that modules and reports can reference actual requests
as evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("krumpa.recorder")


@dataclass
class RequestRecord:
    """One recorded HTTP round-trip."""

    method: str
    url: str
    status_code: int
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0
    request_body: Optional[str] = None
    response_body_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": round(self.duration_ms, 2),
            "request_body": self.request_body,
            "response_body_preview": self.response_body_preview,
        }


class RequestRecorder:
    """Collects :class:`RequestRecord` entries from the HTTP client.

    Parameters
    ----------
    max_records:
        Hard cap on stored records (oldest are dropped when exceeded).
    body_preview_length:
        Maximum characters kept for each response body preview.
    """

    def __init__(
        self,
        *,
        max_records: int = 10_000,
        body_preview_length: int = 500,
    ) -> None:
        self._records: List[RequestRecord] = []
        self._max_records = max_records
        self.body_preview_length = body_preview_length

    # -- public interface ---------------------------------------------------

    def record(self, rec: RequestRecord) -> None:
        """Append a record, dropping the oldest when at capacity."""
        if len(self._records) >= self._max_records:
            self._records.pop(0)
        self._records.append(rec)

    @property
    def records(self) -> List[RequestRecord]:
        """Return a shallow copy of all records."""
        return list(self._records)

    @property
    def count(self) -> int:
        return len(self._records)

    def clear(self) -> None:
        self._records.clear()

    def __repr__(self) -> str:
        return f"RequestRecorder(records={len(self._records)})"
