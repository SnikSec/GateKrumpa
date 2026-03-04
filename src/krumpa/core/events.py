"""
GateKrumpa core — lightweight event bus.

Provides publish-subscribe communication so modules and external
integrations can react to scan lifecycle events without tight coupling.

Usage::

    from krumpa.core.events import EventBus, ScanEvent

    bus = EventBus()
    bus.on(ScanEvent.FINDING_ADDED, lambda data: print(data))
    bus.emit(ScanEvent.FINDING_ADDED, {"finding": f})

The engine wires events automatically when a bus is present on the
:class:`ScanContext`.
"""

from __future__ import annotations

import asyncio
import enum
import logging
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger("krumpa.events")


# ------------------------------------------------------------------
# Event types
# ------------------------------------------------------------------

class ScanEvent(enum.Enum):
    """Well-known lifecycle events emitted during a scan."""

    # Scan-level
    SCAN_STARTED = "scan_started"
    SCAN_FINISHED = "scan_finished"

    # Module-level
    MODULE_STARTED = "module_started"
    MODULE_COMPLETED = "module_completed"
    MODULE_FAILED = "module_failed"
    MODULE_SKIPPED = "module_skipped"

    # Finding-level
    FINDING_ADDED = "finding_added"

    # Target-level
    TARGET_ADDED = "target_added"


# Listener signature: sync  (data: dict) -> None
#                      async (data: dict) -> None
Listener = Union[Callable[[Dict[str, Any]], None], Callable[[Dict[str, Any]], Any]]


# ------------------------------------------------------------------
# EventBus
# ------------------------------------------------------------------

class EventBus:
    """Simple in-process publish-subscribe event bus.

    Supports both **sync** and **async** listener callables.  When
    ``emit`` is called from an async context, async listeners are
    awaited.  When called from sync code, async listeners are skipped
    with a warning.

    Listeners receive a single ``data`` dict whose keys depend on the
    event type (documented below).

    Event data contracts:
      - ``SCAN_STARTED``:  ``{"scan_id": str, "target_count": int}``
      - ``SCAN_FINISHED``: ``{"scan_id": str, "finding_count": int, "duration_s": float | None}``
      - ``MODULE_STARTED``:   ``{"module": str}``
      - ``MODULE_COMPLETED``: ``{"module": str, "finding_count": int}``
      - ``MODULE_FAILED``:    ``{"module": str, "error": str}``
      - ``MODULE_SKIPPED``:   ``{"module": str, "reason": str}``
      - ``FINDING_ADDED``: ``{"finding": Finding}``
      - ``TARGET_ADDED``:  ``{"target": Target}``
    """

    def __init__(self) -> None:
        self._listeners: Dict[ScanEvent, List[Listener]] = {}

    # -- registration -------------------------------------------------------

    def on(self, event: ScanEvent, listener: Listener) -> None:
        """Register *listener* for *event*."""
        self._listeners.setdefault(event, []).append(listener)

    def off(self, event: ScanEvent, listener: Listener) -> None:
        """Remove *listener* from *event*.  No-op if not registered."""
        try:
            self._listeners.get(event, []).remove(listener)
        except ValueError:
            pass

    def once(self, event: ScanEvent, listener: Listener) -> None:
        """Register a listener that fires at most once."""

        def _wrapper(data: Dict[str, Any]) -> Any:
            self.off(event, _wrapper)
            return listener(data)

        self.on(event, _wrapper)

    # -- emission -----------------------------------------------------------

    def emit(self, event: ScanEvent, data: Optional[Dict[str, Any]] = None) -> None:
        """Fire *event* synchronously — async listeners are skipped."""
        payload = data or {}
        for fn in list(self._listeners.get(event, [])):
            if asyncio.iscoroutinefunction(fn):
                logger.debug(
                    "Skipping async listener %s for %s in sync emit",
                    fn.__name__,
                    event.value,
                )
                continue
            try:
                fn(payload)
            except Exception:
                logger.exception("Listener %s raised for %s", fn.__name__, event.value)

    async def emit_async(self, event: ScanEvent, data: Optional[Dict[str, Any]] = None) -> None:
        """Fire *event* — awaits async listeners, calls sync ones normally."""
        payload = data or {}
        for fn in list(self._listeners.get(event, [])):
            try:
                if asyncio.iscoroutinefunction(fn):
                    await fn(payload)
                else:
                    fn(payload)
            except Exception:
                logger.exception("Listener %s raised for %s", fn.__name__, event.value)

    # -- introspection ------------------------------------------------------

    def listener_count(self, event: Optional[ScanEvent] = None) -> int:
        """Number of registered listeners (total or for a specific event)."""
        if event is not None:
            return len(self._listeners.get(event, []))
        return sum(len(v) for v in self._listeners.values())

    def clear(self, event: Optional[ScanEvent] = None) -> None:
        """Remove all listeners, or all listeners for *event*."""
        if event is not None:
            self._listeners.pop(event, None)
        else:
            self._listeners.clear()
