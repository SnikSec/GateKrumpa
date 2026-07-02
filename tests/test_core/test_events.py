"""Tests for EventBus — publish-subscribe event system."""

from __future__ import annotations


import pytest

from krumpa.core.events import EventBus, ScanEvent


# ------------------------------------------------------------------
# Sync emission
# ------------------------------------------------------------------

class TestSyncEmit:

    def test_basic_listener(self):
        bus = EventBus()
        received = []
        bus.on(ScanEvent.SCAN_STARTED, lambda d: received.append(d))
        bus.emit(ScanEvent.SCAN_STARTED, {"scan_id": "abc"})
        assert len(received) == 1
        assert received[0]["scan_id"] == "abc"

    def test_multiple_listeners(self):
        bus = EventBus()
        a, b = [], []
        bus.on(ScanEvent.FINDING_ADDED, lambda d: a.append(1))
        bus.on(ScanEvent.FINDING_ADDED, lambda d: b.append(1))
        bus.emit(ScanEvent.FINDING_ADDED, {"finding": "x"})
        assert len(a) == 1
        assert len(b) == 1

    def test_no_listener_no_error(self):
        bus = EventBus()
        bus.emit(ScanEvent.SCAN_FINISHED)  # should not raise

    def test_default_empty_data(self):
        bus = EventBus()
        received = []
        bus.on(ScanEvent.SCAN_STARTED, lambda d: received.append(d))
        bus.emit(ScanEvent.SCAN_STARTED)
        assert received == [{}]

    def test_listener_exception_does_not_propagate(self):
        bus = EventBus()
        received = []

        def bad_listener(_data):
            raise RuntimeError("boom")

        bus.on(ScanEvent.SCAN_STARTED, bad_listener)
        bus.on(ScanEvent.SCAN_STARTED, lambda d: received.append(1))
        bus.emit(ScanEvent.SCAN_STARTED)
        # second listener still called
        assert len(received) == 1

    def test_async_listener_skipped_in_sync_emit(self):
        bus = EventBus()
        received = []

        async def async_listener(data):
            received.append(data)

        bus.on(ScanEvent.SCAN_STARTED, async_listener)
        bus.emit(ScanEvent.SCAN_STARTED, {"x": 1})
        assert len(received) == 0  # skipped


# ------------------------------------------------------------------
# Async emission
# ------------------------------------------------------------------

@pytest.mark.asyncio
class TestAsyncEmit:

    async def test_async_listener_called(self):
        bus = EventBus()
        received = []

        async def listener(data):
            received.append(data)

        bus.on(ScanEvent.MODULE_COMPLETED, listener)
        await bus.emit_async(ScanEvent.MODULE_COMPLETED, {"module": "test"})
        assert len(received) == 1
        assert received[0]["module"] == "test"

    async def test_sync_listener_called_in_async_emit(self):
        bus = EventBus()
        received = []
        bus.on(ScanEvent.SCAN_FINISHED, lambda d: received.append(d))
        await bus.emit_async(ScanEvent.SCAN_FINISHED, {"done": True})
        assert len(received) == 1

    async def test_mixed_listeners(self):
        bus = EventBus()
        sync_received = []
        async_received = []

        bus.on(ScanEvent.FINDING_ADDED, lambda d: sync_received.append(1))

        async def async_fn(data):
            async_received.append(1)

        bus.on(ScanEvent.FINDING_ADDED, async_fn)
        await bus.emit_async(ScanEvent.FINDING_ADDED)
        assert len(sync_received) == 1
        assert len(async_received) == 1

    async def test_async_exception_does_not_propagate(self):
        bus = EventBus()
        received = []

        async def bad(data):
            raise RuntimeError("boom")

        bus.on(ScanEvent.SCAN_STARTED, bad)
        bus.on(ScanEvent.SCAN_STARTED, lambda d: received.append(1))
        await bus.emit_async(ScanEvent.SCAN_STARTED)
        assert len(received) == 1


# ------------------------------------------------------------------
# Registration management
# ------------------------------------------------------------------

class TestRegistration:

    def test_off_removes_listener(self):
        bus = EventBus()
        received = []

        def fn(d):
            received.append(1)

        bus.on(ScanEvent.SCAN_STARTED, fn)
        bus.off(ScanEvent.SCAN_STARTED, fn)
        bus.emit(ScanEvent.SCAN_STARTED)
        assert len(received) == 0

    def test_off_nonexistent_no_error(self):
        bus = EventBus()
        bus.off(ScanEvent.SCAN_STARTED, lambda d: None)  # should not raise

    def test_once_fires_once(self):
        bus = EventBus()
        received = []
        bus.once(ScanEvent.FINDING_ADDED, lambda d: received.append(1))
        bus.emit(ScanEvent.FINDING_ADDED)
        bus.emit(ScanEvent.FINDING_ADDED)
        assert len(received) == 1

    def test_clear_specific_event(self):
        bus = EventBus()
        bus.on(ScanEvent.SCAN_STARTED, lambda d: None)
        bus.on(ScanEvent.SCAN_FINISHED, lambda d: None)
        bus.clear(ScanEvent.SCAN_STARTED)
        assert bus.listener_count(ScanEvent.SCAN_STARTED) == 0
        assert bus.listener_count(ScanEvent.SCAN_FINISHED) == 1

    def test_clear_all(self):
        bus = EventBus()
        bus.on(ScanEvent.SCAN_STARTED, lambda d: None)
        bus.on(ScanEvent.SCAN_FINISHED, lambda d: None)
        bus.clear()
        assert bus.listener_count() == 0

    def test_listener_count(self):
        bus = EventBus()
        bus.on(ScanEvent.SCAN_STARTED, lambda d: None)
        bus.on(ScanEvent.SCAN_STARTED, lambda d: None)
        bus.on(ScanEvent.FINDING_ADDED, lambda d: None)
        assert bus.listener_count(ScanEvent.SCAN_STARTED) == 2
        assert bus.listener_count() == 3


# ------------------------------------------------------------------
# Event enum completeness
# ------------------------------------------------------------------

class TestScanEvent:

    def test_all_events_have_values(self):
        for event in ScanEvent:
            assert isinstance(event.value, str)
            assert len(event.value) > 0

    def test_expected_events_exist(self):
        names = {e.name for e in ScanEvent}
        assert "SCAN_STARTED" in names
        assert "SCAN_FINISHED" in names
        assert "MODULE_STARTED" in names
        assert "MODULE_COMPLETED" in names
        assert "MODULE_FAILED" in names
        assert "MODULE_SKIPPED" in names
        assert "FINDING_ADDED" in names
        assert "TARGET_ADDED" in names
