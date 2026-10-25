"""Test clock helpers (D-056): stamps go through pc_records' clock seam, and a forward-only clock orders them.

A backward step of the host clock (WSL re-syncing with the host, an NTP step) must not reorder times that one test
stamps in sequence. Product code is tested for such a step only where a test injects it on purpose; fixed-time
patches of pc_records.utc_now inside a single test still override this clock.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest import mock

import pc_records


def utc_now():
    """The current UTC time through pc_records' clock seam, never a name bound at import."""
    return pc_records.utc_now()


def forward_only_clock():
    """A wall clock that never moves back: each reading is at least 1 microsecond after the last one."""
    real, last = pc_records.utc_now, []

    def now():
        value = datetime.fromisoformat(real().replace("Z", "+00:00"))
        if last and value <= last[0]:
            value = last[0] + timedelta(microseconds=1)
        last[:] = [value]
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return now


def start_forward_only_clock(test):
    """Patch pc_records.utc_now with a forward-only clock for the rest of ``test`` (stopped at its cleanup)."""
    patcher = mock.patch("pc_records.utc_now", side_effect=forward_only_clock())
    patcher.start()
    test.addCleanup(patcher.stop)
