"""Clocks.

SimClock supports time acceleration: with speed=60 a full simulated day
streams into Grafana in 24 real minutes — ideal for demo dashboards.
"""

import time

from lab.domain.ports import ClockPort


class SystemClock(ClockPort):
    """Real wall clock (also what the ESP32 build will use, RTC/NTP-backed)."""

    def now(self) -> int:
        return int(time.time())

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class SimClock(ClockPort):
    """Virtual clock: starts at `start_epoch`, advances `speed`x real time.

    sleep(n) sleeps n/speed real seconds but advances n virtual seconds.
    """

    def __init__(self, start_epoch: int = None, speed: float = 1.0):
        if speed <= 0:
            raise ValueError("speed must be > 0")
        # Default to real now: restarts stay continuous on the dashboard and
        # the simulated time-of-day matches the operator's wall clock.
        self._virtual = int(time.time()) if start_epoch is None else start_epoch
        self._speed = speed
        self._anchor = time.monotonic()

    def now(self) -> int:
        elapsed = (time.monotonic() - self._anchor) * self._speed
        return int(self._virtual + elapsed)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds / self._speed)


class ManualClock(ClockPort):
    """Deterministic clock for tests: only moves when you tell it to."""

    def __init__(self, start_epoch: int = 0):
        self._now = start_epoch
        self.sleep_calls = []

    def now(self) -> int:
        return self._now

    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self._now += int(seconds)

    def advance(self, seconds: int) -> None:
        self._now += seconds
