"""Duty-cycle scheduler — ClockPort abstracts sleep so the same loop runs the
desktop sim (accelerated) and the ESP32 firmware (deepsleep)."""


class DutyCycleScheduler:
    def __init__(self, publish_use_case, clock, interval_seconds: int = 60):
        if interval_seconds <= 0:
            raise ValueError("interval must be > 0")
        self._publish = publish_use_case
        self._clock = clock
        self.interval_seconds = interval_seconds

    def run_once(self):
        return self._publish.execute()

    def run(self, cycles: int = 0, on_frame=None, on_error=None):
        done = 0
        while cycles == 0 or done < cycles:
            try:
                frame = self.run_once()
                if on_frame:
                    on_frame(frame)
            except Exception as exc:  # noqa: BLE001
                if on_error:
                    on_error(exc)
            done += 1
            if cycles == 0 or done < cycles:
                self._clock.sleep(self.interval_seconds)
        return done
