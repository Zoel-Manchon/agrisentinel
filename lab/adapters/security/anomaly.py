"""Anomaly detector — the gateway's content inspection.

Four independent checks, each producing SecurityAlerts:

1. out_of_range   — a reading outside its physical envelope (domain-defined).
                    Classic spoofing signature: soil moisture at 250%, animal
                    temp at 80°C. Physics doesn't lie; spoofers do.
2. replay         — a (device_id, sequence) or nonce seen before. Catches an
                    attacker capturing and re-sending a valid signed frame.
3. stale          — timestamp too far behind the gateway clock. Catches held-
                    back / delayed replay even when seq/nonce rotate.
4. rate_anomaly   — a node reporting far faster than its expected cadence
                    (flooding / a cloned node shouting over the real one).

Pure logic, depends only on the domain. Fully unit-testable without hardware.
"""

from lab.domain.model import SecurityAlert
from lab.domain.ports import AnomalyDetectorPort


class AnomalyDetector(AnomalyDetectorPort):
    def __init__(self, clock, stale_after_s: int = 900,
                 min_interval_s: int = 5, replay_window: int = 512):
        self._clock = clock
        self._stale_after = stale_after_s
        self._min_interval = min_interval_s
        self._seen_seq = {}          # device_id -> set of recent sequences
        self._seen_nonce = {}        # device_id -> set of recent nonces
        self._last_ts = {}           # device_id -> last accepted timestamp
        self._replay_window = replay_window

    def inspect(self, frame) -> list:
        alerts = []
        dev = frame.device_id

        # 1) out-of-range readings
        for m in frame.measurements:
            if not m.is_plausible():
                alerts.append(SecurityAlert(
                    "out_of_range", dev,
                    "%s=%.2f%s outside physical envelope" % (m.name, m.value, m.unit),
                    severity="critical"))

        # 2) replay by sequence
        seqs = self._seen_seq.setdefault(dev, set())
        if frame.sequence in seqs:
            alerts.append(SecurityAlert(
                "replay", dev, "sequence %d already seen" % frame.sequence,
                severity="critical"))
        else:
            seqs.add(frame.sequence)
            if len(seqs) > self._replay_window:
                seqs.pop()

        # 2b) replay by nonce (defends against seq reset)
        if frame.nonce:
            nonces = self._seen_nonce.setdefault(dev, set())
            if frame.nonce in nonces:
                alerts.append(SecurityAlert(
                    "replay", dev, "nonce reuse", severity="critical"))
            else:
                nonces.add(frame.nonce)
                if len(nonces) > self._replay_window:
                    nonces.pop()

        # 3) stale timestamp
        now = self._clock.now()
        if now - frame.timestamp > self._stale_after:
            alerts.append(SecurityAlert(
                "stale", dev,
                "timestamp %ds behind gateway" % (now - frame.timestamp),
                severity="warning"))

        # 4) rate anomaly (too fast since last accepted frame)
        last = self._last_ts.get(dev)
        if last is not None and 0 <= frame.timestamp - last < self._min_interval:
            alerts.append(SecurityAlert(
                "rate_anomaly", dev,
                "%ds since last frame (min %ds)" % (frame.timestamp - last, self._min_interval),
                severity="warning"))
        self._last_ts[dev] = frame.timestamp

        return alerts
