"""Use cases — depend only on ports. No mqtt/json/hmac/machine here.

Two sides of the pipeline, both pure:

NODE SIDE (in the field):
  CollectTelemetry  -> builds a TelemetryFrame from sensors (+ nonce, seq)
  PublishSecure     -> encode -> SIGN -> transport

GATEWAY SIDE (trusted edge):
  IngestSecure      -> VERIFY signature -> decode -> DETECT anomalies
                       -> forward clean frames, emit alerts for the rest
"""

from lab.domain.model import UNIT_VOLT, Measurement, SecurityAlert, TelemetryFrame
from lab.domain.ports import SensorError

# ---------------------------------------------------------------- node side ---

class CollectTelemetry:
    """Reads all sensors for one node, stamps sequence + a fresh nonce."""

    def __init__(self, device_id: str, domain: str, sensors: list, clock,
                 nonce_source, power=None):
        if not sensors:
            raise ValueError("at least one sensor is required")
        self._device_id = device_id
        self._domain = domain
        self._sensors = list(sensors)
        self._clock = clock
        self._nonce_source = nonce_source   # callable -> str
        self._power = power
        self._sequence = 0

    def execute(self) -> TelemetryFrame:
        measurements = []
        self.last_errors = []
        for sensor in self._sensors:
            try:
                measurements.extend(sensor.read())
            except SensorError as exc:
                self.last_errors.append(exc)

        if self._power is not None:
            measurements.append(
                Measurement("battery_voltage", self._power.battery_voltage(), UNIT_VOLT))

        if not measurements:
            raise SensorError("all", "no sensor produced data")

        frame = TelemetryFrame(
            device_id=self._device_id, domain=self._domain,
            timestamp=self._clock.now(), measurements=measurements,
            sequence=self._sequence, nonce=self._nonce_source())
        self._sequence += 1
        return frame


class PublishSecure:
    """Node pipeline: collect -> encode -> sign -> transport."""

    def __init__(self, collector, codec, signer, transport):
        self._collector = collector
        self._codec = codec
        self._signer = signer
        self._transport = transport

    def execute(self) -> TelemetryFrame:
        frame = self._collector.execute()
        payload = self._codec.encode(frame)
        signed = self._signer.sign(payload)
        self._transport.send(signed)
        return frame


# ------------------------------------------------------------- gateway side ---

class IngestSecure:
    """Gateway pipeline: verify -> decode -> detect -> forward|alert.

    This is the security heart. A frame is only forwarded downstream (to
    InfluxDB via MQTT) if its signature is valid. Signature failures and
    content anomalies both produce SecurityAlerts that go to a separate
    security topic — so Grafana shows an agronomy dashboard AND a SOC-style
    security dashboard from the same pipeline.
    """

    def __init__(self, codec, verifier, detector, on_clean, on_alert):
        self._codec = codec
        self._verifier = verifier
        self._detector = detector
        self._on_clean = on_clean    # callable(frame)
        self._on_alert = on_alert    # callable(SecurityAlert)

    def handle(self, signed):
        # 1) signature gate — an unsigned/forged frame never gets decoded-trusted
        if not self._verifier.verify(signed):
            self._on_alert(SecurityAlert(
                "bad_signature", _peek_device(signed, self._codec),
                "HMAC verification failed", severity="critical"))
            return None

        # 2) decode now that bytes are authenticated
        frame = self._codec.decode(signed.payload)

        # 3) content inspection (replay, out-of-range, stale, rate)
        alerts = self._detector.inspect(frame)
        for a in alerts:
            self._on_alert(a)

        # 4) forward only if no CRITICAL alert (warnings still flow through)
        if any(a.severity == "critical" for a in alerts):
            return None
        self._on_clean(frame)
        return frame


def _peek_device(signed, codec) -> str:
    """Best-effort device id for logging a bad-signature alert. We must NOT
    trust the payload, but for the alert label a decode attempt is acceptable."""
    try:
        return codec.decode(signed.payload).device_id
    except Exception:
        return "unknown"
