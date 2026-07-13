"""Ports — the hexagon's edges. Plain base classes (no abc; MicroPython-safe).

Driving:  SensorPort, ClockPort, PowerMonitorPort
Driven:   CodecPort, TransportPort
Security: SignerPort (node side), VerifierPort + AnomalyDetectorPort (gateway side)

The security ports are what make this lab different: the node SIGNS, the
gateway VERIFIES and DETECTS. Both sides implement domain ports, so the crypto
and the detection logic are swappable and testable in isolation.
"""


class SensorPort:
    name = "sensor"
    domain = "crops"

    def read(self) -> list:
        raise NotImplementedError

    def warmup_seconds(self) -> int:
        return 0


class ClockPort:
    def now(self) -> int:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError


class PowerMonitorPort:
    def battery_voltage(self) -> float:
        raise NotImplementedError


class CodecPort:
    def encode(self, frame) -> bytes:
        raise NotImplementedError

    def decode(self, payload: bytes):
        raise NotImplementedError


class TransportPort:
    def send(self, data) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SignerPort:
    """Node side: turn encoded bytes into a SignedFrame (HMAC tag + key id)."""

    def sign(self, payload: bytes):
        raise NotImplementedError

    @property
    def key_id(self) -> str:
        raise NotImplementedError


class VerifierPort:
    """Gateway side: check a SignedFrame's HMAC. Returns True/False."""

    def verify(self, signed) -> bool:
        raise NotImplementedError


class AnomalyDetectorPort:
    """Gateway side: inspect a decoded frame for suspicious content.

    Returns a list of SecurityAlert (empty if the frame looks clean).
    Detects: out-of-range values, replayed sequences/nonces, stale
    timestamps, and abnormal report rates.
    """

    def inspect(self, frame) -> list:
        raise NotImplementedError


class SensorError(Exception):
    def __init__(self, sensor_name: str, detail: str = ""):
        self.sensor_name = sensor_name
        self.detail = detail
        super().__init__("%s: %s" % (sensor_name, detail))
