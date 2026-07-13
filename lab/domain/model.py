"""Domain model — pure business objects for a smart rural IoT lab.

MicroPython-compatible: no typing/dataclasses/enum/abc imports.

Three rural domains share one model:
- crops  (soil moisture, soil temp, leaf wetness, air temp/humidity)
- water   (tank level, flow rate, pump state, pressure)
- livestock (animal temp, activity, GPS-ish position, gate state)

Security is first-class here, not an afterthought:
- every TelemetryFrame carries a `sequence` and a `nonce` (anti-replay)
- a SignedFrame wraps the encoded bytes with an HMAC tag + key id
- the domain defines what a *plausible* reading is, so the anomaly detector
  (application layer) can flag spoofed / impossible values.
"""

# --- Units ------------------------------------------------------------------
UNIT_CELSIUS = "degC"
UNIT_PERCENT = "%"
UNIT_PERCENT_VWC = "%vwc"      # volumetric water content (soil moisture)
UNIT_HPA = "hPa"
UNIT_LITER = "L"
UNIT_LPM = "L/min"             # litres per minute (flow)
UNIT_METER = "m"
UNIT_BOOL = "bool"
UNIT_LUX = "lx"
UNIT_PH = "pH"
UNIT_COUNT = "count"
UNIT_VOLT = "V"

VALID_UNITS = (
    UNIT_CELSIUS, UNIT_PERCENT, UNIT_PERCENT_VWC, UNIT_HPA, UNIT_LITER,
    UNIT_LPM, UNIT_METER, UNIT_BOOL, UNIT_LUX, UNIT_PH, UNIT_COUNT, UNIT_VOLT,
)

# Plausible physical envelopes per measurement name. The anomaly detector uses
# these to catch spoofed/faulty readings that are outside physical reality.
PLAUSIBLE_RANGE = {
    "soil_moisture": (0.0, 100.0),
    "soil_temp": (-20.0, 60.0),
    "leaf_wetness": (0.0, 100.0),
    "air_temp": (-30.0, 55.0),
    "air_humidity": (0.0, 100.0),
    "pressure": (900.0, 1080.0),
    "tank_level": (0.0, 100.0),
    "flow_rate": (0.0, 200.0),
    "water_ph": (0.0, 14.0),
    "animal_temp": (33.0, 43.0),
    "animal_activity": (0.0, 100.0),
    "battery_voltage": (2.8, 4.3),
}


class Measurement:
    __slots__ = ("name", "value", "unit")

    def __init__(self, name: str, value: float, unit: str):
        if not name:
            raise ValueError("measurement name must not be empty")
        if unit not in VALID_UNITS:
            raise ValueError("unknown unit: %s" % unit)
        self.name = name
        self.value = float(value)
        self.unit = unit

    def is_plausible(self) -> bool:
        """True if the value falls inside the physical envelope for its name.
        Unknown names are considered plausible (no envelope to check)."""
        rng = PLAUSIBLE_RANGE.get(self.name)
        if rng is None:
            return True
        return rng[0] <= self.value <= rng[1]

    def __repr__(self):
        return "Measurement(%s=%.3f %s)" % (self.name, self.value, self.unit)

    def __eq__(self, other):
        return (isinstance(other, Measurement) and self.name == other.name
                and self.value == other.value and self.unit == other.unit)


class TelemetryFrame:
    """One report from one node. Carries a sequence + nonce for anti-replay."""

    __slots__ = ("device_id", "domain", "timestamp", "measurements", "sequence", "nonce")

    def __init__(self, device_id: str, domain: str, timestamp: int,
                 measurements: list, sequence: int = 0, nonce: str = ""):
        if not device_id:
            raise ValueError("device_id must not be empty")
        if domain not in ("crops", "water", "livestock"):
            raise ValueError("domain must be crops|water|livestock")
        if timestamp < 0:
            raise ValueError("timestamp must be positive epoch")
        if sequence < 0:
            raise ValueError("sequence must be >= 0")
        self.device_id = device_id
        self.domain = domain
        self.timestamp = int(timestamp)
        self.measurements = list(measurements)
        self.sequence = int(sequence)
        self.nonce = nonce

    def get(self, name: str):
        for m in self.measurements:
            if m.name == name:
                return m
        return None

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "domain": self.domain,
            "ts": self.timestamp,
            "seq": self.sequence,
            "nonce": self.nonce,
            "readings": {m.name: {"v": m.value, "u": m.unit} for m in self.measurements},
        }

    def __repr__(self):
        return "TelemetryFrame(%s/%s seq=%d n=%d)" % (
            self.device_id, self.domain, self.sequence, len(self.measurements))


class SignedFrame:
    """A frame's encoded bytes plus an HMAC tag and the key id used.

    This is what actually travels on the wire. The gateway verifies the tag
    before trusting anything — an attacker who can publish MQTT still can't
    forge a frame without the shared key.
    """

    __slots__ = ("payload", "tag", "key_id")

    def __init__(self, payload: bytes, tag: str, key_id: str):
        if not payload:
            raise ValueError("payload must not be empty")
        if not tag:
            raise ValueError("tag must not be empty")
        self.payload = payload
        self.tag = tag
        self.key_id = key_id

    def to_dict(self) -> dict:
        import binascii
        return {
            "payload_b64": binascii.b2a_base64(self.payload).decode().strip(),
            "tag": self.tag,
            "key_id": self.key_id,
        }

    def __repr__(self):
        return "SignedFrame(key=%s tag=%s… %dB)" % (
            self.key_id, self.tag[:8], len(self.payload))


class SecurityAlert:
    """Raised by the verifier/detector when something is wrong with a frame."""

    __slots__ = ("kind", "device_id", "detail", "severity")

    # kinds: bad_signature, replay, out_of_range, rate_anomaly, stale
    def __init__(self, kind: str, device_id: str, detail: str = "", severity: str = "warning"):
        self.kind = kind
        self.device_id = device_id
        self.detail = detail
        self.severity = severity

    def to_dict(self) -> dict:
        return {"kind": self.kind, "device_id": self.device_id,
                "detail": self.detail, "severity": self.severity}

    def __repr__(self):
        return "SecurityAlert(%s %s: %s)" % (self.severity, self.kind, self.device_id)
