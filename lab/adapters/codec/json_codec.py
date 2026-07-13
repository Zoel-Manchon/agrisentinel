"""JSON codec — simulation-phase wire format.

Two things get serialized:
- TelemetryFrame  <-> bytes   (what gets signed)
- SignedFrame     <-> JSON    (what travels on MQTT: payload_b64 + tag + key_id)

Deterministic output (sorted keys, compact) so the HMAC over the payload bytes
is stable and reproducible.
"""

import binascii
import json

from lab.domain.model import Measurement, SignedFrame, TelemetryFrame
from lab.domain.ports import CodecPort


class JsonCodec(CodecPort):
    def encode(self, frame: TelemetryFrame) -> bytes:
        doc = frame.to_dict()
        for r in doc["readings"].values():
            r["v"] = round(r["v"], 3)
        return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def decode(self, payload: bytes) -> TelemetryFrame:
        doc = json.loads(payload.decode("utf-8"))
        measurements = [
            Measurement(name, r["v"], r["u"]) for name, r in sorted(doc["readings"].items())
        ]
        return TelemetryFrame(
            device_id=doc["device_id"], domain=doc["domain"], timestamp=doc["ts"],
            measurements=measurements, sequence=doc.get("seq", 0), nonce=doc.get("nonce", ""))

    # -- SignedFrame envelope (the thing that hits MQTT) ---------------------

    def encode_signed(self, signed: SignedFrame) -> bytes:
        return json.dumps(signed.to_dict(), separators=(",", ":"),
                          sort_keys=True).encode("utf-8")

    def decode_signed(self, data: bytes) -> SignedFrame:
        doc = json.loads(data.decode("utf-8"))
        payload = binascii.a2b_base64(doc["payload_b64"])
        return SignedFrame(payload, doc["tag"], doc["key_id"])
