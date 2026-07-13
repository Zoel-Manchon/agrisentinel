"""Gateway composition — the trusted edge that ingests signed frames.

Subscribes to agri/+/+/secure, runs IngestSecure (verify -> decode -> detect),
and republishes:
- clean frames  -> agri/<domain>/<device>/state    (Node-RED -> InfluxDB telemetry)
- alerts        -> agri/security/alerts            (Node-RED -> InfluxDB security)

In the sim we call handle() directly; on real infra this wraps paho subscribe.
"""


from lab.adapters.codec.json_codec import JsonCodec
from lab.adapters.security.anomaly import AnomalyDetector
from lab.adapters.security.hmac_signer import HmacVerifier
from lab.application.collect import IngestSecure


class Gateway:
    def __init__(self, keyring: dict, clock, publish_clean, publish_alert,
                 stale_after_s=900, min_interval_s=5):
        self._codec = JsonCodec()
        verifier = HmacVerifier(keyring)
        detector = AnomalyDetector(clock, stale_after_s=stale_after_s,
                                   min_interval_s=min_interval_s)
        self._ingest = IngestSecure(
            self._codec, verifier, detector,
            on_clean=publish_clean, on_alert=publish_alert)
        self.stats = {"clean": 0, "alerts": 0, "rejected": 0}

    def handle_envelope(self, envelope_bytes: bytes):
        """Entry point for one MQTT message (the signed JSON envelope)."""
        signed = self._codec.decode_signed(envelope_bytes)
        return self._ingest.handle(signed)

    def handle_signed(self, signed):
        return self._ingest.handle(signed)
