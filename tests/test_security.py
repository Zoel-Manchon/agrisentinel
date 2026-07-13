import pytest

from lab.adapters.codec.json_codec import JsonCodec
from lab.adapters.security.anomaly import AnomalyDetector
from lab.adapters.security.hmac_signer import HmacSigner, HmacVerifier
from lab.adapters.sim.clock import ManualClock
from lab.domain.model import Measurement, TelemetryFrame


def frame(**kw):
    d = dict(device_id="crop-01", domain="crops", timestamp=1_750_000_000,
             measurements=[Measurement("soil_moisture", 42.0, "%vwc")],
             sequence=0, nonce="abc123")
    d.update(kw)
    return TelemetryFrame(**d)


class TestDomain:
    def test_plausible_range(self):
        assert Measurement("soil_moisture", 42.0, "%vwc").is_plausible()
        assert not Measurement("soil_moisture", 250.0, "%vwc").is_plausible()
        assert not Measurement("animal_temp", 80.0, "degC").is_plausible()

    def test_unknown_name_is_plausible(self):
        assert Measurement("mystery", 999.0, "count").is_plausible()

    def test_frame_rejects_bad_domain(self):
        with pytest.raises(ValueError):
            frame(domain="banking")


class TestHmac:
    def test_sign_verify_roundtrip(self):
        key = b"secret-key-123"
        signer = HmacSigner(key, "k1")
        verifier = HmacVerifier({"k1": key})
        signed = signer.sign(b"hello world")
        assert verifier.verify(signed)

    def test_tampered_payload_fails(self):
        key = b"secret-key-123"
        signer = HmacSigner(key, "k1")
        verifier = HmacVerifier({"k1": key})
        signed = signer.sign(b"hello world")
        signed.payload = b"HELLO WORLD"      # tamper
        assert not verifier.verify(signed)

    def test_wrong_key_fails(self):
        signer = HmacSigner(b"attacker-key", "k1")   # claims k1, wrong key
        verifier = HmacVerifier({"k1": b"real-key"})
        signed = signer.sign(b"payload")
        assert not verifier.verify(signed)

    def test_unknown_key_id_fails(self):
        signer = HmacSigner(b"k", "k9")
        verifier = HmacVerifier({"k1": b"k"})
        assert not verifier.verify(signer.sign(b"x"))


class TestAnomalyDetector:
    def _det(self, now=1_750_000_000):
        return AnomalyDetector(ManualClock(now), stale_after_s=900, min_interval_s=5)

    def test_clean_frame_no_alerts(self):
        det = self._det()
        assert det.inspect(frame(timestamp=1_750_000_000)) == []

    def test_out_of_range_flagged(self):
        det = self._det()
        f = frame(measurements=[Measurement("soil_moisture", 250.0, "%vwc")])
        alerts = det.inspect(f)
        assert any(a.kind == "out_of_range" and a.severity == "critical" for a in alerts)

    def test_replay_by_sequence(self):
        det = self._det()
        det.inspect(frame(sequence=5, nonce="n1"))
        alerts = det.inspect(frame(sequence=5, nonce="n2"))
        assert any(a.kind == "replay" for a in alerts)

    def test_replay_by_nonce(self):
        det = self._det()
        det.inspect(frame(sequence=1, nonce="same"))
        alerts = det.inspect(frame(sequence=2, nonce="same"))
        assert any(a.kind == "replay" for a in alerts)

    def test_stale_timestamp(self):
        det = self._det(now=1_750_100_000)
        alerts = det.inspect(frame(timestamp=1_750_000_000, sequence=1))
        assert any(a.kind == "stale" for a in alerts)

    def test_rate_anomaly(self):
        det = self._det()
        det.inspect(frame(sequence=1, timestamp=1_750_000_000, nonce="a"))
        alerts = det.inspect(frame(sequence=2, timestamp=1_750_000_002, nonce="b"))
        assert any(a.kind == "rate_anomaly" for a in alerts)


class TestCodec:
    def test_frame_roundtrip(self):
        c = JsonCodec()
        decoded = c.decode(c.encode(frame(sequence=7)))
        assert decoded.device_id == "crop-01"
        assert decoded.domain == "crops"
        assert decoded.sequence == 7
        assert decoded.nonce == "abc123"

    def test_signed_envelope_roundtrip(self):
        c = JsonCodec()
        signer = HmacSigner(b"key", "k1")
        signed = signer.sign(c.encode(frame()))
        env = c.encode_signed(signed)
        back = c.decode_signed(env)
        assert back.tag == signed.tag
        assert back.payload == signed.payload
        assert HmacVerifier({"k1": b"key"}).verify(back)

    def test_deterministic_encoding(self):
        c = JsonCodec()
        assert c.encode(frame()) == c.encode(frame())
