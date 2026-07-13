import ast
import pathlib

import pytest

from lab.adapters.codec.json_codec import JsonCodec
from lab.adapters.security.anomaly import AnomalyDetector
from lab.adapters.security.hmac_signer import HmacSigner, HmacVerifier
from lab.adapters.sim.clock import ManualClock
from lab.adapters.sim.environment import RuralWorld
from lab.adapters.sim.sensors import (
    SimLivestockCollar,
    SimSoilProbe,
    SimWaterTank,
    make_nonce_source,
)
from lab.adapters.transport.transports import MemoryTransport
from lab.application.collect import (
    CollectTelemetry,
    IngestSecure,
    PublishSecure,
)
from lab.domain.model import Measurement, TelemetryFrame

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEY = b"pipeline-test-key"


def make_world(sod=12 * 3600, seed=1):
    clock = ManualClock(sod)
    return RuralWorld(clock, seed=seed), clock


class TestSimWorld:
    def test_soil_moisture_in_range(self):
        world, clock = make_world()
        for _ in range(200):
            clock.advance(60)
            assert 0 <= world.soil_moisture() <= 100

    def test_animal_temp_realistic(self):
        world, _ = make_world()
        t = world.animal_temp()
        assert 37.0 < t < 41.0

    def test_spoof_hook_forces_value(self):
        world, _ = make_world()
        world.spoof("soil_moisture", 250.0)
        assert world.soil_moisture() == 250.0

    def test_fever_raises_animal_temp(self):
        world, _ = make_world()
        base = world.animal_temp()
        world.set_fever(True)
        assert world.animal_temp() > base


class TestSimSensors:
    def test_each_domain_declares_itself(self):
        world, _ = make_world()
        assert SimSoilProbe(world).domain == "crops"
        assert SimWaterTank(world).domain == "water"
        assert SimLivestockCollar(world).domain == "livestock"

    def test_soil_probe_two_readings(self):
        world, _ = make_world()
        names = {m.name for m in SimSoilProbe(world).read()}
        assert names == {"soil_moisture", "soil_temp"}


class TestNodePipeline:
    def _collector(self, world, clock):
        return CollectTelemetry("crop-01", "crops", [SimSoilProbe(world)],
                                clock, make_nonce_source())

    def test_collect_stamps_seq_and_nonce(self):
        world, clock = make_world()
        c = self._collector(world, clock)
        f1, f2 = c.execute(), c.execute()
        assert f1.sequence == 0 and f2.sequence == 1
        assert f1.nonce and f1.nonce != f2.nonce   # fresh nonce each time

    def test_publish_secure_signs(self):
        world, clock = make_world()
        transport = MemoryTransport()
        pub = PublishSecure(self._collector(world, clock), JsonCodec(),
                            HmacSigner(KEY, "k1"), transport)
        pub.execute()
        signed = transport.signed[0]
        assert HmacVerifier({"k1": KEY}).verify(signed)


class TestGatewayIngest:
    def _ingest(self, clock, clean, alerts):
        return IngestSecure(
            JsonCodec(), HmacVerifier({"k1": KEY}),
            AnomalyDetector(clock, min_interval_s=1),
            on_clean=clean.append, on_alert=alerts.append)

    def _signed(self, **kw):
        c = JsonCodec()
        f = TelemetryFrame("crop-01", "crops", 1_750_000_000,
                           [Measurement("soil_moisture", 42.0, "%vwc")], **kw)
        return HmacSigner(KEY, "k1").sign(c.encode(f))

    def test_clean_frame_forwarded(self):
        clock = ManualClock(1_750_000_000)
        clean, alerts = [], []
        self._ingest(clock, clean, alerts).handle(self._signed(sequence=1, nonce="a"))
        assert len(clean) == 1 and alerts == []

    def test_forged_frame_rejected(self):
        clock = ManualClock(1_750_000_000)
        clean, alerts = [], []
        c = JsonCodec()
        f = TelemetryFrame("crop-01", "crops", 1_750_000_000,
                           [Measurement("soil_moisture", 42.0, "%vwc")], sequence=1)
        forged = HmacSigner(b"wrong-key", "k1").sign(c.encode(f))
        self._ingest(clock, clean, alerts).handle(forged)
        assert clean == []
        assert any(a.kind == "bad_signature" for a in alerts)

    def test_spoofed_value_not_forwarded(self):
        clock = ManualClock(1_750_000_000)
        clean, alerts = [], []
        signed = self._signed(sequence=1, nonce="a",
                              measurements=[Measurement("soil_moisture", 250.0, "%vwc")]) \
            if False else None
        # build a properly signed but out-of-range frame
        c = JsonCodec()
        f = TelemetryFrame("crop-01", "crops", 1_750_000_000,
                           [Measurement("soil_moisture", 250.0, "%vwc")], sequence=1, nonce="a")
        signed = HmacSigner(KEY, "k1").sign(c.encode(f))
        self._ingest(clock, clean, alerts).handle(signed)
        assert clean == []   # critical alert blocks forwarding
        assert any(a.kind == "out_of_range" for a in alerts)


class TestArchitecture:
    FORBIDDEN = {"paho", "json", "hmac", "hashlib", "machine", "typing",
                 "dataclasses", "abc", "enum", "asyncio", "os"}

    def _imports(self, path):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    yield a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                yield node.module.split(".")[0]

    def test_core_is_pure_and_micropython_safe(self):
        for d in ("lab/domain", "lab/application"):
            for path in (ROOT / d).glob("*.py"):
                for name in self._imports(path):
                    assert name not in self.FORBIDDEN, "%s imports %s" % (path.name, name)
                    assert "adapters" not in name, "%s imports adapters" % path.name


class TestRunnerSmoke:
    def test_runs_clean(self, capsys):
        from runner.run_sim import main
        rc = main(["--cycles", "3", "--speed", "100000", "--seed", "7"])
        assert rc == 0

    def test_forged_attack_raises_alert(self, capsys):
        from runner.run_sim import main
        rc = main(["--cycles", "5", "--speed", "100000", "--seed", "7",
                   "--attack", "forged", "--at", "0"])
        assert rc == 0
        err = capsys.readouterr().err
        assert "bad_signature" in err

    def test_spoof_attack_raises_alert(self, capsys):
        from runner.run_sim import main
        rc = main(["--cycles", "6", "--speed", "100000", "--seed", "7",
                   "--attack", "spoof", "--at", "0"])
        assert rc == 0
        err = capsys.readouterr().err
        assert "out_of_range" in err


class TestHwStubs:
    def test_hw_adapters_fail_until_implemented(self):
        from lab.adapters.hw.sensors import HwSoilProbe
        from lab.domain.ports import SensorError
        with pytest.raises(SensorError):
            HwSoilProbe(adc=None).read()

    def test_hw_adapters_declare_correct_domains(self):
        from lab.adapters.hw.sensors import (
            HwLivestockCollar,
            HwSoilProbe,
            HwWaterTank,
        )
        assert HwSoilProbe(adc=None).domain == "crops"
        assert HwWaterTank().domain == "water"
        assert HwLivestockCollar(i2c=None).domain == "livestock"
