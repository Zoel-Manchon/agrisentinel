"""Composition root — runs the whole farm: several signing nodes + a gateway.

    python -m runner.run_sim                          # console, real time
    python -m runner.run_sim --speed 120              # a day in 12 min
    python -m runner.run_sim --mqtt localhost --speed 120
    python -m runner.run_sim --attack spoof --at 3    # inject a spoof at min 3
    python -m runner.run_sim --attack replay --at 3
    python -m runner.run_sim --attack forged --at 3   # frame signed with wrong key

Attacks demonstrate the security layer live: watch the alert stream light up
while the agronomy dashboard keeps running.
"""

import argparse
import sys

from gateway.gateway import Gateway
from lab.adapters.codec.json_codec import JsonCodec
from lab.adapters.security.hmac_signer import HmacSigner
from lab.adapters.sim.clock import SimClock, SystemClock
from lab.adapters.sim.environment import RuralWorld
from lab.adapters.sim.sensors import (
    SimCanopy,
    SimLivestockCollar,
    SimPowerMonitor,
    SimSoilProbe,
    SimWaterTank,
    make_nonce_source,
)
from lab.adapters.transport.transports import MemoryTransport
from lab.application.collect import CollectTelemetry, PublishSecure
from lab.application.scheduler import DutyCycleScheduler

# --- shared secrets (in real life: per-node secure storage / provisioning) ---
KEYRING = {"k1": b"agrisentinel-demo-key-node-fleet-01"}
ATTACKER_KEY = b"totally-the-wrong-key-000000000000"


def build_nodes(world, clock, transport):
    """One node per domain, each with its sensors, signer and scheduler."""
    codec = JsonCodec()
    signer = HmacSigner(KEYRING["k1"], key_id="k1")
    nonce = make_nonce_source()
    power = SimPowerMonitor(world)

    specs = [
        ("crop-01", "crops", [SimSoilProbe(world), SimCanopy(world)]),
        ("water-01", "water", [SimWaterTank(world)]),
        ("herd-01", "livestock", [SimLivestockCollar(world)]),
    ]
    nodes = []
    for dev, domain, sensors in specs:
        collector = CollectTelemetry(dev, domain, sensors, clock, nonce, power=power)
        publisher = PublishSecure(collector, codec, signer, transport)
        nodes.append((dev, domain, DutyCycleScheduler(publisher, clock, 60)))
    return nodes


def main(argv=None):
    p = argparse.ArgumentParser(prog="run_sim", description="agrisentinel smart rural lab")
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--cycles", type=int, default=0, help="0 = forever")
    p.add_argument("--mqtt", metavar="HOST", default=None)
    p.add_argument("--mqtt-port", type=int, default=1883)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--attack", choices=["spoof", "replay", "forged", "fever"], default=None)
    p.add_argument("--at", type=float, default=2.0, metavar="MIN",
                   help="inject the attack after N virtual minutes")
    args = p.parse_args(argv)

    clock = SimClock(speed=args.speed) if args.speed != 1.0 else SystemClock()
    world = RuralWorld(clock, seed=args.seed)

    mqtt_pub = None
    if args.mqtt:
        from lab.adapters.transport.mqtt_publish import MqttPublisher
        mqtt_pub = MqttPublisher(host=args.mqtt, port=args.mqtt_port)

    # node transport just captures signed frames; the gateway does the routing
    tap = MemoryTransport()
    nodes = build_nodes(world, clock, tap)

    codec_out = JsonCodec()

    def publish_clean(frame):
        gw.stats["clean"] += 1
        if mqtt_pub:
            topic = "agri/%s/%s/state" % (frame.domain, frame.device_id)
            mqtt_pub.publish(topic, codec_out.encode(frame))
        else:
            sys.stdout.write("[clean ] %s/%s seq=%d %d readings\n"
                             % (frame.device_id, frame.domain, frame.sequence,
                                len(frame.measurements)))

    def publish_alert(alert):
        gw.stats["alerts"] += 1
        if mqtt_pub:
            import json as _json
            mqtt_pub.publish("agri/security/alerts",
                             _json.dumps(alert.to_dict()).encode("utf-8"))
        sys.stderr.write("[ALERT ] %-13s %s: %s\n"
                         % (alert.kind, alert.device_id, alert.detail))

    gw = Gateway(KEYRING, clock, publish_clean, publish_alert)

    attacker_signer = HmacSigner(ATTACKER_KEY, key_id="k1")  # claims k1, wrong key
    codec = JsonCodec()
    attack_at = int(args.at * 60)
    start = clock.now()
    replay_store = []
    fired = False

    def pump():
        nonlocal fired
        for _dev, _domain, sched in nodes:
            sched.run_once()
        # drain everything the nodes signed this cycle
        while tap.signed:
            signed = tap.signed.pop(0)
            replay_store.append(signed)
            gw.handle_signed(signed)

        # inject attack once, after attack_at virtual seconds
        if args.attack and not fired and clock.now() - start >= attack_at:
            fired = True
            _inject(args.attack, world, gw, codec, attacker_signer, replay_store)

    cycles = args.cycles or 0
    done = 0
    try:
        while cycles == 0 or done < cycles:
            pump()
            done += 1
            if cycles == 0 or done < cycles:
                clock.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    sys.stderr.write("\n[gateway] clean=%d alerts=%d\n"
                     % (gw.stats["clean"], gw.stats["alerts"]))
    return 0


def _inject(kind, world, gw, codec, attacker_signer, replay_store):
    sys.stderr.write("\n>>> INJECTING ATTACK: %s <<<\n" % kind)
    if kind == "spoof":
        # compromised soil probe reports an impossible value
        world.spoof("soil_moisture", 250.0)
    elif kind == "fever":
        world.set_fever(True)   # not an attack, a real livestock anomaly
    elif kind == "replay":
        if replay_store:
            gw.handle_signed(replay_store[0])   # resend an old valid frame
    elif kind == "forged":
        from lab.domain.model import Measurement, TelemetryFrame
        f = TelemetryFrame("crop-01", "crops", world._clock.now(),
                           [Measurement("soil_moisture", 42.0, "%vwc")], sequence=99999,
                           nonce="deadbeef")
        forged = attacker_signer.sign(codec.encode(f))   # signed with WRONG key
        gw.handle_signed(forged)


if __name__ == "__main__":
    raise SystemExit(main())
