"""Transports. They carry SignedFrame envelopes (encoded to JSON bytes)."""

import json

from lab.adapters.codec.json_codec import JsonCodec
from lab.domain.ports import TransportPort

_codec = JsonCodec()


class ConsoleTransport(TransportPort):
    def __init__(self, writer=None):
        self._writer = writer or (lambda line: print(line, flush=True))
        self.sent_count = 0

    def send(self, signed):
        self._writer(_codec.encode_signed(signed).decode("utf-8"))
        self.sent_count += 1


class MemoryTransport(TransportPort):
    def __init__(self):
        self.signed = []

    def send(self, signed):
        self.signed.append(signed)


class MqttTransport(TransportPort):
    """Publishes the signed envelope to agri/<domain>/<device>/secure."""

    def __init__(self, host="localhost", port=1883, base_topic="agri", client=None):
        self._base = base_topic.rstrip("/")
        if client is not None:
            self._client = client
        else:  # pragma: no cover
            import paho.mqtt.client as mqtt
            self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5)
            self._client.connect(host, port, keepalive=60)
            self._client.loop_start()

    def send(self, signed):
        env = _codec.encode_signed(signed)
        # peek domain/device from the inner payload for topic routing
        inner = json.loads(signed.payload)
        topic = "%s/%s/%s/secure" % (self._base, inner.get("domain", "x"),
                                     inner.get("device_id", "x"))
        self._client.publish(topic, env, qos=1)

    def close(self):  # pragma: no cover
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass
