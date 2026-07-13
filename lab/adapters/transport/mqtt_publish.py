"""Thin MQTT publisher for the gateway's clean+alert streams.

Separate from the node TransportPort (which carries SignedFrame envelopes):
the gateway publishes already-decoded telemetry and alert JSON on their own
topics, so Node-RED can route them to two InfluxDB measurements.
"""


class MqttPublisher:
    def __init__(self, host="localhost", port=1883, client=None):
        if client is not None:
            self._client = client
        else:  # pragma: no cover — network wiring
            import paho.mqtt.client as mqtt
            self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5)
            self._client.connect(host, port, keepalive=60)
            self._client.loop_start()

    def publish(self, topic: str, payload: bytes) -> None:
        self._client.publish(topic, payload, qos=1)

    def close(self) -> None:  # pragma: no cover
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass
