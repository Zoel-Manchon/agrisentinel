"""Ejemplo mínimo: un nodo publica por mTLS. El CN del cert (= key_id)
   viaja como identidad de transporte; el HMAC sigue firmando el frame."""
import ssl

import paho.mqtt.client as mqtt

NODE_ID = "crop-01"          # == CN del cert == key_id del HMAC

client = mqtt.Client(client_id=NODE_ID)
client.tls_set(
    ca_certs="certs/ca.crt",
    certfile=f"certs/{NODE_ID}.crt",
    keyfile=f"certs/{NODE_ID}.key",
    tls_version=ssl.PROTOCOL_TLSv1_2,
)
client.connect("localhost", 8883)
# El payload sigue firmado con HMAC+seq+nonce (capa de aplicación intacta).
client.publish(f"agri/crop/{NODE_ID}/secure", b"<signed-frame-bytes>")
client.loop(timeout=1.0)
