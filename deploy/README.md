# Phase 2 — Transport security (mTLS + TLS)

Closes the **FR4 (Data Confidentiality)** gap from the threat model and adds a
per-node, individually-revocable access boundary — *the* real access control for
field IoT. Nothing here needs the physical sensors: simulated nodes exercise the
exact same boundary.

## What this adds

- **MQTT over mutual TLS (8883)** — the broker and every node authenticate each
  other with certificates. Plaintext `1883` is gone.
- **Per-node certs** whose `CN` = `node-id` = HMAC `key_id`, so revocation is
  coordinated across transport and application layers.
- **Grafana & InfluxDB behind a TLS reverse proxy** (Caddy), not exposed directly.

---

## 1. Generate the PKI

```sh
cd deploy/tls
./gen-certs.sh ../mosquitto/certs
```
Creates, under `deploy/mosquitto/certs/`: `ca.crt` (+ `ca.key`), `broker.crt/key`,
and `crop-01`, `water-01`, `herd-01` `.crt/.key`. Verified with
`openssl verify -CAfile ca.crt <cert>`.

> 🔒 **Never commit private keys.** The included `.gitignore` excludes `certs/`.
> Distribute each node its own `ca.crt` + `<node>.crt` + `<node>.key` only.

## 2. Bring up the stack

```sh
cd deploy
GRAFANA_ADMIN_PASSWORD='a-strong-one' docker compose up -d
```
- MQTT (mTLS): `localhost:8883`
- Grafana (TLS): `https://localhost:3443`  ·  InfluxDB (TLS): `https://localhost:8443`

(Caddy uses its own internal CA, so the browser will warn once on first visit — expected for a local lab.)

## 3. Connect a node

Python (paho) example: [`tls/node_client_example.py`](tls/node_client_example.py).
Quick smoke test from the CLI:

```sh
cd deploy/mosquitto/certs
# subscribe as the gateway
mosquitto_sub -h localhost -p 8883 --cafile ca.crt \
  --cert crop-01.crt --key crop-01.key -t 'agri/#' -v
# publish as crop-01
mosquitto_pub -h localhost -p 8883 --cafile ca.crt \
  --cert crop-01.crt --key crop-01.key -t 'agri/crop/crop-01/secure' -m 'hi'
```
With `use_identity_as_username`, the broker sets the MQTT username to the cert `CN`
(`crop-01`). Your gateway can cross-check that username against the frame's HMAC
`key_id` — a mismatch is an attack signal.

## 4. InfluxDB — least-privilege tokens

The bootstrap admin token is for setup only. Create scoped, per-writer tokens and
stop using the admin token in Node-RED:

```sh
# write-only token for the Node-RED writer, scoped to the 'agri' bucket
docker compose exec influxdb influx auth create \
  --org agri --write-bucket <BUCKET_ID> --description "nodered-writer"
```
Put the new token in Node-RED's InfluxDB node; keep the admin token offline.

## 5. Revoke a node

```sh
cd deploy/tls
./revoke-node.sh crop-01 ../mosquitto/certs      # adds it to crl.pem
# then enable the CRL in mosquitto.conf:  crlfile /mosquitto/certs/crl.pem
docker compose restart mosquitto
# also revoke its key_id in the application keyring (defence in depth)
```

---

## Threat-model impact

| Item | Before | After |
|------|--------|-------|
| **FR4 Data Confidentiality** | ❌ plaintext payloads | ✅ encrypted channel (TLS) |
| **T6 Info disclosure** | ❌ sniffable | ✅ mitigated |
| **FR1 Identification & Auth** | HMAC only | HMAC **+** transport-level mTLS |
| **Node revocation** | app-layer only | transport (CRL) **+** app (key_id) |
| **Zone 3 (monitoring)** | HTTP, admin token | TLS proxy + scoped tokens |

Target Security Level for Conduit A moves from partial-SL2 toward **SL 3** on
authenticity/confidentiality. Update `docs/THREAT_MODEL.md` accordingly.

---

## Why keep HMAC *and* mTLS?

They protect different things and that distinction is the interview gold:
mTLS secures the **channel** (node ↔ broker, hop by hop); HMAC secures the
**frame end-to-end** (node → gateway), survives intermediate brokers/bridges, and
carries the `key_id` your business logic needs. Complementary layers, not
redundancy.
