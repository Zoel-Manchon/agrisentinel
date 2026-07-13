# Setup — full pipeline with both dashboards

End-to-end: the sim signs and publishes → the gateway verifies and detects →
Node-RED writes two InfluxDB measurements → Grafana shows the **farm** and
**security** dashboards.

Everything runs locally. Total time ~15 minutes.

---

## 0. Prerequisites

- Docker + Docker Compose
- Python 3.10+
- The repo cloned, and `pip install -e ".[dev,mqtt]"` done

---

## 1. Start the stack

```bash
docker compose -f deploy/docker-compose.yml up -d
```

This brings up Mosquitto (1883), InfluxDB 2 (8086) and Grafana (3000), all
pre-provisioned with org/bucket/token `agri`.

✅ **Verify:** `docker compose -f deploy/docker-compose.yml ps` shows three
services `Up`. Open http://localhost:3000 (admin / admin) — Grafana loads.

> If you've run this before and see stale data or auth errors, reset the volumes:
> `docker compose -f deploy/docker-compose.yml down -v` then `up -d` again.
> Init variables only apply to an **empty** volume.

---

## 2. Node-RED (host install)

Node-RED runs on the host, not in Docker, so it can reach `localhost`.

```bash
npm install -g node-red        # first time only
node-red-start                 # or: node-red
```

Then in the editor (http://localhost:1880):

1. Install the InfluxDB nodes: menu ☰ → Manage palette → Install →
   `node-red-contrib-influxdb`.
2. Import the flow: menu ☰ → Import → select `deploy/nodered/flows-agri.json` →
   Import.
3. Open the **influxdb2** config node (double-click either InfluxDB node → pencil
   on the server field) and set the **Token** to `agri-local-dev-token`. URL
   stays `http://localhost:8086`, org `agri`, version 2.0.
4. **Deploy** (top-right).

✅ **Verify:** the two `mqtt in` nodes show **connected** underneath. If they say
"connecting", check Mosquitto is up (step 1).

---

## 3. Grafana datasource

1. http://localhost:3000 → Connections → Data sources → Add → **InfluxDB**.
2. Query language: **Flux**.
3. URL: `http://influxdb:8086` (inside Docker network) — or `http://localhost:8086`
   if Grafana can't resolve it.
4. Under **InfluxDB Details**: Organization `agri`, Token `agri-local-dev-token`,
   Default Bucket `agri`.
5. Save & test → "datasource is working".

✅ **Verify:** the green "datasource is working" banner.

---

## 4. Import BOTH dashboards

For each of the two files:

1. Dashboards → New → **Import**.
2. Upload `deploy/grafana/dashboard-farm.json` → on the next screen pick your
   InfluxDB datasource for the `DS_INFLUXDB` input → Import.
3. Repeat with `deploy/grafana/dashboard-security.json`.

You now have:
- **🌾 AgriSentinel · Farm** — all measurements across crops, water, livestock.
- **🛡 AgriSentinel · Security (SOC)** — alerts, severity, live event table.

✅ **Verify:** both dashboards appear in your dashboard list.

---

## 5. Run the sim

```bash
# a simulated day in ~12 minutes, publishing to MQTT
python -m runner.run_sim --mqtt localhost --speed 120
```

✅ **Verify:** open the **Farm** dashboard, set the range to **Last 30 minutes**.
Within a few seconds the gauges populate and the domain rows start drawing.

> If a panel says "No data": the window is probably empty — widen to
> "Last 1 hour", and confirm the sim is still running. Panels show the latest
> values, so they need fresh data flowing.

---

## 6. Trigger an attack (the fun part)

While the sim runs, launch one with an attack injected:

```bash
# stop the previous sim (Ctrl-C), then:
python -m runner.run_sim --mqtt localhost --speed 120 --attack spoof --at 2
```

Attack options:
- `--attack spoof` — a compromised soil probe reports 250% moisture → `out_of_range`
- `--attack forged` — a frame signed with the wrong key → `bad_signature`
- `--attack replay` — an old valid frame is re-sent → `replay`
- `--attack fever` — a real livestock anomaly (not an attack): animal temp climbs

✅ **Verify:** open the **Security (SOC)** dashboard. The status flips to
**UNDER ATTACK**, the "Alerts by kind" panel shows a bar, and the "Recent alerts"
table lists the event with its device and severity.

---

## Reference

| Thing | Value |
|-------|-------|
| MQTT broker | `localhost:1883` |
| Clean telemetry topic | `agri/<domain>/<device>/state` |
| Security alerts topic | `agri/security/alerts` |
| InfluxDB | `localhost:8086`, org `agri`, bucket `agri` |
| InfluxDB token | `agri-local-dev-token` |
| InfluxDB measurements | `telemetry`, `alerts` |
| Grafana | `localhost:3000`, admin / admin |

> ⚠️ The token here is a local-dev placeholder. Never commit a real token — and
> see the roadmap for rotating to per-node keys + mTLS.
