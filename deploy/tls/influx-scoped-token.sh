#!/bin/sh
# Crea un token InfluxDB WRITE-ONLY con scope al bucket 'agri' para Node-RED,
# para dejar de usar el token admin. Ejecutar con el stack levantado, desde deploy/.
set -e
ORG="${ORG:-agri}"
BUCKET="${BUCKET:-agri}"
BID=$(docker compose exec -T influxdb influx bucket list --org "$ORG" --name "$BUCKET" --hide-headers 2>/dev/null | awk '{print $1}')
[ -z "$BID" ] && { echo "No encuentro el bucket '$BUCKET'. ¿Stack levantado?"; exit 1; }
echo ">> bucket '$BUCKET' = $BID"
echo ">> creando token write-only con scope..."
docker compose exec -T influxdb influx auth create \
  --org "$ORG" --write-bucket "$BID" \
  --description "nodered-writer (write-only, scoped)"
echo ""
echo ">> Copia el Token de arriba al nodo InfluxDB de Node-RED."
echo ">> Luego RETIRA el token admin de Node-RED/Grafana y guardalo offline."
