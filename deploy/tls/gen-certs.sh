#!/bin/sh
# Genera la PKI de agrisentinel: CA propia + cert de broker + un cert por nodo.
# El CN de cada nodo = su node-id = su key_id de HMAC (revocación coordinada).
set -e
CERTDIR="${1:-./certs}"
DAYS="${DAYS:-3650}"
NODES="${NODES:-crop-01 water-01 herd-01}"
mkdir -p "$CERTDIR"; cd "$CERTDIR"

echo ">> CA propia (agrisentinel-ca)"
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=agrisentinel/CN=agrisentinel-ca" -out ca.crt 2>/dev/null

echo ">> cert del broker (server, con SAN)"
openssl genrsa -out broker.key 2048 2>/dev/null
openssl req -new -key broker.key -subj "/O=agrisentinel/CN=mosquitto" -out broker.csr 2>/dev/null
printf 'subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > broker.ext
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile broker.ext -out broker.crt 2>/dev/null

echo ">> un cert por nodo (CN = node-id = key_id)"
for n in $NODES; do
  openssl genrsa -out "$n.key" 2048 2>/dev/null
  openssl req -new -key "$n.key" -subj "/O=agrisentinel/CN=$n" -out "$n.csr" 2>/dev/null
  printf 'extendedKeyUsage=clientAuth\n' > "$n.ext"
  openssl x509 -req -in "$n.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$n.ext" -out "$n.crt" 2>/dev/null
  echo "   + $n"
done
rm -f *.csr *.ext *.srl
echo ">> listo. Certs en: $CERTDIR"
