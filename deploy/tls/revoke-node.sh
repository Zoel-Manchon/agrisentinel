#!/bin/sh
# Revoca un nodo por su nombre: lo mete en la CRL y regenera crl.pem.
# Uso: ./revoke-node.sh crop-01 [certdir]
set -e
NODE="$1"; CERTDIR="${2:-./certs}"
[ -z "$NODE" ] && { echo "uso: $0 <node-id> [certdir]"; exit 1; }
cd "$CERTDIR"
# infra mínima de CRL para la CA
[ -f index.txt ] || : > index.txt
[ -f crlnumber ] || echo 1000 > crlnumber
cat > crl-openssl.cnf <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
database = index.txt
crlnumber = crlnumber
default_md = sha256
default_crl_days = 30
CNF
echo ">> revocando $NODE"
openssl ca -config crl-openssl.cnf -revoke "$NODE.crt" -keyfile ca.key -cert ca.crt 2>/dev/null || true
openssl ca -config crl-openssl.cnf -gencrl -keyfile ca.key -cert ca.crt -out crl.pem 2>/dev/null
echo ">> crl.pem actualizada. Recuerda tambien revocar la key_id de $NODE en el keyring (capa app)."
