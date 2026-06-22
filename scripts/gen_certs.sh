#!/usr/bin/env bash
# Génère des certificats SSL auto-signés pour SecureZone
# Usage : bash scripts/gen_certs.sh

set -euo pipefail
CERTS_DIR="./nginx/certs"
mkdir -p "$CERTS_DIR"

echo "Génération des certificats SSL..."

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "${CERTS_DIR}/securezone.key" \
    -out    "${CERTS_DIR}/securezone.crt" \
    -subj "/C=TN/ST=Tunis/L=Tunis/O=SecureZone/CN=securezone.local" \
    -addext "subjectAltName=DNS:localhost,DNS:securezone.local,IP:127.0.0.1"

chmod 600 "${CERTS_DIR}/securezone.key"
chmod 644 "${CERTS_DIR}/securezone.crt"

echo "✅ Certificats générés dans ${CERTS_DIR}/"
echo "   securezone.crt  (certificat)"
echo "   securezone.key  (clé privée)"
