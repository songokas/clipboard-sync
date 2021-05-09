#!/bin/bash
set -ex
# # run: ./gen-certs.sh 127.0.0.1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOST=${1:-"my-host"}
HOST_ALT=${2:-"localhost"}
EXPECTED_DIR="${EXPECTED_DIR:-$HOME/.config/clipboard-sync}"
CONFIG="
[req]
distinguished_name=dn
[ dn ]
[ ext ]
"

mkdir -p "$EXPECTED_DIR"
cd "$EXPECTED_DIR"

# openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
# openssl req -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj "/C=GB/CN=$HOST"
# openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt
# openssl verify -CAfile rootca.crt cert.crt

# if [[ -d "$EXPECTED_DIR/cert-verify" ]]; then
#     cp rootca.crt "$EXPECTED_DIR/cert-verify"
# fi

# if [[ ! "$CREATE_ROOT" ]]; then
#     openssl req -new -batch -x509 -nodes -days 1000 -keyout rootkey.pem -out rootcert.pem
# fi

# openssl req -config <(echo "$CONFIG") -new -x509 -nodes -sha256 -subj "/C=GB/CN=$HOST" -addext "subjectAltName = DNS:$HOST_ALT" -keyout key.pem -out cert.csr
# openssl x509 -req -days 1000 -in cert.csr -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out cert.pem
# openssl verify -CAfile rootcert.pem cert.pem

# openssl req -new -batch -nodes -sha256 -keyout cert.pem -out cert.csr -subj "/C=GB/CN=$HOST" -addext "subjectAltName = DNS:$HOST_ALT"
# openssl x509 -req -days 10000 -in cert.csr -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out cert.pem

openssl req -config <(echo "$CONFIG") -new -newkey rsa:4096 -nodes \
  -subj "/CN=$HOST" -x509 -addext "subjectAltName = DNS:$HOST_ALT" -keyout key.pem -out cert.pem

if [[ -d "$EXPECTED_DIR/cert-verify" ]]; then
    cp cert.pem "$EXPECTED_DIR/cert-verify"
    # cp rootcert.pem "$EXPECTED_DIR/cert-verify"
fi

# rm -f cert.csr
# rm -f rootca.srl