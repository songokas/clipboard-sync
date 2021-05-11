#!/bin/bash
set -ex
# # run: ./gen-certs.sh localhost localhost 127.0.0.1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOST=${1:-"localhost"}
HOST_ALT=${2:-"localhost"}
EXPECTED_DIR="${EXPECTED_DIR:-$HOME/.config/clipboard-sync}"

HOST_ALT_SECOND=""
if [[ "$3" ]]; then
  HOST_ALT_SECOND="DNS.2 = $3" 
fi


mkdir -p "$EXPECTED_DIR"
cd "$EXPECTED_DIR"

if [[ ! -f rootca.key ]]; then
    openssl req -new -newkey rsa:4096 -batch -x509 -nodes -days 1000 -keyout rootca.key -out rootca.crt
fi

CONFIG="
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $HOST_ALT
$HOST_ALT_SECOND
"
openssl genrsa -out $HOST.key 2048
openssl req -batch -new -key $HOST.key -out $HOST.csr -subj "/C=GB/CN=$HOST"

openssl x509 -req -in $HOST.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out $HOST.crt -days 1000 -sha256 -extfile <(echo "$CONFIG")

# openssl req -config <(echo "$CONFIG") -new -newkey rsa:4096 -x509 -nodes -sha256 -subj "/C=GB/CN=$HOST" -keyout key.pem -out cert.csr
# openssl x509 -req -days 1000 -in cert.csr -CA rootcert.pem -CAkey rootkey.pem -addext "subjectAltName = DNS:$HOST_ALT"  -CAcreateserial -out cert.pem
# openssl verify -CAfile rootcert.pem cert.pem

# openssl req -new -batch -nodes -sha256 -keyout cert.pem -out cert.csr -subj "/C=GB/CN=$HOST" -addext "subjectAltName = DNS:$HOST_ALT"
# openssl x509 -req -days 10000 -in cert.csr -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out cert.pem

# openssl req -config <(echo "$CONFIG") -new -newkey rsa:4096 -nodes \
#   -subj "/CN=$HOST" -x509 -addext "subjectAltName = DNS:$HOST_ALT" -keyout key.pem -out cert.pem

if [[ ! -f cert.crt ]]; then
  ln -s $HOST.crt cert.crt
fi

if [[ ! -f cert.key ]]; then
  ln -s $HOST.key cert.key
fi

mkdir -p cert-verify

cp rootca.crt "cert-verify"
c_rehash "cert-verify"

rm -f $HOST.csr
rm -f rootca.srl


