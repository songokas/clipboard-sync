#!/bin/bash
set -ex

# run: ./gen-certs.sh 127.0.0.1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOST=${1:-"clipboard-sync"}

EXPECTED_DIR="$HOME/.config/clipboard-sync"

mkdir -p "$EXPECTED_DIR"

cd "$EXPECTED_DIR"

openssl req -new -x509 -batch -nodes -days 10000 -keyout rootca.key -out rootca.crt
openssl req -new -batch -nodes -sha256 -keyout cert.key -out cert.csr -subj "/C=GB/CN=$HOST"

openssl x509 -req -days 10000 -in cert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out cert.crt
openssl verify -CAfile rootca.crt cert.crt
rm cert.csr
rm rootca.key
rm rootca.srl