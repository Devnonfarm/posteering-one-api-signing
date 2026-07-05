#!/usr/bin/env bash
# Self-contained One API signer (bash + openssl). Prints the five headers and sends.
set -euo pipefail
KEY_ID="${KEY_ID:-your_key_id}"
SECRET="${SECRET:-your_signing_secret}"
METHOD="${METHOD:-POST}"
PATH_ONLY="${PATH_ONLY:-/api/v1/one/products/bankrail-gateway/passthrough/virtual-accounts}"
BODY="${BODY:-{\"reference\":\"order-123\",\"holder_name\":\"Payer\",\"holder_phone\":\"08012345678\"}}"
BASE="${BASE:-https://one.posteering.com}"

TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
NONCE=$(uuidgen | tr '[:upper:]' '[:lower:]')
SIGNED_HEADERS="one-api-hmac-timestamp,one-api-hmac-nonce"   # non-empty

BODY_HASH=$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | sed 's/^.*= //')
CANONICAL=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s' "$METHOD" "$PATH_ONLY" "" "$TS" "$NONCE" "$SIGNED_HEADERS" "$BODY_HASH")
CANONICAL=$(printf '%s\none-api-hmac-timestamp:%s\none-api-hmac-nonce:%s' "$CANONICAL" "$TS" "$NONCE")
SIG=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.*= //')

curl -X "$METHOD" "${BASE}${PATH_ONLY}" \
  -H "One-Api-Hmac-Key-Id: ${KEY_ID}" \
  -H "One-Api-Hmac-Timestamp: ${TS}" \
  -H "One-Api-Hmac-Nonce: ${NONCE}" \
  -H "One-Api-Hmac-Signed-Headers: ${SIGNED_HEADERS}" \
  -H "One-Api-Hmac-Signature: ${SIG}" \
  -H "Content-Type: application/json" \
  --data-binary "$BODY"
