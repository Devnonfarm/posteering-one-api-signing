"""Self-contained One API signer (Python standard library only)."""
import hashlib, hmac, uuid
from datetime import datetime, timezone
from urllib.parse import quote


def build_sorted_query(query):
    if not query:
        return ""
    return "&".join(f"{quote(k, safe='')}={quote(str(query[k]), safe='')}" for k in sorted(query))


def sign_one_api_request(*, method, path, key_id, secret, body=b"", query=None,
                         sign_headers=None, header_values=None, timestamp=None, nonce=None):
    if not key_id or not secret:
        raise ValueError("key_id and secret are required")
    method = method.upper()
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce = nonce or str(uuid.uuid4())
    sign_headers = sign_headers or ["one-api-hmac-timestamp", "one-api-hmac-nonce"]
    if not sign_headers:
        raise ValueError("sign_headers must be non-empty")
    signed_headers = ",".join(sign_headers)
    body_hash = hashlib.sha256(body).hexdigest()

    lines = [method, path, build_sorted_query(query), timestamp, nonce, signed_headers, body_hash]
    known = {
        "one-api-hmac-timestamp": timestamp,
        "one-api-hmac-nonce": nonce,
        "one-api-hmac-key-id": key_id,
        "one-api-hmac-signed-headers": signed_headers,
        **(header_values or {}),
    }
    for name in sign_headers:
        n = name.strip().lower()
        lines.append(f"{n}:{known.get(n, '')}")
    canonical = "\n".join(lines)

    signature = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "One-Api-Hmac-Key-Id": key_id,
        "One-Api-Hmac-Timestamp": timestamp,
        "One-Api-Hmac-Nonce": nonce,
        "One-Api-Hmac-Signed-Headers": signed_headers,
        "One-Api-Hmac-Signature": signature,
    }


if __name__ == "__main__":
    hdrs = sign_one_api_request(
        method="POST",
        path="/api/v1/one/products/ledger/passthrough/transactions",
        key_id="kid_example", secret="example_secret",
        body=b'{"amount":"9007199254740993"}',
        timestamp="2026-06-13T00:00:00.000Z",
        nonce="00000000-0000-4000-8000-000000000000",
    )
    for k, v in hdrs.items():
        print(f"{k}: {v}")
