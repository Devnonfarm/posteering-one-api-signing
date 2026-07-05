/**
 * @posteering/one-api-signing — the official One API consumer-leg HMAC signer.
 *
 * You sign ONE leg: your call to the One API (the One-Api-Hmac-* headers). The gateway
 * threads each product's own downstream credential for you — you never build a product's
 * signature. See https://posteering.com/docs/one-api/authentication
 *
 * This signer is self-contained (no server imports) and is guarded against drift by a
 * fixed test vector (see test/vector.test.mjs): its output is asserted byte-for-byte
 * against the value the gateway's verifier produces. If the canonical string ever changes
 * server-side, the vector changes and the test fails in CI, forcing a version bump.
 */
import { createHmac, createHash, randomUUID } from 'node:crypto';

/** Sorted, percent-encoded query string ("" if none) — matches the verifier. */
function buildSortedQuery(query) {
  if (!query) return '';
  const keys = Object.keys(query).sort();
  if (keys.length === 0) return '';
  return keys.map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(query[k])}`).join('&');
}

/**
 * Sign a One API request. Returns the five headers to send.
 *
 * @param {object}  opts
 * @param {string}  opts.method   HTTP method (e.g. 'POST').
 * @param {string}  opts.path     Request path exactly as sent, no query (e.g. '/api/v1/one/products/bankrail-gateway/passthrough/virtual-accounts').
 * @param {string}  opts.keyId    Your HMAC credential key id.
 * @param {string}  opts.secret   Your HMAC credential SIGNING SECRET (not the key id, not the JWT secret).
 * @param {Buffer|string} [opts.body]  Raw request body — hashed exactly as sent. Pass the SAME bytes you send.
 * @param {object}  [opts.query]  Query params as an object ({} or omit if none).
 * @param {string[]}[opts.signHeaders]  Lowercase header names bound into the signature. MUST be non-empty. Default: ['one-api-hmac-timestamp','one-api-hmac-nonce'].
 * @param {object}  [opts.headerValues]  Values for any extra signed header you bind (e.g. { 'one-context': 'acme-prod' }).
 * @param {string}  [opts.timestamp]  Override (ISO 8601 UTC). Default: now.
 * @param {string}  [opts.nonce]      Override. Default: a fresh UUID.
 * @returns {{['One-Api-Hmac-Key-Id']:string,['One-Api-Hmac-Timestamp']:string,['One-Api-Hmac-Nonce']:string,['One-Api-Hmac-Signed-Headers']:string,['One-Api-Hmac-Signature']:string}}
 */
export function signOneApiRequest({
  method, path, keyId, secret,
  body = Buffer.alloc(0), query,
  signHeaders = ['one-api-hmac-timestamp', 'one-api-hmac-nonce'],
  headerValues = {},
  timestamp, nonce,
}) {
  if (!keyId || !secret) throw new Error('signOneApiRequest: keyId and secret are required.');
  if (!Array.isArray(signHeaders) || signHeaders.length === 0) {
    throw new Error('signOneApiRequest: signHeaders must be non-empty (the verifier rejects an empty envelope).');
  }
  method = String(method).toUpperCase();
  const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(body ?? '', 'utf8');
  const ts = timestamp ?? new Date().toISOString();
  const nc = nonce ?? randomUUID();
  const signedHeaders = signHeaders.map((h) => String(h).trim().toLowerCase()).join(',');
  const sortedQuery = buildSortedQuery(query);
  const bodyHash = createHash('sha256').update(bodyBytes).digest('hex');

  const lines = [method, path, sortedQuery, ts, nc, signedHeaders, bodyHash];
  // Value-binding: append `name:value` for each signed header, in signing order.
  const known = {
    'one-api-hmac-timestamp': ts,
    'one-api-hmac-nonce': nc,
    'one-api-hmac-key-id': keyId,
    'one-api-hmac-signed-headers': signedHeaders,
    ...headerValues,
  };
  for (const name of signHeaders) {
    const n = String(name).trim().toLowerCase();
    lines.push(`${n}:${known[n] ?? ''}`);
  }
  const canonical = lines.join('\n');
  const signature = createHmac('sha256', secret).update(canonical).digest('hex');

  return {
    'One-Api-Hmac-Key-Id': keyId,
    'One-Api-Hmac-Timestamp': ts,
    'One-Api-Hmac-Nonce': nc,
    'One-Api-Hmac-Signed-Headers': signedHeaders,
    'One-Api-Hmac-Signature': signature,
  };
}

export default { signOneApiRequest };
