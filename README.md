# @posteering/one-api-signing

Official request signer for the [Posteering One API](https://posteering.com/docs/one-api).
It builds the `One-Api-Hmac-*` signature for the **consumer leg** — your call to the One
API. The gateway threads each product's own downstream credential for you; you never build
a product's signature yourself.

Zero dependencies. Self-contained. Guarded against drift by a fixed test vector checked
against the gateway's own verifier.

## Install

```bash
npm install @posteering/one-api-signing
```

## Use

```js
import { signOneApiRequest } from '@posteering/one-api-signing';

const body = JSON.stringify({
  reference: 'order-123',
  holder_name: 'Payer Name',
  holder_phone: '08012345678',
});

const headers = signOneApiRequest({
  method: 'POST',
  path: '/api/v1/one/products/bankrail-gateway/passthrough/virtual-accounts',
  keyId: process.env.ONE_API_KEY_ID,
  secret: process.env.ONE_API_SECRET,   // your HMAC signing secret
  body: Buffer.from(body, 'utf8'),      // hash the EXACT bytes you send
});

const res = await fetch(
  'https://one.posteering.com/api/v1/one/products/bankrail-gateway/passthrough/virtual-accounts',
  { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body },
);
```

## The three things that cause a signature mismatch

1. **Hash the body as raw bytes, exactly as sent** — don't re-serialize, reorder keys, or
   change whitespace after hashing. Pass the same bytes to `body` that you send.
2. **`signHeaders` must be non-empty** — the verifier rejects an empty envelope. The
   default (`one-api-hmac-timestamp,one-api-hmac-nonce`) is correct for most calls.
3. **Use the signing secret** — not the key id, and not the JWT on-ramp secret. Keep your
   clock within the replay window.

## Binding extra headers

To bind a header's value into the signature (so it can't be tampered with in transit),
list it in `signHeaders` and supply its value in `headerValues`:

```js
signOneApiRequest({
  method: 'POST',
  path: '/api/v1/one/products/ledger/passthrough/accounts',
  keyId, secret,
  body: Buffer.from(body, 'utf8'),
  signHeaders: ['one-api-hmac-timestamp', 'one-api-hmac-nonce', 'one-context'],
  headerValues: { 'one-context': 'acme-prod' },
});
// remember to also SEND the bound header: { 'One-Context': 'acme-prod' }
```

## Other languages

Self-contained signers for **curl**, **Python**, and **Go**, plus a ready-to-import
**Postman collection**, are in [`examples/`](./examples). Each produces the same signature
this package does for the shared test vector.

## Drift guard

The signer is self-contained, so `test/vector.test.mjs` pins it to the gateway verifier:
it asserts the signature for a fixed vector matches the value the server produces. If the
canonical string ever changes, the test fails and a new version ships.

```bash
npm test
```

## Docs

Full reference: https://posteering.com/docs/one-api/authentication

## License

MIT
