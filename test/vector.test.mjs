/**
 * Drift guard. This package's signer is self-contained (it does not import the gateway
 * verifier), so this fixed vector is the contract that keeps it honest: the signature
 * below is the value the One API's own verifier produces for these exact inputs. If the
 * canonical string ever changes server-side, this vector changes and this test fails —
 * which is the signal to publish a new version. Never edit the expected signature to make
 * the test pass; regenerate it from the gateway's verifier.
 *
 * Run: node test/vector.test.mjs
 */
import assert from 'node:assert/strict';
import { signOneApiRequest } from '../index.mjs';

const EXPECTED = '9f2c3688298ef55bb644623e1a2f68c8d857b0b5f1e2996b78fe001b8f4900bd';

const headers = signOneApiRequest({
  method: 'POST',
  path: '/api/v1/one/products/ledger/passthrough/transactions',
  keyId: 'kid_example',
  secret: 'example_secret',
  body: Buffer.from('{"amount":"9007199254740993"}', 'utf8'),
  timestamp: '2026-06-13T00:00:00.000Z',
  nonce: '00000000-0000-4000-8000-000000000000',
});

assert.equal(headers['One-Api-Hmac-Signature'], EXPECTED,
  'signature drift: the signer no longer matches the gateway verifier for the fixed vector');
assert.equal(headers['One-Api-Hmac-Signed-Headers'], 'one-api-hmac-timestamp,one-api-hmac-nonce');
assert.equal(headers['One-Api-Hmac-Key-Id'], 'kid_example');

console.log('vector.test: PASS — signer matches the gateway verifier (9f2c3688…).');
