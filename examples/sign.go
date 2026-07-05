// Self-contained One API signer (Go standard library only).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func buildSortedQuery(query map[string]string) string {
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		ek := strings.ReplaceAll(url.QueryEscape(k), "+", "%20")
		ev := strings.ReplaceAll(url.QueryEscape(query[k]), "+", "%20")
		parts = append(parts, ek+"="+ev)
	}
	return strings.Join(parts, "&")
}

// SignOneApiRequest returns the five One-Api-Hmac-* headers.
func SignOneApiRequest(method, path, keyID, secret string, body []byte,
	query map[string]string, signHeaders []string, timestamp, nonce string) map[string]string {
	method = strings.ToUpper(method)
	if len(signHeaders) == 0 {
		signHeaders = []string{"one-api-hmac-timestamp", "one-api-hmac-nonce"}
	}
	signedHeaders := strings.Join(signHeaders, ",")
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	lines := []string{method, path, buildSortedQuery(query), timestamp, nonce, signedHeaders, bodyHash}
	known := map[string]string{
		"one-api-hmac-timestamp":      timestamp,
		"one-api-hmac-nonce":          nonce,
		"one-api-hmac-key-id":         keyID,
		"one-api-hmac-signed-headers": signedHeaders,
	}
	for _, name := range signHeaders {
		n := strings.ToLower(strings.TrimSpace(name))
		lines = append(lines, n+":"+known[n])
	}
	canonical := strings.Join(lines, "\n")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	return map[string]string{
		"One-Api-Hmac-Key-Id":         keyID,
		"One-Api-Hmac-Timestamp":      timestamp,
		"One-Api-Hmac-Nonce":          nonce,
		"One-Api-Hmac-Signed-Headers": signedHeaders,
		"One-Api-Hmac-Signature":      signature,
	}
}

func main() {
	hdrs := SignOneApiRequest(
		"POST",
		"/api/v1/one/products/ledger/passthrough/transactions",
		"kid_example", "example_secret",
		[]byte(`{"amount":"9007199254740993"}`),
		nil, nil,
		"2026-06-13T00:00:00.000Z",
		"00000000-0000-4000-8000-000000000000",
	)
	for _, k := range []string{"One-Api-Hmac-Key-Id", "One-Api-Hmac-Timestamp", "One-Api-Hmac-Nonce", "One-Api-Hmac-Signed-Headers", "One-Api-Hmac-Signature"} {
		fmt.Printf("%s: %s\n", k, hdrs[k])
	}
}
