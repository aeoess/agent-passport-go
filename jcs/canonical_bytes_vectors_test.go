// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Loader parity test for the shared canonical-bytes JCS vectors, generated from
// the TS SDK canonicalizeJCS reference. Proves the Go Canonicalize produces
// byte-identical canonical output and SHA-256 for each (cross-language parity
// on the byte-contract cases).
func TestCanonicalBytesJCSParity(t *testing.T) {
	data, err := os.ReadFile("testdata/canonical-bytes-jcs-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Name            string          `json:"name"`
			Input           json.RawMessage `json:"input"`
			Canonical       string          `json:"canonical"`
			CanonicalBytes  string          `json:"canonical_bytes_hex"`
			CanonicalSHA256 string          `json:"canonical_sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Vectors) != 8 {
		t.Fatalf("expected 8 vectors, got %d", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		var input interface{}
		if err := json.Unmarshal(v.Input, &input); err != nil {
			t.Errorf("%s: unmarshal input: %v", v.Name, err)
			continue
		}
		canon, err := Canonicalize(input)
		if err != nil {
			t.Errorf("%s: canonicalize: %v", v.Name, err)
			continue
		}
		if canon != v.Canonical {
			t.Errorf("%s: canonical\n got  %q\n want %q", v.Name, canon, v.Canonical)
		}
		if got := hex.EncodeToString([]byte(canon)); got != v.CanonicalBytes {
			t.Errorf("%s: canonical_bytes_hex mismatch", v.Name)
		}
		sum := sha256.Sum256([]byte(canon))
		if got := hex.EncodeToString(sum[:]); got != v.CanonicalSHA256 {
			t.Errorf("%s: canonical_sha256 mismatch", v.Name)
		}
	}
}
