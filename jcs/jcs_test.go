// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package jcs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// decodeJSON decodes a JSON document into Go generic types, keeping numbers as
// json.Number so canonicalization sees the exact numeric token.
func decodeJSON(t *testing.T, raw []byte) interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

// TestBilateralFixtureByteEquality is the load-bearing conformance check. It
// reads the shared APS conformance fixture (a copy of
// aps-conformance-suite/fixtures/bilateral-delegation) and asserts that our Go
// canonicalizer produces, for every vector, the exact canonical_bytes_hex and
// canonical_sha256 recorded by the reference TypeScript implementation. These
// expected values were not authored here; they ship with the fixture.
func TestBilateralFixtureByteEquality(t *testing.T) {
	raw, err := os.ReadFile("testdata/bilateral-canonicalize-fixture-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture struct {
		Vectors []struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			CanonicalBytesHex string          `json:"canonical_bytes_hex"`
			CanonicalSHA256   string          `json:"canonical_sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}
	pass := 0
	for _, v := range fixture.Vectors {
		input := decodeJSON(t, v.Input)
		canon, err := Canonicalize(input)
		if err != nil {
			t.Errorf("%s: canonicalize error: %v", v.Name, err)
			continue
		}
		gotHex := hex.EncodeToString([]byte(canon))
		if gotHex != v.CanonicalBytesHex {
			t.Errorf("%s: canonical_bytes_hex mismatch\n got: %s\nwant: %s\n canon: %s",
				v.Name, gotHex, v.CanonicalBytesHex, canon)
			continue
		}
		gotSHA, err := CanonicalHash(input)
		if err != nil {
			t.Errorf("%s: hash error: %v", v.Name, err)
			continue
		}
		if gotSHA != v.CanonicalSHA256 {
			t.Errorf("%s: canonical_sha256 mismatch got=%s want=%s", v.Name, gotSHA, v.CanonicalSHA256)
			continue
		}
		pass++
	}
	t.Logf("bilateral fixture: %d/%d vectors byte-identical", pass, len(fixture.Vectors))
}

// TestPublishedCrossLanguageVectors asserts byte-equality against the APS
// canonicalization cross-language vectors (cv-001..cv-010 from
// src/core/canonical-jcs.ts getTestVectors). expected_jcs is the published
// reference output. Inputs are given as raw JSON and decoded with UseNumber so
// the numeric tokens match what the reference parsed.
func TestPublishedCrossLanguageVectors(t *testing.T) {
	cases := []struct {
		id       string
		input    string
		expected string
	}{
		{"cv-001", `{"agentId":"agent-001","scope":"read"}`, `{"agentId":"agent-001","scope":"read"}`},
		{"cv-002", `{"agentId":"agent-001","metadata":null,"scope":"read"}`, `{"agentId":"agent-001","metadata":null,"scope":"read"}`},
		{"cv-003", `{"zebra":1,"alpha":2,"middle":3}`, `{"alpha":2,"middle":3,"zebra":1}`},
		{"cv-004", `{"outer":{"inner":null,"value":42},"top":"ok"}`, `{"outer":{"inner":null,"value":42},"top":"ok"}`},
		{"cv-005", `{"items":[1,null,3]}`, `{"items":[1,null,3]}`},
		{"cv-006", `{"integer":42,"negative":-7,"float":3.14,"zero":0}`, `{"float":3.14,"integer":42,"negative":-7,"zero":0}`},
		{"cv-007", `{"emptyArr":[],"emptyObj":{}}`, `{"emptyArr":[],"emptyObj":{}}`},
		{"cv-008", `{"name":"Тимофій","emoji":"🔐"}`, `{"emoji":"🔐","name":"Тимофій"}`},
		{"cv-009", `{"delegationId":"del_abc123","delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","scope":["data:read","commerce:checkout"],"spendLimit":500,"obligationBundleHash":null,"expiresAt":"2026-04-01T00:00:00Z","notBefore":null,"maxDepth":3,"currentDepth":1,"createdAt":"2026-03-29T00:00:00Z"}`, `{"createdAt":"2026-03-29T00:00:00Z","currentDepth":1,"delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","delegationId":"del_abc123","expiresAt":"2026-04-01T00:00:00Z","maxDepth":3,"notBefore":null,"obligationBundleHash":null,"scope":["data:read","commerce:checkout"],"spendLimit":500}`},
		{"cv-010", `{"active":true,"revoked":false}`, `{"active":true,"revoked":false}`},
	}
	for _, c := range cases {
		input := decodeJSON(t, []byte(c.input))
		got, err := Canonicalize(input)
		if err != nil {
			t.Errorf("%s: %v", c.id, err)
			continue
		}
		if got != c.expected {
			t.Errorf("%s: mismatch\n got: %s\nwant: %s", c.id, got, c.expected)
		}
	}
}
