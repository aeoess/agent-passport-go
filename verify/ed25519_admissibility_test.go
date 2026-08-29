// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// admissibilityDoc is testdata/ed25519-admissibility-v1.json: the behaviour on
// which the two strict reference implementations agree, libsodium through
// PyNaCl (agent-passport-python) and ed25519-dalek verify_strict
// (agent-passport-system aps-verifier-core). The same file is used by the
// TypeScript, Rust and Python suites, so all four implementations answer every
// vector the same way by construction.
type admissibilityDoc struct {
	Version string               `json:"version"`
	Count   int                  `json:"count"`
	Vectors []admissibilityVector `json:"vectors"`
}

type admissibilityVector struct {
	ID        string `json:"id"`
	Group     string `json:"group"`
	Note      string `json:"note"`
	Message   string `json:"message_utf8"`
	PublicKey string `json:"public_key_hex"`
	Signature string `json:"signature_hex"`
	Expected  bool   `json:"expected_verification"`
}

func loadAdmissibility(t *testing.T) admissibilityDoc {
	t.Helper()
	raw, err := os.ReadFile("testdata/ed25519-admissibility-v1.json")
	if err != nil {
		t.Fatalf("read admissibility vectors: %v", err)
	}
	var doc admissibilityDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse admissibility vectors: %v", err)
	}
	if doc.Version != "ed25519-admissibility-v1" {
		t.Fatalf("unexpected fixture version %q", doc.Version)
	}
	if len(doc.Vectors) != doc.Count {
		t.Fatalf("fixture declares %d vectors, carries %d", doc.Count, len(doc.Vectors))
	}
	return doc
}

// The Edwards identity point as a public key, and R = the identity with s = 0.
// The RFC 8032 equation degenerates to identity = identity, so this one
// signature verifies under every message unless admissibility is checked.
const (
	identityKey    = "0100000000000000000000000000000000000000000000000000000000000000"
	degenerateSig  = "0100000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
)

func TestAdmissibilityVectorsMatchTheStrictReference(t *testing.T) {
	doc := loadAdmissibility(t)
	var wrong []string
	for _, v := range doc.Vectors {
		got := VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey)
		if got != v.Expected {
			wrong = append(wrong, fmt.Sprintf("%s [%s] expected %v got %v :: %s",
				v.ID, v.Group, v.Expected, got, v.Note))
		}
	}
	if len(wrong) > 0 {
		shown := wrong
		if len(shown) > 12 {
			shown = shown[:12]
		}
		t.Fatalf("%d of %d vectors disagree with the strict reference:\n%s",
			len(wrong), len(doc.Vectors), joinLines(shown))
	}
}

func joinLines(s []string) string {
	out := ""
	for _, line := range s {
		out += line + "\n"
	}
	return out
}

func TestSmallOrderPublicKeyIsRejected(t *testing.T) {
	if VerifyEd25519([]byte("APS admissibility probe"), degenerateSig, identityKey) {
		t.Fatal("a small order public key must not verify")
	}
	if VerifyEd25519([]byte("a completely different message"), degenerateSig, identityKey) {
		t.Fatal("and the degenerate signature must not verify under an unrelated message")
	}
}

func TestEverySmallOrderEncodingIsRejected(t *testing.T) {
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "small_order_pk" && v.Group != "small_order_pk_message_independence" {
			continue
		}
		if VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s accepted a small order public key: %s", v.ID, v.Note)
		}
		n++
	}
	if n != 28 {
		t.Fatalf("expected all eight small order points in every encoding, got %d vectors", n)
	}
}

func TestSmallOrderRUnderAnHonestKeyIsRejected(t *testing.T) {
	// R is the identity and s = k*a mod L, so the cofactorless equation holds
	// exactly under a genuine prime order public key. Only an admissibility
	// test on R refuses it.
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "small_order_R_honest_key" || len(v.ID) < 14 || v.ID[:14] != "smallR-honest-" {
			continue
		}
		if VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s accepted a small order R: %s", v.ID, v.Note)
		}
		n++
	}
	if n < 8 {
		t.Fatalf("expected the honest key small order R vectors, got %d", n)
	}
}

func TestOrdinaryKeysAndSignaturesAreUnaffected(t *testing.T) {
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "normal" {
			continue
		}
		if !VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s is an ordinary valid signature and must still verify", v.ID)
		}
		n++
	}
	if n != 128 {
		t.Fatalf("expected 128 ordinary vectors, got %d", n)
	}
}

func TestDegenerateSignatureIsMessageIndependentAndStillRefused(t *testing.T) {
	for i := 0; i < 256; i++ {
		msg := fmt.Sprintf("unrelated APS artifact body %d", i)
		if VerifyEd25519([]byte(msg), degenerateSig, identityKey) {
			t.Fatalf("message %d accepted the message independent signature", i)
		}
	}
}

// High level paths. VerifyCanonicalSignature is the entry every APS artifact
// verifier in this module reaches: passport issuer signatures, delegation
// links, receipts, coordination artifacts and values attestations. The
// degenerate signature satisfies the RFC 8032 equation whatever the canonical
// bytes are, so only admissibility stops the artifact.
func TestCanonicalArtifactWithSmallOrderSignerIsRefused(t *testing.T) {
	artifacts := []map[string]interface{}{
		{"delegationId": "del_smallorder", "delegatedBy": identityKey,
			"scope": []interface{}{"*"}, "signature": degenerateSig},
		{"agentId": "agent-a", "issuerPublicKey": identityKey, "signature": degenerateSig},
		{"receipt_id": "r1", "kind": "attribution", "signature": degenerateSig},
	}
	for i, obj := range artifacts {
		if VerifyCanonicalSignature(obj, "signature", degenerateSig, identityKey) {
			t.Errorf("artifact %d was accepted under an inadmissible public key", i)
		}
	}
}

func TestChainLinkWithSmallOrderSignerIsRefused(t *testing.T) {
	in := ChainInput{
		Chain: []map[string]interface{}{
			{
				"delegationId":   "del_root",
				"delegator":      identityKey,
				"signature":      degenerateSig,
				"scope":          []interface{}{"*"},
				"validityWindow": map[string]interface{}{"not_after": "2099-01-01T00:00:00Z"},
			},
		},
		Now: "2026-06-01T00:00:00Z",
	}
	if code := ValidateChain(in); code != CodeInvalidSig {
		t.Fatalf("chain with an inadmissible signer key returned %q, want %q", code, CodeInvalidSig)
	}
}
