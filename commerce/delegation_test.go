// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package commerce

import (
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/verify"
)

// TestCreateCommerceDelegationCrossImpl is the round-trip oracle for the signed
// commerce-delegation factory. The pinned canonical SHA-256 and signature hex
// were produced at build time by signing the same typed delegation field set
// with the reference TypeScript sign(canonicalize(delegation minus signature))
// path (src/crypto/keys.ts + src/core/canonical.ts), using the shared
// deterministic seed. Go must match both byte for byte.
func TestCreateCommerceDelegationCrossImpl(t *testing.T) {
	// Produced by the TS reference SDK at build time over the same deterministic
	// delegation field set. See the build report: "Go == TS".
	const wantCanonSHA = "6a4957ab56d60f98f407b08d14bde18d3c15318266449b984d91aaff93790c5e"
	const wantSig = "74ba0d8c53672b47ea59f65db87e9bbdc4e5c74871f164fba091ba0763fc7e23" +
		"e17d959681ce2b92ef4de2871268cf368307db67a372bc2340cea1e4e85fe20f"

	maxDepth := 1
	currentDepth := 0
	opts := CreateCommerceDelegationOptions{
		DelegationID: "del_commerce_typed_01",
		DelegatedBy:  "pub_principal_human",
		DelegatedTo:  "ag_commerce_001",
		SpendLimit:   50000,
		Currency:     "usd",
		ExpiresAt:    "2026-06-04T12:00:00Z",
		NotBefore:    "2026-06-03T12:00:00Z",
		CreatedAt:    "2026-06-03T12:00:00Z",
		MaxDepth:     &maxDepth,
		CurrentDepth: &currentDepth,
	}

	del, err := CreateCommerceDelegation(opts, testPrivHex)
	if err != nil {
		t.Fatal(err)
	}

	// Scope must be the two commerce defaults (no additional scopes here).
	if len(del.Scope) != 2 || del.Scope[0] != "commerce:checkout" || del.Scope[1] != "commerce:browse" {
		t.Fatalf("unexpected commerce scope: %v", del.Scope)
	}

	// (a) canonical preimage bytes must match the TS canonical bytes.
	body, err := structToMap(del)
	if err != nil {
		t.Fatal(err)
	}
	delete(body, "signature")
	canonHash, err := jcs.CanonicalHash(body)
	if err != nil {
		t.Fatal(err)
	}
	if canonHash != wantCanonSHA {
		canon, _ := jcs.Canonicalize(body)
		t.Fatalf("delegation canonical bytes differ from TS:\n got sha256 %s\nwant sha256 %s\n canon=%s",
			canonHash, wantCanonSHA, canon)
	}

	// (b) signature hex must match the TS signature hex.
	if del.Signature != wantSig {
		t.Fatalf("delegation signature differs from TS:\n got %s\nwant %s", del.Signature, wantSig)
	}

	// (c) the Go-created delegation signature verifies under the Go verifier
	//     over the canonical body (Go artifact verifies under Go verify).
	if !verify.VerifyCanonicalSignature(body, "signature", del.Signature, testPubHex) {
		t.Fatal("Go delegation failed Go verification")
	}

	// (d) the TS signature verifies under Go verify over the same canonical body
	//     (TS-created artifact verifies under Go verify).
	if !verify.VerifyCanonicalSignature(body, "signature", wantSig, testPubHex) {
		t.Fatal("TS delegation signature failed Go verification")
	}
}

// TestCreateCommerceDelegationDefaults confirms the factory defaults match the
// reference: currency defaults to usd, scope carries the two commerce defaults
// plus any additional scopes, and depth defaults to 1/0.
func TestCreateCommerceDelegationDefaults(t *testing.T) {
	del, err := CreateCommerceDelegation(CreateCommerceDelegationOptions{
		DelegationID:     "del_x",
		DelegatedBy:      "pub_p",
		DelegatedTo:      "ag_x",
		SpendLimit:       100,
		AdditionalScopes: []string{"commerce:purchase"},
		ExpiresAt:        "2026-06-04T12:00:00Z",
		NotBefore:        "2026-06-03T12:00:00Z",
		CreatedAt:        "2026-06-03T12:00:00Z",
	}, testPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	if del.SpendLimitUnit != "usd" {
		t.Fatalf("currency default: got %q want usd", del.SpendLimitUnit)
	}
	want := []string{"commerce:checkout", "commerce:browse", "commerce:purchase"}
	if len(del.Scope) != len(want) {
		t.Fatalf("scope: got %v want %v", del.Scope, want)
	}
	for i := range want {
		if del.Scope[i] != want[i] {
			t.Fatalf("scope[%d]: got %q want %q", i, del.Scope[i], want[i])
		}
	}
	if del.MaxDepth == nil || *del.MaxDepth != 1 {
		t.Fatalf("maxDepth default: got %v want 1", del.MaxDepth)
	}
	if del.CurrentDepth == nil || *del.CurrentDepth != 0 {
		t.Fatalf("currentDepth default: got %v want 0", del.CurrentDepth)
	}
}
