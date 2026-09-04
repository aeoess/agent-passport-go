// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// A chain that is internally well signed is not thereby authorized. Chain
// validation had no trust root at all, so a chain an attacker minted from their
// own freshly generated root passed every gate and came back with the same ""
// that a legitimate chain gets.

package verify_test

import (
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

func attackerChain(t *testing.T) (verify.ChainInput, string) {
	t.Helper()
	evil, _ := keys.GenerateKeyPair()
	mid, _ := keys.GenerateKeyPair()
	leaf, _ := keys.GenerateKeyPair()
	big := 10
	return verify.ChainInput{Chain: []map[string]interface{}{
		signedLink(t, evil.PrivateKey, evil.PublicKey, mid.PublicKey, []interface{}{"data:read"}),
		signedLink(t, mid.PrivateKey, mid.PublicKey, leaf.PublicKey, []interface{}{"data:read"}),
	}, MaxDepth: &big, Now: "2026-06-01T00:00:00Z"}, evil.PublicKey
}

func TestStructuralPassIsNotAuthorization(t *testing.T) {
	chain, evilRoot := attackerChain(t)

	// The structure really is sound. That is the point: structure is not trust.
	if code := verify.ValidateChainStructure(chain); code != "" {
		t.Fatalf("attacker chain is structurally sound by construction, got %q", code)
	}

	// With no trusted roots, nothing is authorized.
	if _, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{}); code != verify.CodeUntrustedRoot {
		t.Errorf("empty trusted set: got %q, want %q", code, verify.CodeUntrustedRoot)
	}

	// Trusting somebody else does not authorize the attacker's root.
	other, _ := keys.GenerateKeyPair()
	if _, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{
		TrustedRoots: []string{other.PublicKey},
	}); code != verify.CodeUntrustedRoot {
		t.Errorf("unrelated trusted root: got %q, want %q", code, verify.CodeUntrustedRoot)
	}

	// Trusting the root is still not enough without revocation context: the
	// answer is indeterminate, never a positive authorization.
	if _, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{
		TrustedRoots: []string{evilRoot},
	}); code != verify.CodeRevocationIndeterminate {
		t.Errorf("no revocation resolver: got %q, want %q", code, verify.CodeRevocationIndeterminate)
	}

	// A resolver that cannot answer is also indeterminate, not "not revoked".
	if _, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{
		TrustedRoots: []string{evilRoot},
		Revocation:   func(map[string]interface{}) (bool, bool) { return false, false },
	}); code != verify.CodeRevocationIndeterminate {
		t.Errorf("resolver cannot answer: got %q, want %q", code, verify.CodeRevocationIndeterminate)
	}

	// A resolver that reports a revocation refuses.
	if _, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{
		TrustedRoots: []string{evilRoot},
		Revocation:   func(map[string]interface{}) (bool, bool) { return true, true },
	}); code != verify.CodeRevoked {
		t.Errorf("revoked link: got %q, want %q", code, verify.CodeRevoked)
	}

	// Trusted root plus a resolver that can answer: authorized, and the proof
	// token reports the hops it covered.
	auth, code := verify.VerifyChainAuthorization(chain, verify.AuthorizationOptions{
		TrustedRoots: []string{evilRoot},
		Revocation:   func(map[string]interface{}) (bool, bool) { return false, true },
	})
	if code != "" {
		t.Fatalf("trusted root with a working resolver: got %q, want authorization", code)
	}
	if auth.Hops != 2 {
		t.Errorf("authorization covered %d hops, want 2", auth.Hops)
	}
	if !auth.RevocationChecked {
		t.Error("a successful authorization must report that revocation was established")
	}
}

// The deprecated alias must keep its exact old behaviour.
func TestValidateChainAliasUnchanged(t *testing.T) {
	chain, _ := attackerChain(t)
	if verify.ValidateChain(chain) != verify.ValidateChainStructure(chain) {
		t.Error("ValidateChain and ValidateChainStructure disagree")
	}
	if verify.ValidateChain(verify.ChainInput{Chain: nil}) != verify.CodeInvalidSig {
		t.Error("alias changed the nil-chain refusal")
	}
}

// C6 from the review: the refusal of a link with an empty not_after had no test,
// even though its own comment names the fail-open it prevents. parseMillis("")
// returns the current time, so an empty not_after would otherwise pass the
// expiry gate as though the link expired exactly now.
func TestEmptyNotAfterIsRefused(t *testing.T) {
	a, _ := keys.GenerateKeyPair()
	b, _ := keys.GenerateKeyPair()
	big := 10
	now := "2026-06-01T00:00:00Z"

	link := signedLink(t, a.PrivateKey, a.PublicKey, b.PublicKey, []interface{}{"data:read"})
	link["validityWindow"] = map[string]interface{}{
		"not_before": "2020-01-01T00:00:00Z", "not_after": "",
	}
	sig, err := keys.SignArtifact(link, "signature", a.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	link["signature"] = sig
	in := verify.ChainInput{Chain: []map[string]interface{}{link}, MaxDepth: &big, Now: now}
	if code := verify.ValidateChainStructure(in); code != verify.CodeValidityExp {
		t.Errorf("empty not_after: got %q, want %q", code, verify.CodeValidityExp)
	}

	// An absent validityWindow is the same refusal, not a never-expiring link.
	bare := signedLink(t, a.PrivateKey, a.PublicKey, b.PublicKey, []interface{}{"data:read"})
	delete(bare, "validityWindow")
	sig, err = keys.SignArtifact(bare, "signature", a.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bare["signature"] = sig
	in = verify.ChainInput{Chain: []map[string]interface{}{bare}, MaxDepth: &big, Now: now}
	if code := verify.ValidateChainStructure(in); code != verify.CodeValidityExp {
		t.Errorf("absent validityWindow: got %q, want %q", code, verify.CodeValidityExp)
	}

	// A real not_after in the future still passes, so the guard is not blanket.
	good := signedLink(t, a.PrivateKey, a.PublicKey, b.PublicKey, []interface{}{"data:read"})
	in = verify.ChainInput{Chain: []map[string]interface{}{good}, MaxDepth: &big, Now: now}
	if code := verify.ValidateChainStructure(in); code != "" {
		t.Errorf("valid link refused with %q", code)
	}
}
