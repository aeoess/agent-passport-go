// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// expiresAt and notBefore are part of the signed bytes, so a verifier that
// ignores them is checking less than the delegator signed. VerifyDelegation used
// to be signature-only with no clock: a delegation that expired in 2020 verified
// true, and so did one whose notBefore is in 2099.

package delegation

import (
	"testing"

	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

func mustSign(t *testing.T, opts CreateOptions) types.Delegation {
	t.Helper()
	opts.PrivateKey = seed()
	opts.DelegatedBy = wantPub
	d, err := CreateDelegation(opts)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestVerifyDelegationAtEnforcesTheValidityWindow(t *testing.T) {
	d := mustSign(t, CreateOptions{
		DelegationID: "del_window", DelegatedTo: "did:aps:b", Scope: []string{"data:read"},
		MaxDepth: 1, CurrentDepth: 0,
		NotBefore: "2026-06-01T00:00:00.000Z", ExpiresAt: "2026-07-01T00:00:00.000Z",
	})
	cases := []struct {
		now  string
		want error
	}{
		{"2026-05-31T23:59:59.000Z", ErrNotYetValid},
		{"2026-06-01T00:00:00.000Z", nil}, // notBefore boundary is live
		{"2026-06-15T00:00:00.000Z", nil},
		{"2026-07-01T00:00:00.000Z", nil}, // expiry boundary is live
		{"2026-07-01T00:00:00.001Z", ErrExpired},
		{"2030-01-01T00:00:00.000Z", ErrExpired},
	}
	for _, c := range cases {
		got := VerifyDelegationAt(d, mustTime(t, c.now))
		if got != c.want {
			t.Errorf("VerifyDelegationAt(%s) = %v, want %v", c.now, got, c.want)
		}
	}
	// The signature itself is authentic at every one of those instants.
	if !VerifyDelegationSignature(d) {
		t.Error("VerifyDelegationSignature must stay true regardless of the clock")
	}
}

// A missing expiresAt must fail closed as an invalid expiry rather than meaning
// "never expires". Absence of a temporal ceiling is the same class as absence of
// a numeric ceiling: it must not decode to infinity.
func TestVerifyDelegationAtRequiresAnExpiry(t *testing.T) {
	none := mustSign(t, CreateOptions{
		DelegationID: "del_forever", DelegatedTo: "did:aps:b", Scope: []string{"data:read"},
		MaxDepth: 1, CurrentDepth: 0,
	})
	if got := VerifyDelegationAt(none, mustTime(t, "2026-06-15T00:00:00.000Z")); got != ErrInvalidExpiry {
		t.Errorf("delegation with no expiresAt: got %v, want %v", got, ErrInvalidExpiry)
	}
	garbage := none
	garbage.ExpiresAt = "not-a-timestamp"
	if got := VerifyDelegationAt(garbage, mustTime(t, "2026-06-15T00:00:00.000Z")); got == nil {
		t.Error("unparseable expiresAt accepted, must fail closed")
	}
	badNbf := mustSign(t, CreateOptions{
		DelegationID: "del_badnbf", DelegatedTo: "did:aps:b", Scope: []string{"data:read"},
		MaxDepth: 1, CurrentDepth: 0, ExpiresAt: "2026-07-01T00:00:00.000Z", NotBefore: "whenever",
	})
	if got := VerifyDelegationAt(badNbf, mustTime(t, "2026-06-15T00:00:00.000Z")); got != ErrInvalidNotBefore {
		t.Errorf("unparseable notBefore: got %v, want %v", got, ErrInvalidNotBefore)
	}
}

func TestVerifyDelegationAtChecksItsOwnDepthBound(t *testing.T) {
	deep := mustSign(t, CreateOptions{
		DelegationID: "del_deep", DelegatedTo: "did:aps:b", Scope: []string{"data:read"},
		MaxDepth: 1, CurrentDepth: 5, ExpiresAt: "2026-07-01T00:00:00.000Z",
	})
	if got := VerifyDelegationAt(deep, mustTime(t, "2026-06-15T00:00:00.000Z")); got != ErrDepthExceeded {
		t.Errorf("currentDepth 5 > maxDepth 1: got %v, want %v", got, ErrDepthExceeded)
	}
}

// A forged signature stays a signature failure at every instant.
func TestVerifyDelegationAtRejectsForgedSignature(t *testing.T) {
	d := mustSign(t, CreateOptions{
		DelegationID: "del_forge", DelegatedTo: "did:aps:b", Scope: []string{"data:read"},
		MaxDepth: 1, CurrentDepth: 0, ExpiresAt: "2026-07-01T00:00:00.000Z",
	})
	d.Signature = "00" + d.Signature[2:]
	if got := VerifyDelegationAt(d, mustTime(t, "2026-06-15T00:00:00.000Z")); got != ErrInvalidSignature {
		t.Errorf("forged signature: got %v, want %v", got, ErrInvalidSignature)
	}
	if VerifyDelegationSignature(d) {
		t.Error("forged signature passed VerifyDelegationSignature")
	}
}

// The minter must not produce a child that outlives its parent or activates
// before it: SubDelegate applied no temporal narrowing at all, so it minted
// chains this repo's own verifier refuses.
func TestSubDelegateNarrowsTheValidityWindow(t *testing.T) {
	root := boundedRoot(t, "")
	child, err := SubDelegate(SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_mid", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, SpendLimit: f(10),
		ExpiresAt: "2099-01-01T00:00:00.000Z", NotBefore: "2020-01-01T00:00:00.000Z",
		CreatedAt: nbf, Now: mintNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if child.ExpiresAt != rootExp {
		t.Errorf("child expiresAt = %q, want it capped to the parent's %q", child.ExpiresAt, rootExp)
	}
	if child.NotBefore != nbf {
		t.Errorf("child notBefore = %q, want it raised to the parent's %q", child.NotBefore, nbf)
	}
	// Omitting both must inherit, not mint an unbounded window.
	inherited, err := SubDelegate(SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_mid2", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, SpendLimit: f(10), CreatedAt: nbf, Now: mintNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if inherited.ExpiresAt != rootExp || inherited.NotBefore != nbf {
		t.Errorf("omitted window not inherited: expiresAt=%q notBefore=%q", inherited.ExpiresAt, inherited.NotBefore)
	}
	for _, c := range []types.Delegation{child, inherited} {
		if err := verify.VerifyDelegationChain([]types.Delegation{root, c}); err != nil {
			t.Errorf("minted chain refused by this repo's own verifier: %v", err)
		}
	}
}
