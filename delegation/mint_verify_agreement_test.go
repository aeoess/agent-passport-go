// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Minting and verification must agree. SubDelegate must never mint a chain the
// repo's own verifier refuses, and must never mint an unbounded child from a
// bounded parent: a bounded ancestor facet does not become unconstrained
// because the sub-delegation call omitted the field.

package delegation

import (
	"testing"

	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

const (
	// Inside every window used below, so the temporal gates are deterministic.
	mintNow = "2026-06-10T00:00:00.000Z"
	nbf     = "2026-06-03T12:00:00.000Z"
	rootExp = "2026-12-31T00:00:00.000Z"
)

func boundedRoot(t *testing.T, unit string) types.Delegation {
	t.Helper()
	root, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_root", DelegatedBy: wantPub, DelegatedTo: wantPub,
		Scope: []string{"data:*"}, SpendLimit: f(100), SpendLimitUnit: unit,
		MaxDepth: 3, CurrentDepth: 0, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestSubDelegateMaterializesInheritedSpendLimit is the mint half of the
// three-hop laundering vector. Omitting SpendLimit on the middle hop must not
// mint a child that lets a grandchild claim more than the root allowed.
func TestSubDelegateMaterializesInheritedSpendLimit(t *testing.T) {
	root := boundedRoot(t, "")
	mid, err := SubDelegate(SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_mid", DelegatedTo: wantPub,
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
		Now: mintNow,
	})
	if err != nil {
		t.Fatalf("valid sub-delegation rejected: %v", err)
	}
	if mid.SpendLimit == nil {
		t.Fatal("SubDelegate minted an unbounded child from a bounded parent")
	}
	if *mid.SpendLimit != 100 {
		t.Errorf("child spendLimit = %v, want the inherited 100", *mid.SpendLimit)
	}
	if !VerifyDelegation(mid) {
		t.Error("materialized child does not verify against its own signature")
	}
	// The grandchild attempt that the laundering vector needs must be refused
	// at mint, because the middle hop now carries the inherited ceiling.
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: mid, PrivateKey: seed(), DelegationID: "del_leaf", DelegatedTo: "did:aps:c",
		Scope: []string{"data:read"}, SpendLimit: f(1000000), ExpiresAt: rootExp,
		NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	}); err == nil {
		t.Error("SubDelegate minted a 1,000,000 grandchild under a 100 root")
	}
	// Anything the minter does produce must satisfy the verifier.
	leaf, err := SubDelegate(SubDelegateOptions{
		Parent: mid, PrivateKey: seed(), DelegationID: "del_leaf", DelegatedTo: "did:aps:c",
		Scope: []string{"data:read"}, SpendLimit: f(50), ExpiresAt: rootExp,
		NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	})
	if err != nil {
		t.Fatalf("narrowing grandchild rejected at mint: %v", err)
	}
	if err := verify.VerifyDelegationChain([]types.Delegation{root, mid, leaf}); err != nil {
		t.Errorf("minted chain refused by this repo's own verifier: %v", err)
	}
}

// TestSubDelegateCarriesSpendUnit: the unit travels with the materialized
// limit, so a USD budget cannot reappear unlabelled two hops down.
func TestSubDelegateCarriesSpendUnit(t *testing.T) {
	root := boundedRoot(t, "USD")
	mid, err := SubDelegate(SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_mid", DelegatedTo: wantPub,
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
		Now: mintNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mid.SpendLimitUnit != "USD" {
		t.Errorf("child spendLimitUnit = %q, want the inherited USD", mid.SpendLimitUnit)
	}
	// A caller may not convert the unit at the narrowing layer.
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_jpy", DelegatedTo: "did:aps:c",
		Scope: []string{"data:read"}, SpendLimit: f(50), SpendLimitUnit: "JPY",
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	}); err == nil {
		t.Error("SubDelegate converted USD to JPY at the narrowing layer")
	}
}

// TestSubDelegateRefusesExpiredAndPendingParent: minting must consult the
// clock, not only the signature.
func TestSubDelegateRefusesExpiredAndPendingParent(t *testing.T) {
	root := boundedRoot(t, "")
	opts := SubDelegateOptions{
		Parent: root, PrivateKey: seed(), DelegationID: "del_mid", DelegatedTo: wantPub,
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	}
	after := opts
	after.Now = "2027-01-01T00:00:00.000Z"
	if _, err := SubDelegate(after); err == nil {
		t.Error("SubDelegate minted from a parent that expired in 2026")
	}
	before := opts
	before.Now = "2020-01-01T00:00:00.000Z"
	if _, err := SubDelegate(before); err == nil {
		t.Error("SubDelegate minted from a parent whose notBefore has not arrived")
	}
}
