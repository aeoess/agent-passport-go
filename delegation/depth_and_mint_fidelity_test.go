// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Findings from the phase 3 blind review.
//
// The minter fabricated a depth ceiling nobody stated, so it produced chains
// this repo's own verifier refuses. The depth rule held to the letter and failed
// in purpose, because a negative currentDepth bought extra hops under any
// ceiling. And nothing checked a chain root against its own bounds.

package delegation

import (
	"fmt"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

// An absent parent ceiling stays absent in the child. Defaulting to 1 invented a
// bound nobody stated, and the verifier then refused the chain the minter had
// just produced.
func TestSubDelegateDoesNotFabricateMaxDepth(t *testing.T) {
	one := 1
	parent := types.Delegation{
		DelegationID: "del_root", DelegatedBy: wantPub, DelegatedTo: wantPub,
		Scope: []string{"data:*"}, MaxDepth: nil, CurrentDepth: &one,
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	}
	sig, err := keys.SignArtifact(canonicalMap(parent), "signature", seed())
	if err != nil {
		t.Fatal(err)
	}
	parent.Signature = sig

	child, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "del_child", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	})
	if err != nil {
		t.Fatalf("mint refused: %v", err)
	}
	if child.MaxDepth != nil {
		t.Errorf("child maxDepth = %d, want absent: the parent stated none", *child.MaxDepth)
	}
	if err := verify.VerifyDelegationChain([]types.Delegation{parent, child}); err != nil {
		t.Errorf("the minter produced a chain its own verifier refuses: %v", err)
	}
	// A parent that DOES state a ceiling still passes it down unchanged.
	three := 3
	bounded := parent
	bounded.MaxDepth = &three
	zero := 0
	bounded.CurrentDepth = &zero
	sig, err = keys.SignArtifact(canonicalMap(bounded), "signature", seed())
	if err != nil {
		t.Fatal(err)
	}
	bounded.Signature = sig
	kid, err := SubDelegate(SubDelegateOptions{
		Parent: bounded, PrivateKey: seed(), DelegationID: "del_kid", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if kid.MaxDepth == nil || *kid.MaxDepth != 3 {
		t.Errorf("child maxDepth = %v, want the inherited 3", kid.MaxDepth)
	}
}

// A depth ceiling must bound how long a chain can be. Without a floor on
// currentDepth, maxDepth 2 admitted an eight-link chain in which every hop
// incremented by exactly one and every hop sat at or below the ceiling.
func TestDepthCeilingBoundsChainLength(t *testing.T) {
	mk := func(i, depth, max int) types.Delegation {
		d, m := depth, max
		return types.Delegation{
			DelegationID: fmt.Sprintf("d%d", i),
			DelegatedBy:  fmt.Sprintf("k%d", i), DelegatedTo: fmt.Sprintf("k%d", i+1),
			Scope: []string{"data:read"}, MaxDepth: &m, CurrentDepth: &d,
		}
	}
	long := []types.Delegation{}
	for i := 0; i < 8; i++ {
		long = append(long, mk(i, -5+i, 2))
	}
	if err := VerifyChainOrFail(long); err == nil {
		t.Error("maxDepth 2 admitted an eight-link chain starting at currentDepth -5")
	}
	// The honest chain under the same ceiling is exactly three links: 0, 1, 2.
	ok := []types.Delegation{mk(0, 0, 2), mk(1, 1, 2), mk(2, 2, 2)}
	if err := VerifyChainOrFail(ok); err != nil {
		t.Errorf("depths 0,1,2 under maxDepth 2 rejected: %v", err)
	}
	tooLong := append(append([]types.Delegation{}, ok...), mk(3, 3, 2))
	if err := VerifyChainOrFail(tooLong); err == nil {
		t.Error("a fourth link at depth 3 accepted under maxDepth 2")
	}
	// A single negative link is refused on its own, at the root.
	if err := VerifyChainOrFail([]types.Delegation{mk(0, -1, 2)}); err == nil {
		t.Error("a root at currentDepth -1 accepted")
	}
	// A negative ceiling is refused too.
	if err := VerifyChainOrFail([]types.Delegation{mk(0, 0, -1)}); err == nil {
		t.Error("a root with maxDepth -1 accepted")
	}
}

// VerifyChainOrFail keeps the test readable; the verifier lives in another
// package and this test is about the minter and the verifier agreeing.
func VerifyChainOrFail(chain []types.Delegation) error {
	return verify.VerifyDelegationChain(chain)
}

// A chain root must be checked against its own bounds. Nothing did: the a2a map
// shape that VerifyChainAuthorization reads carries no depth members, and there
// is no Go authorization function over a typed chain.
func TestRootIsCheckedAgainstItsOwnBounds(t *testing.T) {
	if _, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_bad", DelegatedBy: wantPub, DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, MaxDepth: 1, CurrentDepth: 5,
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	}); err == nil {
		t.Error("CreateDelegation minted currentDepth 5 under maxDepth 1")
	}
	if _, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_neg", DelegatedBy: wantPub, DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, MaxDepth: 3, CurrentDepth: -1,
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	}); err == nil {
		t.Error("CreateDelegation minted a negative currentDepth")
	}
	// The verifier refuses the same shape independently of the minter.
	five, one := 5, 1
	root := types.Delegation{
		DelegationID: "del_bad", DelegatedBy: wantPub, DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, MaxDepth: &one, CurrentDepth: &five,
	}
	if err := verify.VerifyDelegationChain([]types.Delegation{root}); err == nil {
		t.Error("VerifyDelegationChain([root]) returned nil for currentDepth 5 under maxDepth 1")
	}
}

// B10 from the review: no test asserted that SubDelegate refuses on depth.
func TestSubDelegateRefusesOnDepth(t *testing.T) {
	parent, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_root", DelegatedBy: wantPub, DelegatedTo: wantPub,
		Scope: []string{"data:*"}, MaxDepth: 1, CurrentDepth: 1,
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "del_child", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	}); err == nil {
		t.Error("SubDelegate minted a child at depth 2 under maxDepth 1")
	}
	// The boundary case, depth 1 under maxDepth 1, is allowed.
	room, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_room", DelegatedBy: wantPub, DelegatedTo: wantPub,
		Scope: []string{"data:*"}, MaxDepth: 1, CurrentDepth: 0,
		ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: room, PrivateKey: seed(), DelegationID: "del_ok", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, ExpiresAt: rootExp, NotBefore: nbf, CreatedAt: nbf, Now: mintNow,
	}); err != nil {
		t.Errorf("depth 1 under maxDepth 1 refused: %v", err)
	}
}

// P1 from the review: a mutant here panicked on a nil dereference, which means
// nothing exercised currentDepth present with maxDepth absent.
func TestOwnDepthBoundWithAbsentCeiling(t *testing.T) {
	five := 5
	d := types.Delegation{
		DelegationID: "del_nomax", DelegatedBy: wantPub, DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, CurrentDepth: &five, MaxDepth: nil,
		ExpiresAt: rootExp,
	}
	sig, err := keys.SignArtifact(canonicalMap(d), "signature", seed())
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = sig
	// No ceiling is stated, so there is no ceiling to exceed. The delegation is
	// valid on depth grounds, and must not panic on the absent pointer.
	if err := VerifyDelegationAt(d, mustTime(t, "2026-06-10T00:00:00.000Z")); err != nil {
		t.Errorf("currentDepth present with maxDepth absent: %v, want valid", err)
	}
	// The mirror: maxDepth present, currentDepth absent, treated as 0.
	one := 1
	e := d
	e.CurrentDepth = nil
	e.MaxDepth = &one
	sig, err = keys.SignArtifact(canonicalMap(e), "signature", seed())
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = sig
	if err := VerifyDelegationAt(e, mustTime(t, "2026-06-10T00:00:00.000Z")); err != nil {
		t.Errorf("maxDepth present with currentDepth absent: %v, want valid", err)
	}
}
