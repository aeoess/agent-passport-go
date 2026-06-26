// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Regression tests for the Day 128 same-class sweep findings in VerifyDelegationChain:
// depth was bounded but not required to increment (a flat-depth chain bypassed the bound);
// the spend check ignored the unit (invocations could become currency across a hop); and a
// child that omitted ExpiresAt bypassed the temporal-narrowing check. All are monotonic-narrowing
// violations of the stated invariant (authority only decreases per hop).

package verify

import (
	"testing"

	"github.com/aeoess/agent-passport-go/types"
)

func npI(i int) *int         { return &i }
func npF(f float64) *float64 { return &f }

func TestChainRejectsFlatDepth(t *testing.T) {
	root := types.Delegation{DelegatedBy: "root", DelegatedTo: "a", Scope: []string{"x"}, MaxDepth: npI(5), CurrentDepth: npI(0)}
	flat := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, MaxDepth: npI(5), CurrentDepth: npI(0)}
	if err := VerifyDelegationChain([]types.Delegation{root, flat}); err == nil {
		t.Fatal("flat depth (currentDepth not incremented) must be rejected")
	}
	good := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, MaxDepth: npI(5), CurrentDepth: npI(1)}
	if err := VerifyDelegationChain([]types.Delegation{root, good}); err != nil {
		t.Fatalf("proper depth increment must pass: %v", err)
	}
}

func TestChainRejectsSpendUnitChange(t *testing.T) {
	root := types.Delegation{DelegatedBy: "root", DelegatedTo: "a", Scope: []string{"x"}, SpendLimit: npF(5), SpendLimitUnit: "invocations", MaxDepth: npI(5), CurrentDepth: npI(0)}
	flip := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, SpendLimit: npF(5), SpendLimitUnit: "currency", MaxDepth: npI(5), CurrentDepth: npI(1)}
	if err := VerifyDelegationChain([]types.Delegation{root, flip}); err == nil {
		t.Fatal("spend unit change invocations->currency must be rejected")
	}
	dropped := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, SpendLimit: npF(5), SpendLimitUnit: "", MaxDepth: npI(5), CurrentDepth: npI(1)}
	if err := VerifyDelegationChain([]types.Delegation{root, dropped}); err == nil {
		t.Fatal("dropping the parent's spend unit must be rejected")
	}
	same := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, SpendLimit: npF(3), SpendLimitUnit: "invocations", MaxDepth: npI(5), CurrentDepth: npI(1)}
	if err := VerifyDelegationChain([]types.Delegation{root, same}); err != nil {
		t.Fatalf("same-unit narrowing must pass: %v", err)
	}
}

func TestChainRejectsMissingChildExpiry(t *testing.T) {
	root := types.Delegation{DelegatedBy: "root", DelegatedTo: "a", Scope: []string{"x"}, MaxDepth: npI(5), CurrentDepth: npI(0), ExpiresAt: "2030-01-01T00:00:00.000Z"}
	child := types.Delegation{DelegatedBy: "a", DelegatedTo: "b", Scope: []string{"x"}, MaxDepth: npI(5), CurrentDepth: npI(1), ExpiresAt: ""}
	if err := VerifyDelegationChain([]types.Delegation{root, child}); err == nil {
		t.Fatal("child with no expiry under a parent that has one must be rejected")
	}
}
