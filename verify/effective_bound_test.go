// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Effective-bound regressions. A bounded ancestor facet never becomes
// unconstrained because a descendant omitted the field. The effective bound at
// verify is the minimum spendLimit over the bounded ancestors, with the unit
// carried from the nearest bounded ancestor. It is a ceiling derived from the
// artifacts, never a remaining balance.
//
// These need THREE hops to be verdict-visible: with two hops a pairwise check
// and an effective-bound check give the same answer, so a two-hop vector cannot
// distinguish the interpretations.

package verify

import (
	"testing"

	"github.com/aeoess/agent-passport-go/types"
)

// link builds a chain link with explicit linkage and depth.
func link(by, to string, depth int, limit *float64, unit string) types.Delegation {
	d := depth
	max := 5
	return types.Delegation{
		DelegationID:   by + "->" + to,
		DelegatedBy:    by,
		DelegatedTo:    to,
		Scope:          []string{"data:read"},
		SpendLimit:     limit,
		SpendLimitUnit: unit,
		MaxDepth:       &max,
		CurrentDepth:   &d,
	}
}

// TestThreeHopSpendLaundering is the mutation sentinel. Reverting the missing
// middle bound to "unconstrained" makes the first row accept.
func TestThreeHopSpendLaundering(t *testing.T) {
	cases := []struct {
		name       string
		mid, leaf  *float64
		wantReject bool
	}{
		{"100 -> absent -> 1000000", nil, npF(1000000), true},
		{"100 -> absent -> 50", nil, npF(50), false},
		{"100 -> 100 -> 100", npF(100), npF(100), false},
		{"100 -> 50 -> 50", npF(50), npF(50), false},
		{"100 -> 101 -> 101", npF(101), npF(101), true},
	}
	for _, c := range cases {
		chain := []types.Delegation{
			link("root", "a", 0, npF(100), ""),
			link("a", "b", 1, c.mid, ""),
			link("b", "c", 2, c.leaf, ""),
		}
		err := VerifyDelegationChain(chain)
		if c.wantReject && err == nil {
			t.Errorf("%s: accepted, must be REJECT", c.name)
		}
		if !c.wantReject && err != nil {
			t.Errorf("%s: rejected (%v), must be ACCEPT", c.name, err)
		}
	}
}

// TestTwoHopSpendTableUnchanged pins the neighbour cases: the direct
// parent/child rows keep the verdicts they had before the effective bound
// existed. 100 -> 100 and 100 -> 50 accept, 100 -> 101 rejects.
func TestTwoHopSpendTableUnchanged(t *testing.T) {
	cases := []struct {
		name       string
		child      *float64
		wantReject bool
	}{
		{"100 -> 100", npF(100), false},
		{"100 -> 50", npF(50), false},
		{"100 -> 101", npF(101), true},
	}
	for _, c := range cases {
		chain := []types.Delegation{
			link("root", "a", 0, npF(100), ""),
			link("a", "b", 1, c.child, ""),
		}
		err := VerifyDelegationChain(chain)
		if c.wantReject != (err != nil) {
			t.Errorf("%s: err=%v, wantReject=%v", c.name, err, c.wantReject)
		}
	}
}

// TestUnitSurvivesOmission: a USD-bound authority cannot erase the unit by
// omitting the spend facet and reappear as JPY or unitless one hop later.
func TestUnitSurvivesOmission(t *testing.T) {
	root := link("root", "a", 0, npF(100), "USD")

	// The middle hop omits the whole spend facet; the leaf reappears as JPY.
	jpy := []types.Delegation{root, link("a", "b", 1, nil, ""), link("b", "c", 2, npF(50), "JPY")}
	if err := VerifyDelegationChain(jpy); err == nil {
		t.Error("USD -> absent -> JPY accepted, must be REJECT")
	}

	// The leaf restates a limit but no unit: unitless under a bounded ancestor
	// is a different unit, so it is refused.
	unitless := []types.Delegation{root, link("a", "b", 1, nil, ""), link("b", "c", 2, npF(50), "")}
	if err := VerifyDelegationChain(unitless); err == nil {
		t.Error("USD -> absent -> unitless-with-limit accepted, must be REJECT")
	}

	// Omitting the facet entirely inherits USD and stays within 100.
	inherit := []types.Delegation{root, link("a", "b", 1, nil, ""), link("b", "c", 2, nil, "")}
	if err := VerifyDelegationChain(inherit); err != nil {
		t.Errorf("USD -> absent -> absent rejected (%v), must be ACCEPT", err)
	}

	// Restating the inherited unit under the effective ceiling is narrowing.
	same := []types.Delegation{root, link("a", "b", 1, nil, ""), link("b", "c", 2, npF(50), "USD")}
	if err := VerifyDelegationChain(same); err != nil {
		t.Errorf("USD -> absent -> USD 50 rejected (%v), must be ACCEPT", err)
	}

	// The inherited unit still carries the inherited ceiling.
	over := []types.Delegation{root, link("a", "b", 1, nil, ""), link("b", "c", 2, npF(101), "USD")}
	if err := VerifyDelegationChain(over); err == nil {
		t.Error("USD -> absent -> USD 101 accepted, must be REJECT")
	}
}

// TestMaxDepthSurvivesOmission: an omitted maxDepth must not erase an ancestor
// depth constraint, and a descendant must not raise it.
func TestMaxDepthSurvivesOmission(t *testing.T) {
	mk := func(by, to string, depth int, max *int) types.Delegation {
		d := depth
		return types.Delegation{
			DelegationID: by + "->" + to, DelegatedBy: by, DelegatedTo: to,
			Scope: []string{"data:read"}, MaxDepth: max, CurrentDepth: &d,
		}
	}
	// root bounds depth at 1; the middle omits maxDepth; the leaf sits at depth 2.
	launder := []types.Delegation{mk("root", "a", 0, npI(1)), mk("a", "b", 1, nil), mk("b", "c", 2, nil)}
	if err := VerifyDelegationChain(launder); err == nil {
		t.Error("maxDepth 1 -> absent -> depth 2 accepted, must be REJECT")
	}
	// A descendant may not raise the ancestor bound by restating a larger one.
	raise := []types.Delegation{mk("root", "a", 0, npI(1)), mk("a", "b", 1, npI(99)), mk("b", "c", 2, npI(99))}
	if err := VerifyDelegationChain(raise); err == nil {
		t.Error("maxDepth 1 -> 99 -> depth 2 accepted, must be REJECT")
	}
	// Staying within the ancestor bound is fine.
	ok := []types.Delegation{mk("root", "a", 0, npI(2)), mk("a", "b", 1, nil), mk("b", "c", 2, nil)}
	if err := VerifyDelegationChain(ok); err != nil {
		t.Errorf("maxDepth 2 -> absent -> depth 2 rejected (%v), must be ACCEPT", err)
	}
}

// TestScopeAbsenceIsZeroAuthority pins the other half of the classification
// rule: absence of a SET decodes to EMPTY, which is zero authority and fails
// closed. A middle hop that carries no scope cannot be used to launder a wider
// scope back in, because the empty set covers nothing.
func TestScopeAbsenceIsZeroAuthority(t *testing.T) {
	mk := func(by, to string, depth int, scope []string) types.Delegation {
		d := depth
		max := 5
		return types.Delegation{
			DelegationID: by + "->" + to, DelegatedBy: by, DelegatedTo: to,
			Scope: scope, MaxDepth: &max, CurrentDepth: &d,
		}
	}
	launder := []types.Delegation{
		mk("root", "a", 0, []string{"data:read"}),
		mk("a", "b", 1, nil),
		mk("b", "c", 2, []string{"data:*"}),
	}
	if err := VerifyDelegationChain(launder); err == nil {
		t.Error("data:read -> absent scope -> data:* accepted, must be REJECT")
	}
	// A hop that narrows to nothing is valid; it simply grants nothing.
	narrowed := []types.Delegation{
		mk("root", "a", 0, []string{"data:read"}),
		mk("a", "b", 1, nil),
		mk("b", "c", 2, nil),
	}
	if err := VerifyDelegationChain(narrowed); err != nil {
		t.Errorf("narrowing to the empty scope rejected (%v), must be ACCEPT", err)
	}
}

// TestNotBeforeSurvivesOmission: an activation floor set by an ancestor is not
// erased by a descendant that omits notBefore, and a descendant may not become
// active earlier than the effective inherited floor.
func TestNotBeforeSurvivesOmission(t *testing.T) {
	mk := func(by, to string, depth int, nbf string) types.Delegation {
		d := depth
		max := 5
		return types.Delegation{
			DelegationID: by + "->" + to, DelegatedBy: by, DelegatedTo: to,
			Scope: []string{"data:read"}, MaxDepth: &max, CurrentDepth: &d, NotBefore: nbf,
		}
	}
	earlier := []types.Delegation{
		mk("root", "a", 0, "2026-06-01T00:00:00Z"),
		mk("a", "b", 1, ""),
		mk("b", "c", 2, "2020-01-01T00:00:00Z"),
	}
	if err := VerifyDelegationChain(earlier); err == nil {
		t.Error("notBefore 2026 -> absent -> 2020 accepted, must be REJECT")
	}
	inherit := []types.Delegation{
		mk("root", "a", 0, "2026-06-01T00:00:00Z"),
		mk("a", "b", 1, ""),
		mk("b", "c", 2, ""),
	}
	if err := VerifyDelegationChain(inherit); err != nil {
		t.Errorf("notBefore 2026 -> absent -> absent rejected (%v), must be ACCEPT", err)
	}
	later := []types.Delegation{
		mk("root", "a", 0, "2026-06-01T00:00:00Z"),
		mk("a", "b", 1, ""),
		mk("b", "c", 2, "2026-07-01T00:00:00Z"),
	}
	if err := VerifyDelegationChain(later); err != nil {
		t.Errorf("notBefore 2026-06 -> absent -> 2026-07 rejected (%v), must be ACCEPT", err)
	}
	garbage := []types.Delegation{
		mk("root", "a", 0, "2026-06-01T00:00:00Z"),
		mk("a", "b", 1, "not-a-timestamp"),
	}
	if err := VerifyDelegationChain(garbage); err == nil {
		t.Error("unparseable notBefore accepted, must be REJECT (fail closed)")
	}
}

// An explicit empty chain is not a valid delegation. Returning nil read
// "nothing to narrow" as "narrowing satisfied"; Rust and Python both refuse.
func TestEmptyTypedChainFailsClosed(t *testing.T) {
	if err := VerifyDelegationChain(nil); err == nil {
		t.Error("nil chain accepted, must fail closed")
	}
	if err := VerifyDelegationChain([]types.Delegation{}); err == nil {
		t.Error("empty chain accepted, must fail closed")
	}
	one := link("root", "a", 0, npF(100), "")
	if err := VerifyDelegationChain([]types.Delegation{one}); err != nil {
		t.Errorf("single-link chain rejected (%v), must be ACCEPT", err)
	}
}
