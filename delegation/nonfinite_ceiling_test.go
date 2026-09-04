// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package delegation

import (
	"fmt"
	"testing"

	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

// A non-finite spend ceiling erases the bound, because every comparison against
// NaN is false. commerce.RecordSpend already guards the spend AMOUNT this way.
func TestNonFiniteSpendCeilingIsRefused(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	nan := 0.0
	nan = nan / nan
	inf := math_Inf()
	mk := func(i int, limit *float64) types.Delegation {
		d := i
		max := 9
		return types.Delegation{
			DelegationID: fmt.Sprintf("d%d", i), DelegatedBy: fmt.Sprintf("k%d", i),
			DelegatedTo: fmt.Sprintf("k%d", i+1), Scope: []string{"data:read"},
			SpendLimit: limit, MaxDepth: &max, CurrentDepth: &d,
		}
	}
	rising := []types.Delegation{mk(0, &nan), mk(1, f(1e12)), mk(2, f(2e12)), mk(3, f(3e12)), mk(4, f(4e12))}
	if err := verify.VerifyDelegationChain(rising); err == nil {
		t.Error("a NaN root ceiling admitted a chain whose ceilings increase at every hop")
	}
	if err := verify.VerifyDelegationChain([]types.Delegation{mk(0, &inf)}); err == nil {
		t.Error("an infinite ceiling accepted")
	}
}

func math_Inf() float64 {
	big := 1e308
	return big * 10
}
