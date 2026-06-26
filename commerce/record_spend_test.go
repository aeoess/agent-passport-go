// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Regression: spend accumulation (RecordSpend). CheckSpendGate reads
// CommerceDelegation.SpentAmount, which was created at 0 and never written, so
// one delegation passed unlimited purchases against its cap. RecordSpend is the
// stateless write primitive that closes the loop. The cumulative-overspend test
// fails before the fix (RecordSpend did not exist) and passes after.

package commerce

import (
	"math"
	"testing"
)

func mkCommerceDel(limit float64) CommerceDelegation {
	return CommerceDelegation{
		AgentID:      "a",
		DelegationID: "del_1",
		Scope:        []string{"commerce:checkout"},
		SpendLimit:   limit,
		SpentAmount:  0,
		Currency:     "usd",
	}
}

func TestRecordSpend_SecondPurchaseOverCapDenied(t *testing.T) {
	d0 := mkCommerceDel(100)
	if !CheckSpendGate(d0, Money{Amount: 60, Currency: "usd"}).Passed {
		t.Fatal("first purchase of 60 should be within the full budget")
	}
	d1, err := RecordSpend(d0, 60)
	if err != nil {
		t.Fatalf("RecordSpend(60) unexpected error: %v", err)
	}
	if d1.SpentAmount != 60 {
		t.Fatalf("SpentAmount = %v, want 60", d1.SpentAmount)
	}
	if CheckSpendGate(d1, Money{Amount: 60, Currency: "usd"}).Passed {
		t.Fatal("second purchase of 60 should be denied (only 40 remaining)")
	}
}

func TestRecordSpend_PureNoMutation(t *testing.T) {
	d0 := mkCommerceDel(100)
	if _, err := RecordSpend(d0, 25); err != nil {
		t.Fatal(err)
	}
	if d0.SpentAmount != 0 {
		t.Fatalf("input mutated: SpentAmount = %v, want 0", d0.SpentAmount)
	}
}

func TestRecordSpend_RefusesOverLimit(t *testing.T) {
	d1, _ := RecordSpend(mkCommerceDel(100), 80)
	if _, err := RecordSpend(d1, 30); err == nil {
		t.Fatal("expected error: spend would exceed the limit")
	}
}

func TestRecordSpend_RefusesInvalidAmounts(t *testing.T) {
	d0 := mkCommerceDel(100)
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := RecordSpend(d0, bad); err == nil {
			t.Fatalf("expected error for invalid amount %v", bad)
		}
	}
}

func TestRecordSpend_AccumulatesAcrossPurchases(t *testing.T) {
	d := mkCommerceDel(100)
	for _, amt := range []float64{30, 30, 40} {
		var err error
		d, err = RecordSpend(d, amt)
		if err != nil {
			t.Fatal(err)
		}
	}
	if d.SpentAmount != 100 {
		t.Fatalf("SpentAmount = %v, want 100", d.SpentAmount)
	}
	if CheckSpendGate(d, Money{Amount: 1, Currency: "usd"}).Passed {
		t.Fatal("budget exhausted; further spend should be denied")
	}
}
