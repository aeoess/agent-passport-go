// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Regression (round-3): CheckSpendGate must check currency. It compared amounts without checking
// currency, so a EUR purchase passed a USD budget (the SDK does no conversion).

package commerce

import "testing"

func TestCheckSpendGateRejectsCurrencyMismatch(t *testing.T) {
	d := CommerceDelegation{SpendLimit: 100, SpentAmount: 0, Currency: "usd"}
	if CheckSpendGate(d, Money{Amount: 10, Currency: "eur"}).Passed {
		t.Fatal("a EUR purchase against a USD budget must be denied")
	}
	if !CheckSpendGate(d, Money{Amount: 10, Currency: "USD"}).Passed {
		t.Fatal("USD (case-insensitive) against a usd budget must pass")
	}
	if CheckSpendGate(d, Money{Amount: 200, Currency: "usd"}).Passed {
		t.Fatal("amount over budget in a matching currency must still be denied")
	}
}
