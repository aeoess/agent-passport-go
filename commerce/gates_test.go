// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package commerce

import "testing"

func ptrBool(b bool) *bool        { return &b }
func ptrFloat(f float64) *float64 { return &f }

// commerceDelegation is a base delegation for the pure gate tests.
func baseDelegation() CommerceDelegation {
	return CommerceDelegation{
		AgentID:      "ag_commerce_001",
		DelegationID: "del_commerce_001",
		Scope:        []string{"commerce:checkout", "commerce:browse"},
		SpendLimit:   50000,
		SpentAmount:  10000,
		Currency:     "usd",
	}
}

func TestHasCommerceScope(t *testing.T) {
	d := baseDelegation()
	if !HasCommerceScope(d, "commerce:checkout") {
		t.Error("expected commerce:checkout authorized")
	}
	if !HasCommerceScope(d, "commerce:browse") {
		t.Error("expected commerce:browse authorized")
	}
	if HasCommerceScope(d, "commerce:purchase") {
		t.Error("did not expect commerce:purchase authorized")
	}
	// Wildcard scope authorizes everything (verify.ScopeCovers).
	wild := CommerceDelegation{Scope: []string{"commerce:*"}}
	if !HasCommerceScope(wild, "commerce:purchase") {
		t.Error("commerce:* should cover commerce:purchase")
	}
}

func TestCheckScopeGate(t *testing.T) {
	pass := CheckScopeGate(baseDelegation())
	if !pass.Passed || pass.Check != "delegation_scope" {
		t.Fatalf("expected delegation_scope passed, got %+v", pass)
	}
	noScope := CommerceDelegation{Scope: []string{"commerce:browse"}}
	fail := CheckScopeGate(noScope)
	if fail.Passed {
		t.Fatalf("expected scope gate to fail without commerce:checkout, got %+v", fail)
	}
}

func TestCheckSpendGate(t *testing.T) {
	d := baseDelegation() // limit 50000, spent 10000 -> remaining 40000
	within := CheckSpendGate(d, Money{Amount: 40000, Currency: "usd"})
	if !within.Passed || within.Check != "spend_limit" {
		t.Fatalf("expected spend within budget, got %+v", within)
	}
	over := CheckSpendGate(d, Money{Amount: 40001, Currency: "usd"})
	if over.Passed {
		t.Fatalf("expected spend over budget to fail, got %+v", over)
	}
}

func TestCheckHumanApprovalThreshold(t *testing.T) {
	// No approval required -> empty reason.
	d := baseDelegation()
	if r := CheckHumanApprovalThreshold(d, Money{Amount: 99999, Currency: "usd"}); r != "" {
		t.Fatalf("expected no approval reason when not required, got %q", r)
	}
	// Approval required, threshold 25000.
	d.RequireHumanApproval = ptrBool(true)
	d.HumanApprovalThreshold = ptrFloat(25000)
	if r := CheckHumanApprovalThreshold(d, Money{Amount: 25000, Currency: "usd"}); r != "" {
		t.Fatalf("at-threshold should not require approval, got %q", r)
	}
	if r := CheckHumanApprovalThreshold(d, Money{Amount: 25001, Currency: "usd"}); r == "" {
		t.Fatal("over-threshold should require approval")
	}
	// Required but no threshold set -> no reason (TS returns null).
	d.HumanApprovalThreshold = nil
	if r := CheckHumanApprovalThreshold(d, Money{Amount: 99999, Currency: "usd"}); r != "" {
		t.Fatalf("no threshold should mean no approval reason, got %q", r)
	}
}

func TestCheckMerchantGate(t *testing.T) {
	// No allowlist -> no gate applies (TS returns null).
	d := baseDelegation()
	if _, applies := CheckMerchantGate(d, "Example Merchant"); applies {
		t.Fatal("expected no merchant gate when allowlist is empty")
	}
	d.ApprovedMerchants = []string{"Example Merchant", "Other Co"}
	chk, applies := CheckMerchantGate(d, "Example Merchant")
	if !applies || !chk.Passed || chk.Check != "merchant_approved" {
		t.Fatalf("expected approved merchant to pass, got applies=%v chk=%+v", applies, chk)
	}
	chk, applies = CheckMerchantGate(d, "Unknown Shop")
	if !applies || chk.Passed {
		t.Fatalf("expected unapproved merchant to fail, got applies=%v chk=%+v", applies, chk)
	}
}

// passportFixture is the deterministic signed passport whose body and signature
// were produced by the reference TS signPassport path at build time. The
// canonical body matches PASSPORT_CANON and the signature matches PASSPORT_SIG.
func passportFixture() SignedPassport {
	return SignedPassport{
		Passport: map[string]interface{}{
			"agentId":   "ag_commerce_001",
			"publicKey": testPubHex,
			"issuedAt":  "2026-06-03T12:00:00Z",
			"expiresAt": "2030-01-01T00:00:00Z",
		},
		// Produced by TS sign(canonicalize(passport), priv) at build time.
		Signature: "6a032914b88a6325174329653ebbc764b71966527ea5a240d62756c81c39e432" +
			"66f874837d58296f63b290779602c1b170d4a9b11985a1c0d726bf8c18d9060f",
	}
}

// TestCheckPassportGateCrossImpl verifies the Go passport gate accepts a passport
// signed by the reference TS SDK (TS-created artifact verifies under Go), and
// rejects a tampered body.
func TestCheckPassportGateCrossImpl(t *testing.T) {
	sp := passportFixture()
	chk := CheckPassportGate(sp)
	if !chk.Passed || chk.Check != "passport_valid" {
		t.Fatalf("expected passport gate to pass on TS-signed passport, got %+v", chk)
	}

	// Tamper: change a body field so the signature no longer covers it.
	tampered := passportFixture()
	tampered.Passport["agentId"] = "ag_evil_999"
	if CheckPassportGate(tampered).Passed {
		t.Fatal("tampered passport unexpectedly passed the gate")
	}
}

// walletFixture returns the bound wallet whose binding_signature was produced by
// the reference TS bindWallet path at build time (WALLET_SIG over WALLET_PAYLOAD).
func walletFixture() BoundWallet {
	return BoundWallet{
		Chain:   "ethereum",
		Address: "0xAbC0000000000000000000000000000000000001",
		BoundAt: "2026-06-03T12:00:00Z",
		// Produced by TS sign(canonicalize({passport_id,chain,address,bound_at}), priv).
		BindingSignature: "e96e55f0be09ae780f489d5ab38630af374980be2baca1bc4b0e760b1e0d8a83" +
			"886fa03b3a0969ece8804cfad7f1f06fa06b9112a9a3e85561e78d7e34096d0f",
	}
}

// TestCheckWalletGateCrossImpl verifies the Go wallet gate accepts a binding
// signed by the reference TS SDK (TS-created artifact verifies under Go) and
// rejects a wrong address or an absent binding.
func TestCheckWalletGateCrossImpl(t *testing.T) {
	sp := passportFixture()
	wallets := []BoundWallet{walletFixture()}
	ref := WalletRef{Chain: "ethereum", Address: "0xAbC0000000000000000000000000000000000001"}

	chk := CheckWalletGate(sp, wallets, ref)
	if !chk.Passed || chk.Check != "wallet_bound" {
		t.Fatalf("expected wallet gate to pass on TS-signed binding, got %+v", chk)
	}

	// Address not in the bound list.
	otherRef := WalletRef{Chain: "ethereum", Address: "0xDEAD000000000000000000000000000000000000"}
	if CheckWalletGate(sp, wallets, otherRef).Passed {
		t.Fatal("unbound address unexpectedly passed the wallet gate")
	}

	// No bound wallets at all.
	if CheckWalletGate(sp, nil, ref).Passed {
		t.Fatal("empty wallet list unexpectedly passed the wallet gate")
	}
}

func TestExtractDelegationChain(t *testing.T) {
	sp := SignedPassport{Passport: map[string]interface{}{"publicKey": "pub_agent"}}
	chain := ExtractDelegationChain(sp, nil)
	if len(chain) != 1 || chain[0] != "pub_agent" {
		t.Fatalf("expected root chain [pub_agent], got %v", chain)
	}
}
