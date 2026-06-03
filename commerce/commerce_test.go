// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package commerce

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// Deterministic key material for every cross-impl test below. The private key
// is sha256("aps-go-commerce-key"); the TS reference derives the same seed the
// same way, so Go and TS sign with byte-identical Ed25519 keys.
//
// These constants were produced at build time by the reference TypeScript SDK
// (publicKeyFromPrivate in src/crypto/keys.ts) and pinned here. Do not edit by
// hand; regenerate from the TS reference if the derivation changes.
const (
	testPrivHex = "278bdb0479963b56abcb528d3aecdd14646e635b3b624af33b4a627e28e3239e"
	testPubHex  = "5371810cce53c42037af0ead3a7ccd8009e14fe0b0f862ca8a0f335e8b70243b"
)

// TestSeedDerivationMatchesTS confirms the Go-derived public key equals the
// reference SDK public key for the shared deterministic seed, so any signature
// comparison below is meaningful.
func TestSeedDerivationMatchesTS(t *testing.T) {
	sum := sha256.Sum256([]byte("aps-go-commerce-key"))
	gotPriv := hex.EncodeToString(sum[:])
	if gotPriv != testPrivHex {
		t.Fatalf("seed derivation drift: got %s want %s", gotPriv, testPrivHex)
	}
	gotPub, err := keys.PublicKeyFromPrivate(gotPriv)
	if err != nil {
		t.Fatal(err)
	}
	if gotPub != testPubHex {
		t.Fatalf("public key drift: got %s want %s", gotPub, testPubHex)
	}
}

// sampleReceipt builds the same fully-deterministic commerce receipt used to
// produce the pinned TS reference values. No randomness, no wall clock.
func sampleReceipt() CommerceActionReceipt {
	return CommerceActionReceipt{
		ReceiptID:    "rcpt-commerce-0011223344556677",
		Version:      "1.0",
		Timestamp:    "2026-06-03T12:00:00Z",
		AgentID:      "ag_commerce_001",
		DelegationID: "del_commerce_001",
		Action: ReceiptAction{
			Type:      "commerce:create_checkout",
			Target:    "https://merchant.example.com/checkout",
			Method:    "POST",
			ScopeUsed: "commerce:checkout",
			Spend:     Money{Amount: 4999, Currency: "usd"},
		},
		Checkout: ReceiptCheckout{
			SessionID:    "cs_test_abc123",
			MerchantName: "Example Merchant",
			Items: []ReceiptItem{
				{SkuID: "sku_001", Name: "Widget", Quantity: 2, UnitPrice: 2000},
				{SkuID: "sku_002", Name: "Gadget", Quantity: 1, UnitPrice: 999},
			},
			TotalAmount:   4999,
			TotalCurrency: "usd",
			Status:        "open",
		},
		DelegationChain: []string{"pub_principal_human", "pub_agent_001"},
		Beneficiary:     "human_principal_001",
	}
}

// TestSignCommerceReceiptCrossImpl is the round-trip oracle for the receipt
// signing primitive. The expected canonical SHA-256 and signature hex were
// produced at build time by the reference TypeScript signCommerceReceipt path
// (sign(canonicalize(receipt minus signature), priv) in src/core/commerce.ts
// over the same deterministic receipt). Go must match both byte for byte.
func TestSignCommerceReceiptCrossImpl(t *testing.T) {
	// Produced by the TS reference SDK at build time over the sampleReceipt
	// inputs. See the build report: "Go == TS".
	const wantCanonSHA = "5fd9d0bbb8da0eaf33b369b20437e07fc54b553d90ddcc3e79f7571e18927506"
	const wantSig = "f30f089cd77ec4ed9233c96aaac941a22b5678807ff36ecf00b8bd3e81b5c8de" +
		"97bb1bb289055a99882775f30f60332c5115a1c45d95740474216cad315c910f"

	receipt := sampleReceipt()

	// (a) canonical preimage bytes must match the TS canonical bytes.
	body, err := structToMap(receipt)
	if err != nil {
		t.Fatal(err)
	}
	delete(body, "signature")
	canonHash, err := jcs.CanonicalHash(body)
	if err != nil {
		t.Fatal(err)
	}
	if canonHash != wantCanonSHA {
		canon, _ := jcs.Canonicalize(body)
		t.Fatalf("canonical bytes differ from TS:\n got sha256 %s\nwant sha256 %s\n canon=%s",
			canonHash, wantCanonSHA, canon)
	}

	// (b) signature hex must match the TS signature hex.
	signed, err := SignCommerceReceipt(receipt, testPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature != wantSig {
		t.Fatalf("signature differs from TS:\n got %s\nwant %s", signed.Signature, wantSig)
	}

	// (c) a Go-created receipt verifies under the Go verifier.
	ok, errs := VerifyCommerceReceipt(signed, testPubHex)
	if !ok {
		t.Fatalf("Go receipt failed Go verification: %v", errs)
	}

	// (d) a TS-created receipt (its signature is wantSig) verifies under Go.
	tsReceipt := sampleReceipt()
	tsReceipt.Signature = wantSig
	ok, errs = VerifyCommerceReceipt(tsReceipt, testPubHex)
	if !ok {
		t.Fatalf("TS receipt failed Go verification: %v", errs)
	}
}

// TestVerifyCommerceReceiptTamper confirms a mutated receipt body fails the
// signature check (the signed bytes no longer match) and that missing required
// fields are reported.
func TestVerifyCommerceReceiptTamper(t *testing.T) {
	signed, err := SignCommerceReceipt(sampleReceipt(), testPrivHex)
	if err != nil {
		t.Fatal(err)
	}

	tampered := signed
	tampered.Checkout.TotalAmount = 1 // body changed, signature stale
	ok, errs := VerifyCommerceReceipt(tampered, testPubHex)
	if ok {
		t.Fatal("tampered receipt unexpectedly verified")
	}
	if !containsStr(errs, "Commerce receipt signature is invalid") {
		t.Fatalf("expected signature-invalid error, got %v", errs)
	}

	missing := signed
	missing.Beneficiary = ""
	ok, errs = VerifyCommerceReceipt(missing, testPubHex)
	if ok {
		t.Fatal("receipt missing beneficiary unexpectedly verified")
	}
	if !containsStr(errs, "Missing beneficiary") {
		t.Fatalf("expected missing-beneficiary error, got %v", errs)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
