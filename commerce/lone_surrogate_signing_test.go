// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package commerce

import (
	"errors"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

// wtf8LoneSurrogate is the WTF-8 encoding of U+D800, built from raw bytes so it
// reaches the signing path without ever passing through Unmarshal (the way a
// gRPC/protobuf endpoint or an unvalidating DB driver would deliver it).
var wtf8LoneSurrogate = string([]byte{0xED, 0xA0, 0x80})

// TestSignCommerceReceiptRejectsLoneSurrogate proves the marshal-phase guard:
// a lone surrogate anywhere in the typed receipt is rejected before json.Marshal
// can rewrite it to U+FFFD, and NO signature is produced.
func TestSignCommerceReceiptRejectsLoneSurrogate(t *testing.T) {
	mutations := map[string]func(*CommerceActionReceipt){
		"top-level string field":   func(r *CommerceActionReceipt) { r.Beneficiary = wtf8LoneSurrogate },
		"nested struct field":      func(r *CommerceActionReceipt) { r.Action.Type = wtf8LoneSurrogate },
		"slice element":            func(r *CommerceActionReceipt) { r.Checkout.Items[0].Name = wtf8LoneSurrogate },
		"delegation-chain element": func(r *CommerceActionReceipt) { r.DelegationChain[0] = wtf8LoneSurrogate },
	}
	for name, mutate := range mutations {
		r := sampleReceipt()
		mutate(&r)
		signed, err := SignCommerceReceipt(r, testPrivHex)
		if err == nil {
			t.Errorf("%s: expected rejection before signing, got nil", name)
		} else if !errors.Is(err, jcs.ErrLoneSurrogate) {
			t.Errorf("%s: want ErrLoneSurrogate, got %v", name, err)
		}
		if signed.Signature != "" {
			t.Errorf("%s: a signature was produced over a rejected value: %q", name, signed.Signature)
		}
	}
}

// TestSignCommerceReceiptAcceptsValidScalars proves no over-rejection: a valid
// non-BMP scalar and a legitimate U+FFFD sign unchanged.
func TestSignCommerceReceiptAcceptsValidScalars(t *testing.T) {
	for name, s := range map[string]string{"non-BMP scalar": "\U0001F600", "U+FFFD": "�"} {
		r := sampleReceipt()
		r.Checkout.MerchantName = s
		signed, err := SignCommerceReceipt(r, testPrivHex)
		if err != nil {
			t.Errorf("%s: expected accept, got %v", name, err)
		}
		if signed.Signature == "" {
			t.Errorf("%s: no signature produced for a valid input", name)
		}
	}
}
