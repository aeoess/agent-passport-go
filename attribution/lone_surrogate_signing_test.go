// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package attribution

import (
	"errors"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

// wtf8LoneSurrogate is the WTF-8 encoding of U+D800, built from raw bytes so it
// reaches the signing path without ever passing through Unmarshal.
var wtf8LoneSurrogate = string([]byte{0xED, 0xA0, 0x80})

// TestSignReportRejectsLoneSurrogate proves the marshal-phase guard on the
// attribution report signing path: a lone surrogate in the typed report is
// rejected before json.Marshal, and NO signature is produced.
func TestSignReportRejectsLoneSurrogate(t *testing.T) {
	seed := deriveSeed()
	mutations := map[string]func(*AttributionReport){
		"top-level field":       func(r *AttributionReport) { r.Beneficiary = wtf8LoneSurrogate },
		"nested struct field":   func(r *AttributionReport) { r.Period.From = wtf8LoneSurrogate },
		"slice element (entry)": func(r *AttributionReport) { r.Entries[0].Action = wtf8LoneSurrogate },
	}
	for name, mutate := range mutations {
		r := fixtureReport(t)
		mutate(&r)
		signed, err := SignReport(r, seed)
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

// TestHashReceiptRejectsLoneSurrogate proves the guard on the receipt hashing
// path (HashReceipt projects through toGeneric before canonicalizing).
func TestHashReceiptRejectsLoneSurrogate(t *testing.T) {
	r := fixtureReceipt()
	r.Action.Target = wtf8LoneSurrogate
	h, err := HashReceipt(r)
	if err == nil {
		t.Fatalf("expected rejection, got hash %q", h)
	}
	if !errors.Is(err, jcs.ErrLoneSurrogate) {
		t.Errorf("want ErrLoneSurrogate, got %v", err)
	}
	if h != "" {
		t.Errorf("a hash was produced over a rejected value: %q", h)
	}
}

// TestAttributionAcceptsValidScalars proves no over-rejection: a valid non-BMP
// scalar and a legitimate U+FFFD sign and hash unchanged.
func TestAttributionAcceptsValidScalars(t *testing.T) {
	seed := deriveSeed()
	for name, s := range map[string]string{"non-BMP scalar": "\U0001F600", "U+FFFD": "�"} {
		r := fixtureReport(t)
		r.Beneficiary = s
		signed, err := SignReport(r, seed)
		if err != nil {
			t.Errorf("%s: SignReport expected accept, got %v", name, err)
		}
		if signed.Signature == "" {
			t.Errorf("%s: no signature produced for a valid input", name)
		}
		rc := fixtureReceipt()
		rc.Action.Target = s
		if _, err := HashReceipt(rc); err != nil {
			t.Errorf("%s: HashReceipt expected accept, got %v", name, err)
		}
	}
}
