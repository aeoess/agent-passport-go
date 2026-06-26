// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Regression (round-2 sweep): SubDelegate must verify the parent's signature before minting a
// child. Previously it trusted any parent struct, so a forged/invalid parent could mint an
// authority-bearing child. Parity with the Python sub_delegate parent check.

package delegation

import "testing"

func TestSubDelegateRejectsInvalidParentSignature(t *testing.T) {
	parent, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_root", DelegatedBy: wantPub, DelegatedTo: wantPub,
		Scope: []string{"data:*"}, SpendLimit: f(500), MaxDepth: 3, CurrentDepth: 0,
		ExpiresAt: "2026-12-31T00:00:00.000Z", NotBefore: "2026-06-03T12:00:00.000Z", CreatedAt: "2026-06-03T12:00:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the parent signature so it no longer verifies.
	if parent.Signature[:2] == "00" {
		parent.Signature = "ff" + parent.Signature[2:]
	} else {
		parent.Signature = "00" + parent.Signature[2:]
	}
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "del_child", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, SpendLimit: f(100), ExpiresAt: "2026-06-30T00:00:00.000Z",
		NotBefore: "2026-06-03T12:00:00.000Z", CreatedAt: "2026-06-03T12:00:00.000Z",
	}); err == nil {
		t.Fatal("SubDelegate must reject a parent with an invalid signature")
	}
}
