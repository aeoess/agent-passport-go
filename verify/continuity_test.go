// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// signedLink builds a self-consistently signed chain link: its signature
// verifies against the delegator key it names.
func signedLink(t *testing.T, delegatorPriv, delegatorPub, delegateePub string, cats []interface{}) map[string]interface{} {
	t.Helper()
	m := map[string]interface{}{
		"delegator": delegatorPub,
		"delegatee": delegateePub,
		"scope":     map[string]interface{}{"action_categories": cats},
		"validityWindow": map[string]interface{}{
			"not_before": "2020-01-01T00:00:00Z",
			"not_after":  "2999-12-31T23:59:59Z",
		},
	}
	sig, err := keys.SignArtifact(m, "signature", delegatorPriv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	m["signature"] = sig
	return m
}

func TestValidateChain_ContinuityEnforced(t *testing.T) {
	a, _ := keys.GenerateKeyPair()
	b, _ := keys.GenerateKeyPair()
	c, _ := keys.GenerateKeyPair()
	d, _ := keys.GenerateKeyPair()
	evil, _ := keys.GenerateKeyPair()
	big := 10
	now := "2026-06-01T00:00:00Z"

	// Properly linked chain: link1.delegator == link0.delegatee.
	good := verify.ChainInput{Chain: []map[string]interface{}{
		signedLink(t, a.PrivateKey, a.PublicKey, b.PublicKey, []interface{}{"data:read", "data:write"}),
		signedLink(t, b.PrivateKey, b.PublicKey, c.PublicKey, []interface{}{"data:read"}),
	}, MaxDepth: &big, Now: now}
	if code := verify.ValidateChain(good); code != "" {
		t.Errorf("valid linked chain: got %q, want \"\"", code)
	}

	// Spliced / self-minted chain: link1 signed by a key that is NOT link0's
	// delegatee. Each link's own signature verifies, but the chain is
	// unauthorized. Must be refused (was accepted before the continuity fix).
	spliced := verify.ChainInput{Chain: []map[string]interface{}{
		signedLink(t, a.PrivateKey, a.PublicKey, b.PublicKey, []interface{}{"data:read"}),
		signedLink(t, evil.PrivateKey, evil.PublicKey, d.PublicKey, []interface{}{"data:read"}),
	}, MaxDepth: &big, Now: now}
	if code := verify.ValidateChain(spliced); code != verify.CodeInvalidSig {
		t.Errorf("spliced chain: got %q, want %q (continuity must be enforced)", code, verify.CodeInvalidSig)
	}
}
