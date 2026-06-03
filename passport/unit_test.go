// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package passport

import (
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

func TestCalculateVoteWeight(t *testing.T) {
	cases := []struct {
		caps []string
		want int
	}{
		{nil, 1},
		{[]string{}, 1},
		{[]string{"web_search"}, 1},     // 1 + 0.2 -> round 1.2 = 1
		{[]string{"code_execution"}, 2}, // 1 + 0.5 -> round 1.5 = 2
		{[]string{"code_execution", "system_control"}, 2},                                       // 1 + 1.0 = 2
		{[]string{"code_execution", "web_search"}, 2},                                           // 1 + 0.7 -> round 1.7 = 2
		{[]string{"unknown_cap"}, 1},                                                            // 1 + 0.1 -> round 1.1 = 1
		{[]string{"code_execution", "system_control", "file_management"}, 2},                    // 1 + 1.3 -> 2
		{[]string{"code_execution", "system_control", "email_management", "git_operations"}, 3}, // 1+1.6 -> 3
	}
	for _, c := range cases {
		if got := CalculateVoteWeight(c.caps); got != c.want {
			t.Errorf("CalculateVoteWeight(%v) = %d, want %d", c.caps, got, c.want)
		}
	}
}

func TestVerifyPassportTamperDetected(t *testing.T) {
	signed, _, _, _, _ := fixturePassport(t)
	// Tamper with a signed field; the agent signature must no longer verify.
	signed.Passport.Mission = "tampered"
	res := VerifyPassport(signed, nil, fixedVerifyNow)
	if res.Valid {
		t.Error("expected tampered passport to be invalid")
	}
}

func TestVerifyPassportExpiry(t *testing.T) {
	signed, _, _, _, _ := fixturePassport(t)
	// now is after expiresAt -> expired error.
	res := VerifyPassport(signed, nil, "2030-01-01T00:00:00Z")
	if res.Valid {
		t.Error("expected expired passport to be invalid")
	}
	foundExpiry := false
	for _, e := range res.Errors {
		if e == "Passport expired at "+fixedExpiresAt {
			foundExpiry = true
		}
	}
	if !foundExpiry {
		t.Errorf("expected expiry error, got %v", res.Errors)
	}
	// Empty clock skips expiry; passport remains valid.
	if res2 := VerifyPassport(signed, nil, ""); !res2.Valid {
		t.Errorf("expected valid with no clock, got %v", res2.Errors)
	}
}

func TestVerifyPassportTrustedIssuers(t *testing.T) {
	signed, _, _, issuerPriv, issuerPub := fixturePassport(t)

	// Self-signed (no issuer sig) but trustedIssuers required -> error.
	res := VerifyPassport(signed, []string{issuerPub}, fixedVerifyNow)
	if res.Valid {
		t.Error("expected self-signed passport to fail trustedIssuers check")
	}

	cs, err := CountersignPassport(signed, issuerPriv, "aeoess", fixedSignedAt)
	if err != nil {
		t.Fatalf("CountersignPassport: %v", err)
	}
	// Correct trusted issuer -> valid.
	if res := VerifyPassport(cs, []string{issuerPub}, fixedVerifyNow); !res.Valid {
		t.Errorf("expected valid with trusted issuer, got %v", res.Errors)
	}
	// Issuer not in trusted list -> error.
	other := "00000000000000000000000000000000000000000000000000000000000000ff"
	if res := VerifyPassport(cs, []string{other}, fixedVerifyNow); res.Valid {
		t.Error("expected failure when issuer not in trusted list")
	}
}

func TestVerifyIssuerSignatureWrongKey(t *testing.T) {
	signed, _, _, issuerPriv, issuerPub := fixturePassport(t)
	cs, err := CountersignPassport(signed, issuerPriv, "aeoess", fixedSignedAt)
	if err != nil {
		t.Fatalf("CountersignPassport: %v", err)
	}
	if !VerifyIssuerSignature(cs, issuerPub) {
		t.Error("expected issuer signature to verify with correct key")
	}
	wrong := "00000000000000000000000000000000000000000000000000000000000000ff"
	if VerifyIssuerSignature(cs, wrong) {
		t.Error("expected issuer signature to fail with wrong key")
	}
	// No issuer signature present -> false.
	if VerifyIssuerSignature(signed, issuerPub) {
		t.Error("expected false when no issuer signature present")
	}
}

func TestChallengeRoundTripAndExpiry(t *testing.T) {
	priv := seedHex(agentKeySeed)
	pub, err := keys.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	ch, err := CreateChallenge("chal_rt", 300, "2026-06-03T12:00:00Z")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if ch.Timestamp != "2026-06-03T12:00:00Z" {
		t.Errorf("timestamp = %q", ch.Timestamp)
	}
	if ch.ExpiresAt != "2026-06-03T12:05:00Z" {
		t.Errorf("expiresAt = %q, want +300s", ch.ExpiresAt)
	}
	if len(ch.Nonce) != 64 {
		t.Errorf("nonce hex length = %d, want 64", len(ch.Nonce))
	}
	resp, err := SignChallenge(ch, priv, pub)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	// Fresh challenge verifies.
	if !VerifyChallenge(ch, resp.Signature, pub, "2026-06-03T12:01:00Z") {
		t.Error("expected fresh challenge to verify")
	}
	// Expired challenge rejected even with a valid signature.
	if VerifyChallenge(ch, resp.Signature, pub, "2026-06-03T12:10:00Z") {
		t.Error("expected expired challenge to be rejected")
	}
	// Wrong key fails.
	other := "00000000000000000000000000000000000000000000000000000000000000ff"
	if VerifyChallenge(ch, resp.Signature, other, "2026-06-03T12:01:00Z") {
		t.Error("expected wrong-key challenge to be rejected")
	}
}

func TestCreateChallengeNonceIsRandom(t *testing.T) {
	a, err := CreateChallenge("a", 60, "2026-06-03T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateChallenge("b", 60, "2026-06-03T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce {
		t.Error("two challenges produced the same nonce; randomness broken")
	}
}
