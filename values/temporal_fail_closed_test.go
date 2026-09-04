// timeLess returned a bare bool and resolved every parse failure as "not
// expired". All three of its callers are expiry gates whose verdict is derived
// from the length of an appended-string list, so a swallowed parse failure did
// not suppress a warning, it flipped the verdict: VerifyAttestation returned
// (true, nil) and NegotiateCommonGround returned Compatible with no reasons.
//
// The helper now reports whether it could read both timestamps, and the callers
// branch on it. The unreadable case is named separately from the expired case,
// because "expired" claims a limit was read and had passed.
package values

import (
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

var unreadableStamps = []struct{ name, value string }{
	{"not a date at all", "not-a-date"},
	{"no zone designator", "2020-01-01T00:00:00"},
	{"date only", "2020-01-01"},
	{"impossible day of month", "2020-02-30T00:00:00Z"},
	{"hour 24", "2020-01-01T24:00:00Z"},
	{"leap second", "2020-12-31T23:59:60Z"},
	{"lowercase t and z", "2020-01-01t00:00:00z"},
	{"whitespace padded", "  2020-01-01T00:00:00Z  "},
	{"colon-less offset", "2020-01-01T00:00:00+0000"},
	{"unix millis", "1767225600000"},
}

const groundNow = "2026-06-03T13:00:00Z"

func groundAttestation(t *testing.T, id, expiresAt string) (FloorAttestation, string) {
	t.Helper()
	priv := seedHex("aps-values-temporal-" + id)
	pub, err := keys.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	att, err := AttestFloor("att_"+id, "ag_"+id, pub, "1.0", []string{},
		"2026-06-03T12:00:00Z", expiresAt, priv)
	if err != nil {
		t.Fatalf("AttestFloor: %v", err)
	}
	return att, pub
}

func containsSubstring(items []string, substr string) bool {
	for _, s := range items {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func TestAttestationHonestExpiryIsExpired(t *testing.T) {
	att, _ := groundAttestation(t, "a", "2020-01-01T00:00:00Z")
	ok, errs := VerifyAttestation(att, groundNow)
	if ok || !containsSubstring(errs, "Attestation expired") {
		t.Fatalf("expected expired, got ok=%v errs=%v", ok, errs)
	}
}

func TestAttestationUnreadableExpiryIsRefused(t *testing.T) {
	for _, c := range unreadableStamps {
		t.Run(c.name, func(t *testing.T) {
			att, _ := groundAttestation(t, "a", c.value)
			ok, errs := VerifyAttestation(att, groundNow)
			if ok {
				t.Fatalf("expiresAt %q left the attestation valid", c.value)
			}
			if !containsSubstring(errs, "Unreadable attestation expiresAt") {
				t.Fatalf("expiresAt %q gave %v", c.value, errs)
			}
			if containsSubstring(errs, "Attestation expired") {
				t.Fatalf("expiresAt %q was reported as expired, which claims a limit was read", c.value)
			}
		})
	}
}

func TestAttestationUnreadableClockIsRefused(t *testing.T) {
	att, _ := groundAttestation(t, "a", "2030-01-01T00:00:00Z")
	ok, errs := VerifyAttestation(att, "not-a-date")
	if ok || !containsSubstring(errs, "Unreadable attestation expiresAt") {
		t.Fatalf("an unreadable verifier clock must refuse, got ok=%v errs=%v", ok, errs)
	}
}

func TestAttestationAbsentExpiryAndAbsentClockStaySkips(t *testing.T) {
	// Both guards are documented opt-outs throughout this module and are
	// unchanged. An attestation may state no end; a caller may state no clock.
	att, _ := groundAttestation(t, "a", "")
	if ok, errs := VerifyAttestation(att, groundNow); !ok {
		t.Fatalf("absent expiresAt must stay a skip, got %v", errs)
	}
	att2, _ := groundAttestation(t, "a", "2020-01-01T00:00:00Z")
	if ok, errs := VerifyAttestation(att2, ""); !ok {
		t.Fatalf("absent clock must stay a skip, got %v", errs)
	}
}

func TestAttestationReadableFutureExpiryStillVerifies(t *testing.T) {
	att, _ := groundAttestation(t, "a", "2030-01-01T00:00:00Z")
	if ok, errs := VerifyAttestation(att, groundNow); !ok {
		t.Fatalf("expected valid, got %v", errs)
	}
}

func TestNegotiateHonestExpiryIsIncompatible(t *testing.T) {
	a, pa := groundAttestation(t, "a", "2020-01-01T00:00:00Z")
	b, pb := groundAttestation(t, "b", "2030-01-01T00:00:00Z")
	sg := NegotiateCommonGround(pa, a, pb, b, groundNow)
	if sg.Compatible || !containsSubstring(sg.IncompatibilityReasons, "attestation expired") {
		t.Fatalf("expected incompatible, got %+v", sg)
	}
}

func TestNegotiateUnreadableExpiryIsRefusedOnEitherSide(t *testing.T) {
	for _, c := range unreadableStamps {
		t.Run("A/"+c.name, func(t *testing.T) {
			a, pa := groundAttestation(t, "a", c.value)
			b, pb := groundAttestation(t, "b", "2030-01-01T00:00:00Z")
			sg := NegotiateCommonGround(pa, a, pb, b, groundNow)
			if sg.Compatible {
				t.Fatalf("A expiresAt %q negotiated as compatible", c.value)
			}
			if !containsSubstring(sg.IncompatibilityReasons, "unreadable expiresAt") {
				t.Fatalf("A expiresAt %q gave %v", c.value, sg.IncompatibilityReasons)
			}
		})
		t.Run("B/"+c.name, func(t *testing.T) {
			a, pa := groundAttestation(t, "a", "2030-01-01T00:00:00Z")
			b, pb := groundAttestation(t, "b", c.value)
			sg := NegotiateCommonGround(pa, a, pb, b, groundNow)
			if sg.Compatible {
				t.Fatalf("B expiresAt %q negotiated as compatible", c.value)
			}
		})
	}
}

func TestNegotiateBothLiveAttestationsStillAgree(t *testing.T) {
	a, pa := groundAttestation(t, "a", "2030-01-01T00:00:00Z")
	b, pb := groundAttestation(t, "b", "2030-01-01T00:00:00Z")
	sg := NegotiateCommonGround(pa, a, pb, b, groundNow)
	if !sg.Compatible {
		t.Fatalf("expected compatible, got %v", sg.IncompatibilityReasons)
	}
}
