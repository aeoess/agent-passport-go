// A timestamp a verifier cannot read is not a timestamp it can honour.
//
// VerifyPassport and VerifyChallenge called isExpired/isBefore and then wrote
// `ok && expired`, so a timestamp that did not parse produced ok=false, the
// error append was skipped, and the result came back success-shaped. An honest
// expired passport was invalid; a passport whose expiresAt was the word
// "never" was valid. VerifyChallenge was the sharpest of the three: freshness
// is the only thing between a replayed challenge response and acceptance, and
// an unreadable expiry removed it while still returning true.
//
// The unreadable case is reported separately from the expired case. "Expired
// at X" claims a limit was read and had passed, which is a different finding
// from having read no limit at all.
package passport

import (
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

// Present, and not readable as RFC 3339 by time.Parse. Each is a value a
// producer can put on the wire today; the zone-less and date-only forms in
// particular are what a careless or non-Go producer emits, so this triggers on
// honest malformed input and not only on attack.
var unreadableStamps = []struct{ name, value string }{
	{"not a date at all", "not-a-date"},
	{"empty string", ""},
	{"no zone designator", "2020-01-01T00:00:00"},
	{"date only", "2020-01-01"},
	{"impossible day of month", "2020-02-30T00:00:00Z"},
	{"hour 24", "2020-01-01T24:00:00Z"},
	{"leap second", "2020-12-31T23:59:60Z"},
	{"lowercase t and z", "2020-01-01t00:00:00z"},
	{"whitespace padded", "  2020-01-01T00:00:00Z  "},
	{"unix millis", "1767225600000"},
}

const probeNow = "2026-06-03T13:00:00Z"

func temporalFixture(t *testing.T, expiresAt, notBefore string) SignedPassport {
	t.Helper()
	priv := seedHex("aps-temporal-fail-closed")
	pub, err := keys.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	signed, err := CreatePassport(CreatePassportInput{
		AgentID: "ag_temporal", PublicKey: pub,
		Capabilities: []string{"code_execution"},
		CreatedAt:    "2026-06-03T12:00:00Z",
		ExpiresAt:    expiresAt, NotBefore: notBefore,
	}, priv, "2026-06-03T12:00:00Z")
	if err != nil {
		t.Fatalf("CreatePassport(%q,%q): %v", expiresAt, notBefore, err)
	}
	return signed
}

func hasErrorContaining(errs []string, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// ── expiresAt ──────────────────────────────────────────────────────────────

func TestPassportHonestExpiryIsExpired(t *testing.T) {
	// The baseline every unreadable case below is measured against.
	res := VerifyPassport(temporalFixture(t, "2020-01-01T00:00:00Z", ""), nil, probeNow)
	if res.Valid || !hasErrorContaining(res.Errors, "Passport expired at") {
		t.Fatalf("expected expired, got valid=%v errors=%v", res.Valid, res.Errors)
	}
}

func TestPassportUnreadableExpiryIsRefused(t *testing.T) {
	for _, c := range unreadableStamps {
		t.Run(c.name, func(t *testing.T) {
			res := VerifyPassport(temporalFixture(t, c.value, ""), nil, probeNow)
			if res.Valid {
				t.Fatalf("expiresAt %q left the passport valid", c.value)
			}
			if !hasErrorContaining(res.Errors, "Unreadable expiresAt") {
				t.Fatalf("expiresAt %q gave %v, wanted an unreadable-expiresAt error", c.value, res.Errors)
			}
			if hasErrorContaining(res.Errors, "Passport expired at") {
				t.Fatalf("expiresAt %q was reported as expired, which claims a limit was read", c.value)
			}
		})
	}
}

func TestPassportReadableFutureExpiryStillVerifies(t *testing.T) {
	res := VerifyPassport(temporalFixture(t, "2030-01-01T00:00:00Z", ""), nil, probeNow)
	if !res.Valid {
		t.Fatalf("expected valid, got %v", res.Errors)
	}
}

func TestPassportExplicitOffsetIsReadableAndStillCompared(t *testing.T) {
	// The repair narrows nothing that already parsed.
	res := VerifyPassport(temporalFixture(t, "2020-01-01T05:30:00+05:30", ""), nil, probeNow)
	if !hasErrorContaining(res.Errors, "Passport expired at") {
		t.Fatalf("explicit offset should still compare as expired, got %v", res.Errors)
	}
}

// ── notBefore ──────────────────────────────────────────────────────────────

func TestPassportHonestNotBeforeIsNotYetValid(t *testing.T) {
	res := VerifyPassport(temporalFixture(t, "2030-01-01T00:00:00Z", "2029-01-01T00:00:00Z"), nil, probeNow)
	if res.Valid || !hasErrorContaining(res.Errors, "not valid before") {
		t.Fatalf("expected not-yet-valid, got valid=%v errors=%v", res.Valid, res.Errors)
	}
}

func TestPassportUnreadableNotBeforeIsRefused(t *testing.T) {
	for _, c := range unreadableStamps {
		if c.value == "" {
			continue // an empty notBefore is absent, and the profile marks it optional
		}
		t.Run(c.name, func(t *testing.T) {
			res := VerifyPassport(temporalFixture(t, "2030-01-01T00:00:00Z", c.value), nil, probeNow)
			if res.Valid {
				t.Fatalf("notBefore %q left the passport valid", c.value)
			}
			if !hasErrorContaining(res.Errors, "Unreadable notBefore") {
				t.Fatalf("notBefore %q gave %v, wanted an unreadable-notBefore error", c.value, res.Errors)
			}
			if hasErrorContaining(res.Errors, "not valid before") {
				t.Fatalf("notBefore %q claimed a start date was read", c.value)
			}
		})
	}
}

func TestPassportAbsentNotBeforeLeavesTheLowerEdgeOpen(t *testing.T) {
	// notBefore is `json:"notBefore,omitempty"` in the profile, expiresAt is
	// not. That asymmetry is the profile's and is pinned here so a later edit
	// does not quietly make one match the other.
	res := VerifyPassport(temporalFixture(t, "2030-01-01T00:00:00Z", ""), nil, probeNow)
	if !res.Valid {
		t.Fatalf("expected valid with no notBefore, got %v", res.Errors)
	}
}

// ── the verifier's own clock ───────────────────────────────────────────────

func TestPassportEmptyClockStillSkipsBothBoundaries(t *testing.T) {
	// Documented opt-out for a caller with no deterministic clock, asserted by
	// unit_test.go. The repair must not turn it into a refusal.
	res := VerifyPassport(temporalFixture(t, "2020-01-01T00:00:00Z", ""), nil, "")
	if !res.Valid {
		t.Fatalf("expected an empty clock to skip expiry, got %v", res.Errors)
	}
}

func TestPassportUnreadableClockIsRefused(t *testing.T) {
	// The quieter half of the same defect: one unreadable clock string
	// disabled expiry and notBefore for every passport a verifier checked,
	// with nothing surfaced. An empty clock says "do not check"; a non-empty
	// one says "check", and failing to read it is a failure to check.
	for _, c := range unreadableStamps {
		if c.value == "" {
			continue // empty is the documented opt-out above
		}
		t.Run(c.name, func(t *testing.T) {
			res := VerifyPassport(temporalFixture(t, "2030-01-01T00:00:00Z", ""), nil, c.value)
			if res.Valid {
				t.Fatalf("clock %q left the passport valid", c.value)
			}
			if !hasErrorContaining(res.Errors, "Unreadable verifier clock") {
				t.Fatalf("clock %q gave %v", c.value, res.Errors)
			}
		})
	}
}

// ── challenge freshness ────────────────────────────────────────────────────

func TestChallengeUnreadableExpiryIsRefused(t *testing.T) {
	priv := seedHex("aps-temporal-fail-closed")
	pub, _ := keys.PublicKeyFromPrivate(priv)
	sig, err := keys.Sign("nonce-temporal", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	mk := func(expiresAt string) Challenge {
		return Challenge{ChallengeID: "ch_1", Nonce: "nonce-temporal", ExpiresAt: expiresAt}
	}
	if VerifyChallenge(mk("2020-01-01T00:00:00Z"), sig, pub, probeNow) {
		t.Fatal("an honestly expired challenge must be refused")
	}
	if !VerifyChallenge(mk("2030-01-01T00:00:00Z"), sig, pub, probeNow) {
		t.Fatal("a fresh challenge with a good signature must be accepted")
	}
	for _, c := range unreadableStamps {
		t.Run(c.name, func(t *testing.T) {
			if VerifyChallenge(mk(c.value), sig, pub, probeNow) {
				t.Fatalf("challenge expiresAt %q was accepted; replay protection is off", c.value)
			}
		})
	}
	// The documented no-clock opt-out survives.
	if !VerifyChallenge(mk("not-a-date"), sig, pub, "") {
		t.Fatal("an empty clock must still skip the freshness check")
	}
}
