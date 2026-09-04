// A signature over a passport says who signed it, not who vouches for it.
//
// The verifying key is the one the passport carries, so a good signature is
// available to anyone who can generate a key pair. With an empty trustedIssuers
// list VerifyPassport skipped the issuer check entirely and reported Valid from
// the error count, so a passport minted by anyone at all came back valid and a
// caller had to read a warning string to find out why.
//
// The contract, identical in all four SDKs: a bare verification checks and
// reports the signature and is not valid; a trusted issuer's countersignature
// is valid with IssuerTrustChecked set; an explicit AllowSelfSigned is valid
// with SelfSignedAccepted set; and the opt-in never rescues a failed issuer
// check.
package passport

import (
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

const rg2Now = "2026-06-03T13:00:00Z"

func rg2Minted(t *testing.T, expiresAt string) SignedPassport {
	t.Helper()
	priv := seedHex("aps-rg2-agent")
	pub, err := keys.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	s, err := CreatePassport(CreatePassportInput{
		AgentID: "ag_attacker_claims_treasury", PublicKey: pub,
		Capabilities: []string{"commerce:checkout"},
		CreatedAt:    "2026-06-03T12:00:00Z", ExpiresAt: expiresAt,
	}, priv, "2026-06-03T12:00:00Z")
	if err != nil {
		t.Fatalf("CreatePassport: %v", err)
	}
	return s
}

// rg2Countersign signs canonicalize({passport, signature, signedAt}), the same
// preimage the other three SDKs verify. namedKey is what the envelope claims,
// which is not always the key that signed it.
func rg2Countersign(t *testing.T, s SignedPassport, signerSeed, namedKey string) SignedPassport {
	t.Helper()
	// The library's own preimage builder, so the test cannot drift from it.
	m, err := issuerPayloadMap(s)
	if err != nil {
		t.Fatalf("issuerPayloadMap: %v", err)
	}
	payload, err := jcs.Canonicalize(m)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, err := keys.Sign(payload, seedHex(signerSeed))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s.IssuerSignature = &IssuerSignature{
		IssuerID: "aeoess", IssuerPublicKey: namedKey, Signature: sig, SignedAt: s.SignedAt,
	}
	return s
}

func rg2IssuerKey(t *testing.T, seed string) string {
	t.Helper()
	pub, err := keys.PublicKeyFromPrivate(seedHex(seed))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return pub
}

func hasErr(errs []string, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

const rg2Live = "2030-01-01T00:00:00Z"

func TestBareVerificationIsIntegrityNotAuthority(t *testing.T) {
	r := VerifyPassport(rg2Minted(t, rg2Live), VerifyPassportOptions{Now: rg2Now})
	if r.Valid {
		t.Fatal("a passport nobody vouched for was reported valid")
	}
	if !hasErr(r.Errors, "Authority not established") {
		t.Fatalf("wanted an authority error, got %v", r.Errors)
	}
	if r.IssuerTrustChecked || r.SelfSignedAccepted {
		t.Fatalf("flags wrong: %+v", r)
	}
}

func TestBareCallStillChecksAndReportsTheSignature(t *testing.T) {
	// Integrity is established and reported even though authority is not: the
	// bare call must not collapse into one undifferentiated refusal.
	s := rg2Minted(t, rg2Live)
	s.Passport.AgentID = "ag_promoted"
	r := VerifyPassport(s, VerifyPassportOptions{Now: rg2Now})
	if !hasErr(r.Errors, "Invalid signature") || !hasErr(r.Errors, "Authority not established") {
		t.Fatalf("wanted both findings, got %v", r.Errors)
	}
}

func TestTrustedIssuerCountersignatureIsValid(t *testing.T) {
	k := rg2IssuerKey(t, "aps-rg2-issuer")
	s := rg2Countersign(t, rg2Minted(t, rg2Live), "aps-rg2-issuer", k)
	r := VerifyPassport(s, VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now})
	if !r.Valid {
		t.Fatalf("expected valid, got %v", r.Errors)
	}
	if !r.IssuerTrustChecked || r.SelfSignedAccepted {
		t.Fatalf("flags wrong: %+v", r)
	}
}

func TestSelfSignedOptInIsExplicit(t *testing.T) {
	r := VerifyPassport(rg2Minted(t, rg2Live), VerifyPassportOptions{Now: rg2Now, AllowSelfSigned: true})
	if !r.Valid {
		t.Fatalf("expected valid, got %v", r.Errors)
	}
	if !r.SelfSignedAccepted || r.IssuerTrustChecked {
		t.Fatalf("flags wrong: %+v", r)
	}
}

func TestOptInStillRequiresAGoodSignature(t *testing.T) {
	s := rg2Minted(t, rg2Live)
	s.Passport.AgentID = "ag_promoted"
	if VerifyPassport(s, VerifyPassportOptions{Now: rg2Now, AllowSelfSigned: true}).Valid {
		t.Fatal("a tampered passport passed under the opt-in")
	}
}

func TestTrustedListWithNoCountersignatureIsRefused(t *testing.T) {
	k := rg2IssuerKey(t, "aps-rg2-issuer")
	r := VerifyPassport(rg2Minted(t, rg2Live), VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now})
	if r.Valid || !r.IssuerTrustChecked {
		t.Fatalf("expected refusal with the check having run, got %+v", r)
	}
}

func TestCountersignatureByAKeyNotInTheListIsRefused(t *testing.T) {
	trusted := rg2IssuerKey(t, "aps-rg2-issuer")
	other := rg2IssuerKey(t, "aps-rg2-other")
	s := rg2Countersign(t, rg2Minted(t, rg2Live), "aps-rg2-other", other)
	if VerifyPassport(s, VerifyPassportOptions{TrustedIssuers: []string{trusted}, Now: rg2Now}).Valid {
		t.Fatal("an untrusted issuer was accepted")
	}
}

func TestCountersignatureNamingATrustedKeyButMadeByAnotherIsRefused(t *testing.T) {
	trusted := rg2IssuerKey(t, "aps-rg2-issuer")
	s := rg2Countersign(t, rg2Minted(t, rg2Live), "aps-rg2-other", trusted)
	r := VerifyPassport(s, VerifyPassportOptions{TrustedIssuers: []string{trusted}, Now: rg2Now})
	if r.Valid || !hasErr(r.Errors, "Invalid issuer countersignature") {
		t.Fatalf("expected a countersignature error, got %+v", r)
	}
}

func TestCountersignedPassportReSignedByAnotherKeyIsRefused(t *testing.T) {
	k := rg2IssuerKey(t, "aps-rg2-issuer")
	s := rg2Countersign(t, rg2Minted(t, rg2Live), "aps-rg2-issuer", k)
	s.Passport.AgentID = "ag_promoted"
	if VerifyPassport(s, VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now}).Valid {
		t.Fatal("a tampered body passed under a trusted issuer")
	}
}

func TestExpiredPassportUnderATrustedIssuerIsStillRefused(t *testing.T) {
	k := rg2IssuerKey(t, "aps-rg2-issuer")
	s := rg2Countersign(t, rg2Minted(t, "2020-01-01T00:00:00Z"), "aps-rg2-issuer", k)
	r := VerifyPassport(s, VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now})
	if r.Valid || !hasErr(r.Errors, "expired") {
		t.Fatalf("expected an expiry refusal, got %+v", r)
	}
}

func TestOptInDoesNotRescueAFailedIssuerCheck(t *testing.T) {
	trusted := rg2IssuerKey(t, "aps-rg2-issuer")
	other := rg2IssuerKey(t, "aps-rg2-other")
	s := rg2Countersign(t, rg2Minted(t, rg2Live), "aps-rg2-other", other)
	r := VerifyPassport(s, VerifyPassportOptions{
		TrustedIssuers: []string{trusted}, Now: rg2Now, AllowSelfSigned: true})
	if r.Valid || r.SelfSignedAccepted {
		t.Fatalf("the opt-in rescued a failed issuer check: %+v", r)
	}
}

func TestTheWholeTruthTable(t *testing.T) {
	// Re-attack, not in the brief: the two inputs are independent, so pin every
	// combination rather than the two rows the brief names.
	k := rg2IssuerKey(t, "aps-rg2-issuer")
	bare := rg2Minted(t, rg2Live)
	cases := []struct {
		name   string
		opts   VerifyPassportOptions
		wantOK bool
	}{
		{"no list, no opt-in", VerifyPassportOptions{Now: rg2Now}, false},
		{"no list, opt-in", VerifyPassportOptions{Now: rg2Now, AllowSelfSigned: true}, true},
		{"list, no countersignature, no opt-in",
			VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now}, false},
		{"list, no countersignature, opt-in",
			VerifyPassportOptions{TrustedIssuers: []string{k}, Now: rg2Now, AllowSelfSigned: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := VerifyPassport(bare, c.opts).Valid; got != c.wantOK {
				t.Fatalf("Valid = %v, want %v", got, c.wantOK)
			}
		})
	}
}

func TestEmptyClockStillSkipsTheBoundaries(t *testing.T) {
	// The documented opt-out survives the authority change: an empty Now still
	// skips expiry, and it is not a way to skip authority.
	expired := rg2Minted(t, "2020-01-01T00:00:00Z")
	if !VerifyPassport(expired, VerifyPassportOptions{AllowSelfSigned: true}).Valid {
		t.Fatal("an empty clock should still skip expiry")
	}
	if VerifyPassport(expired, VerifyPassportOptions{}).Valid {
		t.Fatal("an empty clock must not skip the authority requirement")
	}
}
