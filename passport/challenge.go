// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package passport

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/aeoess/agent-passport-go/keys"
)

// Challenge mirrors Challenge in src/types/passport.ts. It is a signed-nonce
// pair: the holder proves possession of a private key by signing the nonce.
type Challenge struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Timestamp   string `json:"timestamp"`
	ExpiresAt   string `json:"expiresAt"`
}

// ChallengeResponse mirrors ChallengeResponse in src/types/passport.ts.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Signature   string `json:"signature"`
	PublicKey   string `json:"publicKey"`
}

// CreateChallenge mirrors createChallenge in src/verification/verify.ts: a fresh
// random 32-byte nonce with a creation timestamp and an expiry expiresInSeconds
// from now. challengeID is caller-supplied so the value is reproducible in tests
// (the reference uses a random UUID). issuedAt is the reference clock as an ISO
// 8601 string; pass an empty string to use the wall clock.
func CreateChallenge(challengeID string, expiresInSeconds int, issuedAt string) (Challenge, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Challenge{}, err
	}
	var base time.Time
	if issuedAt == "" {
		base = time.Now().UTC()
	} else {
		t, err := time.Parse(time.RFC3339, issuedAt)
		if err != nil {
			return Challenge{}, err
		}
		base = t.UTC()
	}
	return Challenge{
		ChallengeID: challengeID,
		Nonce:       hex.EncodeToString(nonceBytes),
		Timestamp:   formatISO(base),
		ExpiresAt:   formatISO(base.Add(time.Duration(expiresInSeconds) * time.Second)),
	}, nil
}

// SignChallenge produces the response to a challenge: an Ed25519 signature over
// the raw nonce string, exactly the message verifyChallenge checks. The private
// key never leaves this call. publicKeyHex is recorded on the response so a
// verifier can locate the key.
func SignChallenge(challenge Challenge, privateKeyHex, publicKeyHex string) (ChallengeResponse, error) {
	sig, err := keys.Sign(challenge.Nonce, privateKeyHex)
	if err != nil {
		return ChallengeResponse{}, err
	}
	return ChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		Signature:   sig,
		PublicKey:   publicKeyHex,
	}, nil
}

// VerifyChallenge mirrors verifyChallenge in src/verification/verify.ts: reject
// an expired challenge, then verify the signature over the nonce. now is the
// verifier clock as an ISO 8601 string; an empty string skips the expiry check
// (matching a caller that has no deterministic clock).
//
// A non-empty timestamp that does not parse is a refusal, not a skipped check.
// Freshness is the only thing standing between a replayed challenge response
// and acceptance, so a challenge whose expiresAt cannot be read has to fail:
// otherwise the cheapest way to defeat the expiry gate is to put a word where
// the date goes, and the function still returns true.
func VerifyChallenge(challenge Challenge, signatureHex, publicKeyHex, now string) bool {
	if now != "" {
		expired, ok := isExpired(challenge.ExpiresAt, now)
		if !ok || expired {
			return false
		}
	}
	return keys.Verify(challenge.Nonce, signatureHex, publicKeyHex)
}

// formatISO renders a time the way JavaScript's Date.toISOString does for a
// whole-second value: RFC 3339 with a trailing Z and no offset.
func formatISO(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// parseClock reads one RFC 3339 timestamp. It exists so a caller can tell an
// unreadable verifier clock from an unreadable artifact timestamp: isExpired
// and isBefore collapse both failures into one ok, and the two are different
// findings. A verifier that cannot read its own clock has not checked
// anything, which is the failure verify.VerifyChain reports as CodeValidityExp.
func parseClock(ts string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	return t, err == nil
}

// isExpired reports whether expiresAt < now, and whether both timestamps could
// be read at all. Callers MUST branch on ok before trusting expired: a false
// expired with ok false means "this could not be determined", not "not
// expired". Treating the two alike is what let an unreadable expiresAt pass a
// gate that an honest expired one failed.
func isExpired(expiresAt, now string) (expired bool, ok bool) {
	e, err1 := time.Parse(time.RFC3339, expiresAt)
	n, err2 := time.Parse(time.RFC3339, now)
	if err1 != nil || err2 != nil {
		return false, false
	}
	return e.Before(n), true
}

// isBefore reports whether a < b for two ISO 8601 timestamps, and whether both
// could be read. The same rule as isExpired applies to ok.
func isBefore(a, b string) (before bool, ok bool) {
	ta, err1 := time.Parse(time.RFC3339, a)
	tb, err2 := time.Parse(time.RFC3339, b)
	if err1 != nil || err2 != nil {
		return false, false
	}
	return ta.Before(tb), true
}
