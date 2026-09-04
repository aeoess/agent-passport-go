// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

// admissibilityDoc is testdata/ed25519-admissibility-v1.json: the behaviour on
// which the two strict reference implementations agree, libsodium through
// PyNaCl (agent-passport-python) and ed25519-dalek verify_strict
// (agent-passport-system aps-verifier-core). The same file is used by the
// TypeScript, Rust and Python suites, so all four implementations answer every
// vector the same way by construction.
type admissibilityDoc struct {
	Version         string                `json:"version"`
	Count           int                   `json:"count"`
	Vectors         []admissibilityVector `json:"vectors"`
	ArtifactVectors artifactVector        `json:"artifact_vectors"`
}

// artifactVector is a real delegation whose canonical bytes satisfy the RFC
// 8032 equation under a small order public key, with a full order canonical R
// and s < L. It was minted with no private key.
type artifactVector struct {
	Note              string                 `json:"note"`
	PublicKeyHex      string                 `json:"public_key_hex"`
	CanonicalPreimage string                 `json:"canonical_preimage"`
	Delegation        map[string]interface{} `json:"delegation"`
}

type admissibilityVector struct {
	ID        string `json:"id"`
	Group     string `json:"group"`
	Note      string `json:"note"`
	Message   string `json:"message_utf8"`
	PublicKey string `json:"public_key_hex"`
	Signature string `json:"signature_hex"`
	Expected  bool   `json:"expected_verification"`
}

func loadAdmissibility(t *testing.T) admissibilityDoc {
	t.Helper()
	raw, err := os.ReadFile("testdata/ed25519-admissibility-v1.json")
	if err != nil {
		t.Fatalf("read admissibility vectors: %v", err)
	}
	var doc admissibilityDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse admissibility vectors: %v", err)
	}
	if doc.Version != "ed25519-admissibility-v1" {
		t.Fatalf("unexpected fixture version %q", doc.Version)
	}
	if len(doc.Vectors) != doc.Count {
		t.Fatalf("fixture declares %d vectors, carries %d", doc.Count, len(doc.Vectors))
	}
	return doc
}

// The Edwards identity point as a public key, and R = the identity with s = 0.
// The RFC 8032 equation degenerates to identity = identity, so this one
// signature verifies under every message unless admissibility is checked.
const (
	identityKey   = "0100000000000000000000000000000000000000000000000000000000000000"
	degenerateSig = "0100000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
)

func TestAdmissibilityVectorsMatchTheStrictReference(t *testing.T) {
	doc := loadAdmissibility(t)
	var wrong []string
	for _, v := range doc.Vectors {
		got := VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey)
		if got != v.Expected {
			wrong = append(wrong, fmt.Sprintf("%s [%s] expected %v got %v :: %s",
				v.ID, v.Group, v.Expected, got, v.Note))
		}
	}
	if len(wrong) > 0 {
		shown := wrong
		if len(shown) > 12 {
			shown = shown[:12]
		}
		t.Fatalf("%d of %d vectors disagree with the strict reference:\n%s",
			len(wrong), len(doc.Vectors), joinLines(shown))
	}
}

func joinLines(s []string) string {
	out := ""
	for _, line := range s {
		out += line + "\n"
	}
	return out
}

func TestSmallOrderPublicKeyIsRejected(t *testing.T) {
	if VerifyEd25519([]byte("APS admissibility probe"), degenerateSig, identityKey) {
		t.Fatal("a small order public key must not verify")
	}
	if VerifyEd25519([]byte("a completely different message"), degenerateSig, identityKey) {
		t.Fatal("and the degenerate signature must not verify under an unrelated message")
	}
}

func TestEverySmallOrderEncodingIsRejected(t *testing.T) {
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "small_order_pk" && v.Group != "small_order_pk_message_independence" {
			continue
		}
		if VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s accepted a small order public key: %s", v.ID, v.Note)
		}
		n++
	}
	if n != 28 {
		t.Fatalf("expected all eight small order points in every encoding, got %d vectors", n)
	}
}

func TestSmallOrderRUnderAnHonestKeyIsRejected(t *testing.T) {
	// R is the identity and s = k*a mod L, so the cofactorless equation holds
	// exactly under a genuine prime order public key. Only an admissibility
	// test on R refuses it.
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "small_order_R_honest_key" || len(v.ID) < 14 || v.ID[:14] != "smallR-honest-" {
			continue
		}
		if VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s accepted a small order R: %s", v.ID, v.Note)
		}
		n++
	}
	if n < 8 {
		t.Fatalf("expected the honest key small order R vectors, got %d", n)
	}
}

func TestOrdinaryKeysAndSignaturesAreUnaffected(t *testing.T) {
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "normal" {
			continue
		}
		if !VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s is an ordinary valid signature and must still verify", v.ID)
		}
		n++
	}
	if n != 128 {
		t.Fatalf("expected 128 ordinary vectors, got %d", n)
	}
}

func TestDegenerateSignatureIsMessageIndependentAndStillRefused(t *testing.T) {
	for i := 0; i < 256; i++ {
		msg := fmt.Sprintf("unrelated APS artifact body %d", i)
		if VerifyEd25519([]byte(msg), degenerateSig, identityKey) {
			t.Fatalf("message %d accepted the message independent signature", i)
		}
	}
}

// High level paths. VerifyCanonicalSignature is the entry every APS artifact
// verifier in this module reaches: passport issuer signatures, delegation
// links, receipts, coordination artifacts and values attestations. The
// degenerate signature satisfies the RFC 8032 equation whatever the canonical
// bytes are, so only admissibility stops the artifact.
func TestCanonicalArtifactWithSmallOrderSignerIsRefused(t *testing.T) {
	artifacts := []map[string]interface{}{
		{"delegationId": "del_smallorder", "delegatedBy": identityKey,
			"scope": []interface{}{"*"}, "signature": degenerateSig},
		{"agentId": "agent-a", "issuerPublicKey": identityKey, "signature": degenerateSig},
		{"receipt_id": "r1", "kind": "attribution", "signature": degenerateSig},
	}
	for i, obj := range artifacts {
		if VerifyCanonicalSignature(obj, "signature", degenerateSig, identityKey) {
			t.Errorf("artifact %d was accepted under an inadmissible public key", i)
		}
	}
}

func TestChainLinkWithSmallOrderSignerIsRefused(t *testing.T) {
	in := ChainInput{
		Chain: []map[string]interface{}{
			{
				"delegationId":   "del_root",
				"delegator":      identityKey,
				"signature":      degenerateSig,
				"scope":          []interface{}{"*"},
				"validityWindow": map[string]interface{}{"not_after": "2099-01-01T00:00:00Z"},
			},
		},
		Now: "2026-06-01T00:00:00Z",
	}
	if code := ValidateChain(in); code != CodeInvalidSig {
		t.Fatalf("chain with an inadmissible signer key returned %q, want %q", code, CodeInvalidSig)
	}
}

// ---------------------------------------------------------------------------
// The public-key half of admissibility, isolated.
//
// Every vector above that carries a small order public key also carries
// R = the identity, so the test on R alone refuses it and the test on A is
// never exercised. Dropping the check on A would leave those tests green.
//
// These vectors close that. Take a canonical order 8 public key, pick any r,
// set R = [r]B, and grind the message until k = H(R||A||M) mod L is divisible
// by 8. Then [k]A is the identity and [s]B = R + [k]A holds with s = r. R is a
// full order, canonically encoded point and s < L, so the R half of the check
// passes it and only the test on A refuses it.
// ---------------------------------------------------------------------------

func TestSmallOrderPublicKeyWithFullOrderRIsRejected(t *testing.T) {
	doc := loadAdmissibility(t)
	n := 0
	for _, v := range doc.Vectors {
		if v.Group != "small_order_A_full_order_R" {
			continue
		}
		if VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
			t.Errorf("%s accepted a small order public key carrying an ordinary R: %s",
				v.ID, v.Note)
		}
		n++
	}
	if n != 28 {
		t.Fatalf("expected the isolating vectors, got %d", n)
	}
}

// The R half must stay independently forced too: these carry a small order R
// under an honest, full order public key, so only the test on R refuses them.
func TestAdmissibilityHalvesAreIndependentlyForced(t *testing.T) {
	doc := loadAdmissibility(t)
	var aOnly, rOnly int
	for _, v := range doc.Vectors {
		switch {
		case v.Group == "small_order_A_full_order_R":
			aOnly++
		case v.Group == "small_order_R_honest_key" && len(v.ID) >= 14 && v.ID[:14] == "smallR-honest-":
			rOnly++
		}
	}
	if aOnly == 0 {
		t.Fatal("no vector isolates the public-key half of the check")
	}
	if rOnly == 0 {
		t.Fatal("no vector isolates the R half of the check")
	}
	t.Logf("public-key half forced by %d vectors, R half by %d", aOnly, rOnly)
}

// Artifact path. VerifyCanonicalSignature is the funnel every APS artifact
// verifier in this module reaches. The delegation below grants
// payments:transfer and admin:*, and it was minted with no private key.
func TestDelegationWithSmallOrderSignerAndOrdinaryRIsRefused(t *testing.T) {
	doc := loadAdmissibility(t)
	av := doc.ArtifactVectors
	if av.PublicKeyHex == "" || av.Delegation == nil {
		t.Fatal("fixture carries no artifact vector")
	}
	sig, _ := av.Delegation["signature"].(string)
	if sig == "" {
		t.Fatal("artifact vector has no signature")
	}

	// The canonical bytes this module computes must be the ones the signature
	// was ground against, otherwise the test would pass for the wrong reason.
	rest := map[string]interface{}{}
	for k, v := range av.Delegation {
		if k != "signature" {
			rest[k] = v
		}
	}
	canon, err := jcs.Canonicalize(rest)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if canon != av.CanonicalPreimage {
		t.Fatalf("canonical bytes differ from the fixture preimage:\n got %q\nwant %q",
			canon, av.CanonicalPreimage)
	}

	if VerifyCanonicalSignature(av.Delegation, "signature", sig, av.PublicKeyHex) {
		t.Error("a delegation granting payments:transfer and admin:*, minted with " +
			"no private key, was accepted under a small order signer")
	}
}

// ── RETRO-AUDIT C2 / R1 ──────────────────────────────────────────────
//
// The R conjunct was pinned only at R = identity. Of the 50 fixture vectors
// carrying a valid public key and an inadmissible R, 8 were LIVE — refused by
// the guard AND accepted by a permissive verifier — and all 8 were R = the
// identity encoding. A=valid x R=small-order was 16/0 and A=valid x R=all-zero
// was 9/0: every one of those 25 is already refused by crypto/ed25519, so they
// constrain nothing about the guard. Narrowing the R test to "R != the identity
// encoding" passed the whole suite.
//
// The vectors below close that. Each carries an ADMISSIBLE public key
// A = A0 + T (A0 prime order, T of order 8, so [8]A != identity) and an R of
// order 2, 4 and 8. crypto/ed25519 accepts all three; only the small-order test
// on R refuses them. A fourth vector is the positive control: the same key with
// a full-order canonical R, which must verify, so a refusal of the three is
// attributable to the R half and not to the key.
//
// LIVENESS IS ASSERTED, NOT ASSUMED. A vector that a permissive verifier also
// rejects pins nothing, and 24 of the 32 existing small_order_R_honest_key
// vectors are vacuous in exactly that way. Counting them was the defect
// (RETRO-AUDIT C9); this test measures instead.

// permissiveVerify is crypto/ed25519 with no APS-side admissibility check: the
// oracle for whether a negative vector discriminates. If this accepts and
// VerifyEd25519 refuses, the vector is LIVE and the guard is what refused it.
func permissiveVerify(t *testing.T, v admissibilityVector) bool {
	t.Helper()
	pk, err := hex.DecodeString(v.PublicKey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(v.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), []byte(v.Message), sig)
}

func TestSmallOrderRUnderAnAdmissibleTorsionAliasedKeyIsRefusedAndLive(t *testing.T) {
	doc := loadAdmissibility(t)

	var group []admissibilityVector
	for _, v := range doc.Vectors {
		if v.Group == "small_order_R_torsion_alias_A" {
			group = append(group, v)
		}
	}
	if len(group) != 3 {
		t.Fatalf("small_order_R_torsion_alias_A carries %d vectors, want 3 (R of order 2, 4 and 8)", len(group))
	}

	// The R halves must be three DISTINCT small-order encodings, not the same
	// point three times, and none of them may be the identity: pinning
	// R = identity three more times is what this test exists to stop.
	const identityR = "0100000000000000000000000000000000000000000000000000000000000000"
	seen := map[string]bool{}
	live := 0
	for _, v := range group {
		rHalf := v.Signature[:64]
		if rHalf == identityR {
			t.Errorf("%s: R is the identity encoding; the class already pinned by the existing vectors", v.ID)
		}
		if seen[rHalf] {
			t.Errorf("%s: duplicate R half %s", v.ID, rHalf)
		}
		seen[rHalf] = true

		if v.Expected {
			t.Errorf("%s: expected_verification must be false", v.ID)
			continue
		}
		if got := VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey); got {
			t.Errorf("%s: the guard ACCEPTED a signature whose R has small order", v.ID)
		}
		if !permissiveVerify(t, v) {
			t.Errorf("%s: VACUOUS. crypto/ed25519 rejects this vector too, so it pins nothing about the guard "+
				"and would survive a mutation that removed the R check entirely.", v.ID)
			continue
		}
		live++
	}
	if live != 3 {
		t.Fatalf("%d of 3 vectors are LIVE; all three must be accepted by crypto/ed25519 and refused by the guard", live)
	}
	t.Logf("R half forced by %d LIVE vectors over %d distinct non-identity small-order R encodings", live, len(seen))
}

// The positive control. Without it, a guard that refused EVERY signature under a
// torsion-aliased key would also pass the test above, and the three negatives
// would not isolate the R half at all.
func TestTheTorsionAliasedKeyItselfIsAdmissible(t *testing.T) {
	doc := loadAdmissibility(t)

	var control []admissibilityVector
	for _, v := range doc.Vectors {
		if v.Group == "torsion_alias_A_valid_R" {
			control = append(control, v)
		}
	}
	if len(control) != 1 {
		t.Fatalf("torsion_alias_A_valid_R carries %d vectors, want 1", len(control))
	}
	v := control[0]
	if !v.Expected {
		t.Fatalf("%s: the control must be expected_verification true", v.ID)
	}
	if !permissiveVerify(t, v) {
		t.Fatalf("%s: the control does not verify under crypto/ed25519, so it controls nothing", v.ID)
	}
	if !VerifyEd25519([]byte(v.Message), v.Signature, v.PublicKey) {
		t.Fatalf("%s: the guard refused the control, so the refusals above are not attributable to the R half", v.ID)
	}

	// The control and the three negatives must share one public key, or they do
	// not isolate anything.
	for _, n := range doc.Vectors {
		if n.Group == "small_order_R_torsion_alias_A" && n.PublicKey != v.PublicKey {
			t.Errorf("%s uses a different public key from the control; the R half is not isolated", n.ID)
		}
	}

	// And this is the documented limit, now contradicted by a test rather than
	// by a comment: the guard admits torsion aliases, so one private key has
	// eight admissible public keys (RETRO-AUDIT C5). Verifying is CORRECT for a
	// signature primitive. A consumer that infers identity from "the signature
	// verified" is the thing this pins against.
	t.Logf("torsion-aliased public key %s is admissible and verifies", v.PublicKey)
}
