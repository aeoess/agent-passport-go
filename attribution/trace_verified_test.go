// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package attribution

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aeoess/agent-passport-go/delegation"
	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// seedFromLabel derives a deterministic 32-byte Ed25519 seed hex from a label,
// the same sha256(label) derivation the TS oracle uses, so both sides sign with
// the same key material.
func seedFromLabel(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// signTraceDelegation mints a signed delegation via the delegation package (so
// its canonical preimage is exactly what delegation.VerifyDelegation checks) and
// returns it projected to the enriched TraceDelegation shape. The fixed
// far-future expiry and past notBefore keep it temporally valid.
func signTraceDelegation(t *testing.T, delegatorSeed, id, from, to string, scope []string) TraceDelegation {
	t.Helper()
	maxD := 1
	del, err := delegation.CreateDelegation(delegation.CreateOptions{
		PrivateKey:   delegatorSeed,
		DelegationID: id,
		DelegatedBy:  from,
		DelegatedTo:  to,
		Scope:        scope,
		MaxDepth:     maxD,
		CurrentDepth: 0,
		ExpiresAt:    "2099-01-01T00:00:00.000Z",
		NotBefore:    "2026-01-01T00:00:00.000Z",
		CreatedAt:    "2026-01-01T00:00:00.000Z",
	})
	if err != nil {
		t.Fatalf("CreateDelegation: %v", err)
	}
	return TraceDelegation{
		DelegationID: del.DelegationID,
		DelegatedBy:  del.DelegatedBy,
		DelegatedTo:  del.DelegatedTo,
		Scope:        del.Scope,
		ExpiresAt:    del.ExpiresAt,
		NotBefore:    del.NotBefore,
		CreatedAt:    del.CreatedAt,
		MaxDepth:     del.MaxDepth,
		CurrentDepth: del.CurrentDepth,
		SpendLimit:   del.SpendLimit,
		Signature:    del.Signature,
	}
}

// signReceipt signs a receipt over canonicalize(receipt minus signature) with
// the given seed, the exact preimage TS verifyReceipt checks.
func signReceipt(t *testing.T, receipt ActionReceipt, seed string) string {
	t.Helper()
	gv, err := toGeneric(receipt)
	if err != nil {
		t.Fatalf("toGeneric receipt: %v", err)
	}
	g, ok := gv.(map[string]interface{})
	if !ok {
		t.Fatal("receipt did not project to a map")
	}
	delete(g, "signature")
	canon, err := jcs.Canonicalize(g)
	if err != nil {
		t.Fatalf("canonicalize receipt: %v", err)
	}
	sig, err := keys.Sign(canon, seed)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return sig
}

// ── Unit tests (no TS repo needed) ─────────────────────────────────────────

// TestTraceVerifiedFullyValidChain: a real signed chain is both resolved and
// verified.
func TestTraceVerifiedFullyValidChain(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if !got.Resolved {
		t.Errorf("expected resolved=true, got false: %+v", got)
	}
	if !got.Verified {
		t.Errorf("expected verified=true, got false: %+v", got)
	}
	if got.Beneficiary != "human_alice" {
		t.Errorf("expected beneficiary human_alice, got %q", got.Beneficiary)
	}
}

// TestTraceForgedDelegationSignature: a delegation whose signature is corrupted
// fails verifyDelegation, so verified=false. resolved stays true because the
// (from,to) pair still maps to a known delegation record (lookup only).
func TestTraceForgedDelegationSignature(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	// Flip the delegation signature bytes: valid hex, wrong signature.
	delegations[0].Signature = flipHexTail(delegations[0].Signature)

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Verified {
		t.Errorf("forged delegation signature must not verify: %+v", got)
	}
	if !got.Resolved {
		t.Errorf("resolved is lookup-only and should still be true with a known delegation record: %+v", got)
	}
}

// TestTraceEmptyDelegationSignature: an absent delegation signature fails
// verifyDelegation, so verified=false.
func TestTraceEmptyDelegationSignature(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	delegations[0].Signature = ""

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Verified {
		t.Errorf("empty delegation signature must not verify: %+v", got)
	}
}

// TestTraceForgedReceiptSignature: a corrupted receipt signature fails
// verifyReceipt against the tail key, so verified=false even though every hop's
// delegation is authentic and the chain resolves.
func TestTraceForgedReceiptSignature(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	receipt.Signature = flipHexTail(receipt.Signature)

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Verified {
		t.Errorf("forged receipt signature must not verify: %+v", got)
	}
	if !got.Resolved {
		t.Errorf("resolved is lookup-only and independent of the receipt signature: %+v", got)
	}
}

// TestTraceEmptyReceiptSignature: an absent receipt signature fails
// verifyReceipt, so verified=false.
func TestTraceEmptyReceiptSignature(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	receipt.Signature = ""

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Verified {
		t.Errorf("empty receipt signature must not verify: %+v", got)
	}
}

// TestTraceKeyChainLengthOne: a single-key chain has no hops, so verified=false
// (keyChain<2) regardless of the receipt signature. resolved is also false
// because resolved requires keyChain.length>1.
func TestTraceKeyChainLengthOne(t *testing.T) {
	receipt, delegations, bmap, principalPub, _ := signedTraceFixture(t)
	// Collapse the chain to a single key; re-sign the receipt for that chain so
	// the failure is attributable to length, not to a stale signature.
	agentSeed := seedFromLabel("aps-go-trace-agent")
	receipt.DelegationChain = []string{principalPub}
	receipt.Signature = signReceipt(t, receipt, agentSeed)

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Verified {
		t.Errorf("keyChain length 1 must not verify: %+v", got)
	}
	if got.Resolved {
		t.Errorf("keyChain length 1 must not resolve (needs length>1): %+v", got)
	}
}

// TestTraceResolvedButNotVerified is the headline defect guard: a chain whose
// records all resolve by lookup but whose delegation signature is forged must
// report resolved=true, verified=false. The pre-fix code (Verified from lookup
// success) reported the opposite for a forged-but-resolvable chain.
func TestTraceResolvedButNotVerified(t *testing.T) {
	receipt, delegations, bmap, _, _ := signedTraceFixture(t)
	delegations[0].Signature = flipHexTail(delegations[0].Signature)

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if !(got.Resolved && !got.Verified) {
		t.Errorf("expected resolved=true, verified=false for a forged-but-resolvable chain: %+v", got)
	}
}

// flipHexTail returns a valid-hex signature of the same length with its last
// hex nibble changed, producing a well-formed but incorrect signature.
func flipHexTail(sig string) string {
	if sig == "" {
		return sig
	}
	last := sig[len(sig)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return sig[:len(sig)-1] + string(repl)
}
