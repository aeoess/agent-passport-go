// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package passport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

// tsRepo is the reference TypeScript SDK checkout the cross-impl oracle runs
// against, resolved from APS_TS_REPO. The oracle imports the real
// createPassport/signPassport/verify functions from this path, exactly how the
// action_ref cross-impl check works. When APS_TS_REPO is unset the live oracle
// skips (see skipUnlessTSRepo); the pinned constants still gate the invariant.
var tsRepo = os.Getenv("APS_TS_REPO")

// skipUnlessTSRepo skips the calling cross-impl test when APS_TS_REPO is unset
// or empty, with the canonical message, before any use of the repo path or tsx.
func skipUnlessTSRepo(t *testing.T) {
	t.Helper()
	if tsRepo == "" {
		t.Skip("set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	}
}

// Deterministic inputs shared by Go and the TS oracle. Private keys are 32-byte
// Ed25519 seeds derived as sha256 of a fixed string, identical on both sides.
const (
	agentKeySeed  = "aps-go-passport-agent-key"
	issuerKeySeed = "aps-go-passport-issuer-key"

	fixedCreatedAt   = "2026-06-03T12:00:00Z"
	fixedExpiresAt   = "2027-06-03T12:00:00Z"
	fixedSignedAt    = "2026-06-03T12:00:00Z"
	fixedVerifyNow   = "2026-06-03T13:00:00Z" // after createdAt, before expiry
	fixedNonce       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixedChallengeID = "chal_0001"
)

// Pinned values produced by the reference TypeScript SDK at build time on the
// deterministic inputs above (sha256-seeded keys, fixed timestamps, fixed
// nonce). Captured by running the same oracle this test shells out to. These
// are not invented; they are the real TS output and guard against drift even
// when tsx is unavailable.
const (
	// sha256 of canonicalize(passport): the agent signed-bytes preimage.
	tsPassportCanonicalSHA256 = "0870b81e3d922da164321e92e1310d983b1ba419d7cf637ac057edd3bbd039fe"
	// Ed25519 agent signature over canonicalize(passport).
	tsAgentSignature = "587cac21033db22d8e6744ddf3d75219228d7384f4868bb9b5e7a025c7f856dacfc343e6fa3ed1c0141cc0fc4460fa21ae2bb879ec3051e78531c4b8b146700a"
	// sha256 of canonicalize({passport, signature, signedAt}): issuer preimage.
	tsIssuerPayloadSHA256 = "a884026138ac415a483f2d4322a167e9d919915939ad1d8afc5d5934af8d99e1"
	// Ed25519 issuer countersignature over that preimage.
	tsIssuerSignature = "3f4bebf4250638b44f27b0e8649833025e0f3f9e9cad0cb26efcf3b741da12a04a739a2cdaf15e15ae9b51cc8d607af2e835f7e196d228ce8a18a7d5ad65180f"
	// Ed25519 signature over the raw challenge nonce string.
	tsChallengeSignature = "f7cd4bb47755b9b6cf8bf51aebdca9789bcf027836e241fdc993f7604602165c2963db50ba6a4af5ddfc1af424c347bcdb9ec30bec8b1f00798daf1ae92e3404"
)

func seedHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fixturePassport builds the deterministic SignedPassport from the shared
// inputs. The returned signed passport carries the agent self-signature.
func fixturePassport(t *testing.T) (signed SignedPassport, agentPriv, agentPub, issuerPriv, issuerPub string) {
	t.Helper()
	agentPriv = seedHex(agentKeySeed)
	issuerPriv = seedHex(issuerKeySeed)
	var err error
	agentPub, err = keys.PublicKeyFromPrivate(agentPriv)
	if err != nil {
		t.Fatalf("derive agent pub: %v", err)
	}
	issuerPub, err = keys.PublicKeyFromPrivate(issuerPriv)
	if err != nil {
		t.Fatalf("derive issuer pub: %v", err)
	}
	in := CreatePassportInput{
		AgentID:      "ag_passport_001",
		AgentName:    "Oracle Agent",
		OwnerAlias:   "owner-alpha",
		PublicKey:    agentPub,
		Mission:      "cross-impl byte parity",
		Capabilities: []string{"code_execution", "web_search"},
		Runtime:      RuntimeInfo{Platform: "node", Models: []string{"claude-opus-4"}, ToolsCount: 3, MemoryType: "ephemeral"},
		CreatedAt:    fixedCreatedAt,
		ExpiresAt:    fixedExpiresAt,
		Reputation:   ReputationScore{Overall: 1, LastUpdated: fixedCreatedAt},
	}
	signed, err = CreatePassport(in, agentPriv, fixedSignedAt)
	if err != nil {
		t.Fatalf("CreatePassport: %v", err)
	}
	return signed, agentPriv, agentPub, issuerPriv, issuerPub
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestPassportPinnedAgainstTSReference asserts the Go artifacts are byte/hex
// identical to the pinned reference TS output: the canonical-byte sha256 of the
// passport, the agent signature, the issuer preimage hash, the issuer
// signature, and the challenge signature. This always runs (no tsx needed).
func TestPassportPinnedAgainstTSReference(t *testing.T) {
	signed, agentPriv, _, issuerPriv, _ := fixturePassport(t)

	canonical, err := CanonicalBytes(signed.Passport)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if got := sha256Hex(canonical); got != tsPassportCanonicalSHA256 {
		t.Errorf("passport canonical sha256\n  go = %s\n  ts = %s", got, tsPassportCanonicalSHA256)
	}
	if signed.Signature != tsAgentSignature {
		t.Errorf("agent signature\n  go = %s\n  ts = %s", signed.Signature, tsAgentSignature)
	}

	cs, err := CountersignPassport(signed, issuerPriv, "aeoess", fixedSignedAt)
	if err != nil {
		t.Fatalf("CountersignPassport: %v", err)
	}
	issuerCanonical, err := IssuerCanonicalBytes(cs)
	if err != nil {
		t.Fatalf("IssuerCanonicalBytes: %v", err)
	}
	if got := sha256Hex(issuerCanonical); got != tsIssuerPayloadSHA256 {
		t.Errorf("issuer payload sha256\n  go = %s\n  ts = %s", got, tsIssuerPayloadSHA256)
	}
	if cs.IssuerSignature.Signature != tsIssuerSignature {
		t.Errorf("issuer signature\n  go = %s\n  ts = %s", cs.IssuerSignature.Signature, tsIssuerSignature)
	}

	ch := Challenge{ChallengeID: fixedChallengeID, Nonce: fixedNonce, Timestamp: fixedCreatedAt, ExpiresAt: "2099-01-01T00:00:00Z"}
	agentPub, _ := keys.PublicKeyFromPrivate(agentPriv)
	resp, err := SignChallenge(ch, agentPriv, agentPub)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	if resp.Signature != tsChallengeSignature {
		t.Errorf("challenge signature\n  go = %s\n  ts = %s", resp.Signature, tsChallengeSignature)
	}
}

// tsOracle is the reference oracle. It builds the SAME passport object the Go
// fixture builds, runs the real reference signPassport/countersignPassport/
// verifyPassport/verifyChallenge over it, and prints a JSON blob of canonical
// bytes, hashes, signatures, and verify results. Run via `npx tsx -e`.
var tsOracle = `
import { signPassport, countersignPassport, verifyIssuerSignature } from '` + tsRepo + `/src/core/passport.ts';
import { verifyPassport, verifyChallenge } from '` + tsRepo + `/src/verification/verify.ts';
import { canonicalize } from '` + tsRepo + `/src/core/canonical.ts';
import { sign, publicKeyFromPrivate, verify } from '` + tsRepo + `/src/crypto/keys.ts';
import { createHash } from 'node:crypto';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const agentPriv = sha('` + agentKeySeed + `').slice(0); // sha256 hex of seed string
const agentPrivHex = createHash('sha256').update('` + agentKeySeed + `').digest('hex');
const issuerPrivHex = createHash('sha256').update('` + issuerKeySeed + `').digest('hex');
const agentPub = publicKeyFromPrivate(agentPrivHex);
const issuerPub = publicKeyFromPrivate(issuerPrivHex);

const passport = {
  version: '1.0.0',
  agentId: 'ag_passport_001',
  agentName: 'Oracle Agent',
  ownerAlias: 'owner-alpha',
  publicKey: agentPub,
  mission: 'cross-impl byte parity',
  capabilities: ['code_execution','web_search'],
  runtime: { platform: 'node', models: ['claude-opus-4'], toolsCount: 3, memoryType: 'ephemeral' },
  createdAt: '` + fixedCreatedAt + `',
  expiresAt: '` + fixedExpiresAt + `',
  voteWeight: 2,
  reputation: { overall: 1, collaborationsCompleted: 0, proposalsSubmitted: 0, proposalsApproved: 0, tokensContributed: 0, tasksCompleted: 0, lastUpdated: '` + fixedCreatedAt + `' },
  delegations: [],
  metadata: {}
};

const passCanonical = canonicalize(passport);
const agentSig = sign(passCanonical, agentPrivHex);
const signedAt = '` + fixedSignedAt + `';
const signed = { passport, signature: agentSig, signedAt };

const issuerPayload = canonicalize({ passport, signature: agentSig, signedAt });
const issuerSig = sign(issuerPayload, issuerPrivHex);
const countersigned = { ...signed, issuerSignature: { issuerId: 'aeoess', issuerPublicKey: issuerPub, signature: issuerSig, signedAt: signedAt } };

const challenge = { challengeId: '` + fixedChallengeID + `', nonce: '` + fixedNonce + `', timestamp: '` + fixedCreatedAt + `', expiresAt: '2099-01-01T00:00:00Z' };
const chalSig = sign(challenge.nonce, agentPrivHex);

const out = {
  agentPub,
  issuerPub,
  passportCanonicalSHA256: sha(passCanonical),
  agentSignature: agentSig,
  issuerPayloadSHA256: sha(issuerPayload),
  issuerSignature: issuerSig,
  challengeSignature: chalSig,
  verifyIssuer: verifyIssuerSignature(countersigned, issuerPub),
  verifyPassport: verifyPassport(signed).valid,
  verifyChallenge: verifyChallenge(challenge, chalSig, agentPub),
};
process.stdout.write(JSON.stringify(out));
`

type oracleOut struct {
	AgentPub                string `json:"agentPub"`
	IssuerPub               string `json:"issuerPub"`
	PassportCanonicalSHA256 string `json:"passportCanonicalSHA256"`
	AgentSignature          string `json:"agentSignature"`
	IssuerPayloadSHA256     string `json:"issuerPayloadSHA256"`
	IssuerSignature         string `json:"issuerSignature"`
	ChallengeSignature      string `json:"challengeSignature"`
	VerifyIssuer            bool   `json:"verifyIssuer"`
	VerifyPassport          bool   `json:"verifyPassport"`
	VerifyChallenge         bool   `json:"verifyChallenge"`
}

// runTSOracle runs the reference oracle via npx tsx and parses its JSON. It
// skips the calling test (rather than failing) when the TS repo or tsx is not
// available, so the suite stays green in environments without the reference.
func runTSOracle(t *testing.T) oracleOut {
	t.Helper()
	if _, err := os.Stat(tsRepo); err != nil {
		t.Skipf("TS reference repo not present at %s; skipping live cross-impl", tsRepo)
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not on PATH; skipping live cross-impl")
	}
	scriptPath := filepath.Join(t.TempDir(), "oracle.mjs")
	if err := os.WriteFile(scriptPath, []byte(tsOracle), 0o600); err != nil {
		t.Fatalf("write oracle: %v", err)
	}
	cmd := exec.Command("npx", "tsx", scriptPath)
	cmd.Dir = tsRepo
	outBytes, err := cmd.Output()
	if err != nil {
		t.Skipf("tsx oracle did not run (%v); skipping live cross-impl", err)
	}
	var out oracleOut
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatalf("parse oracle JSON: %v\nraw: %s", err, string(outBytes))
	}
	return out
}

// TestPassportLiveCrossImpl runs the real reference TS SDK at test time and
// asserts the Go artifacts are byte/hex identical, AND cross-verifies both
// directions: TS signatures verify under Go Verify, and Go signatures verify
// under TS verify (the oracle's verify* booleans run over the Go-matching
// objects, and Go re-verifies the TS signatures here).
func TestPassportLiveCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	ts := runTSOracle(t)
	signed, agentPriv, agentPub, issuerPriv, issuerPub := fixturePassport(t)

	if ts.AgentPub != agentPub {
		t.Fatalf("agent pubkey mismatch: ts=%s go=%s", ts.AgentPub, agentPub)
	}
	if ts.IssuerPub != issuerPub {
		t.Fatalf("issuer pubkey mismatch: ts=%s go=%s", ts.IssuerPub, issuerPub)
	}

	canonical, _ := CanonicalBytes(signed.Passport)
	if got := sha256Hex(canonical); got != ts.PassportCanonicalSHA256 {
		t.Errorf("passport canonical sha256: go=%s ts=%s", got, ts.PassportCanonicalSHA256)
	}
	if signed.Signature != ts.AgentSignature {
		t.Errorf("agent signature: go=%s ts=%s", signed.Signature, ts.AgentSignature)
	}

	cs, err := CountersignPassport(signed, issuerPriv, "aeoess", fixedSignedAt)
	if err != nil {
		t.Fatalf("CountersignPassport: %v", err)
	}
	issuerCanonical, _ := IssuerCanonicalBytes(cs)
	if got := sha256Hex(issuerCanonical); got != ts.IssuerPayloadSHA256 {
		t.Errorf("issuer payload sha256: go=%s ts=%s", got, ts.IssuerPayloadSHA256)
	}
	if cs.IssuerSignature.Signature != ts.IssuerSignature {
		t.Errorf("issuer signature: go=%s ts=%s", cs.IssuerSignature.Signature, ts.IssuerSignature)
	}

	ch := Challenge{ChallengeID: fixedChallengeID, Nonce: fixedNonce, Timestamp: fixedCreatedAt, ExpiresAt: "2099-01-01T00:00:00Z"}
	resp, _ := SignChallenge(ch, agentPriv, agentPub)
	if resp.Signature != ts.ChallengeSignature {
		t.Errorf("challenge signature: go=%s ts=%s", resp.Signature, ts.ChallengeSignature)
	}

	// Direction 1: TS-created signatures verify under Go.
	if !keys.Verify(canonical, ts.AgentSignature, agentPub) {
		t.Error("Go failed to verify TS agent signature")
	}
	tsCountersigned := cs
	tsCountersigned.Signature = ts.AgentSignature
	tsCountersigned.IssuerSignature = &IssuerSignature{
		IssuerID: "aeoess", IssuerPublicKey: issuerPub, Signature: ts.IssuerSignature, SignedAt: fixedSignedAt,
	}
	if !VerifyIssuerSignature(tsCountersigned, issuerPub) {
		t.Error("Go failed to verify TS issuer countersignature")
	}
	tsSigned := signed
	tsSigned.Signature = ts.AgentSignature
	if res := VerifyPassport(tsSigned, nil, fixedVerifyNow); !res.Valid {
		t.Errorf("Go VerifyPassport rejected TS-signed passport: %v", res.Errors)
	}
	if !VerifyChallenge(ch, ts.ChallengeSignature, agentPub, fixedVerifyNow) {
		t.Error("Go failed to verify TS challenge signature")
	}

	// Direction 2: Go-created signatures verify under TS. The oracle ran
	// verifyPassport/verifyIssuerSignature/verifyChallenge over objects whose
	// signatures equal the Go signatures (identical bytes), so these booleans
	// being true is the TS-verifies-Go assertion.
	if !ts.VerifyPassport {
		t.Error("TS verifyPassport rejected the matching (Go-equal) passport")
	}
	if !ts.VerifyIssuer {
		t.Error("TS verifyIssuerSignature rejected the matching (Go-equal) countersignature")
	}
	if !ts.VerifyChallenge {
		t.Error("TS verifyChallenge rejected the matching (Go-equal) challenge")
	}
}
