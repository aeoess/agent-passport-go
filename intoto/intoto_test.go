// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package intoto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// ── Deterministic inputs ──
//
// No randomness, no wall clock. The signer seed is sha256("aps-go-intoto-key")
// derived identically in Go and in the TS harness. issuedAt is pinned to the
// exact string the reference SDK's new Date().toISOString() renders for whole
// seconds (a trailing .000Z). All IDs, timestamps, and nonces are fixed.

const (
	// tsRepo is the reference TS SDK checkout used by the build-time oracle.
	tsRepo = "/Users/tima/agent-passport-system"

	// seedString is hashed to the 32-byte Ed25519 seed on BOTH sides.
	seedString = "aps-go-intoto-key"

	// fixedIssuedAt is what new Date('2026-06-03T12:00:00Z').toISOString()
	// renders in the TS harness (millisecond precision).
	fixedIssuedAt = "2026-06-03T12:00:00.000Z"
)

// deriveSeed reproduces the seed both implementations use.
func deriveSeed() string {
	sum := sha256.Sum256([]byte(seedString))
	return hex.EncodeToString(sum[:])
}

// ── Cross-impl pins ──
//
// These hex values were produced by the REAL TS reference SDK
// (src/decisionReceipt.ts emitDecisionReceipt) at build time, on the exact
// deterministic inputs in buildVector1 / buildVector2, with the global Date
// mocked to fixedIssuedAt. Do not hand-edit: regenerate via the tsx oracle
// (TestEmitDecisionReceiptCrossImpl drives it when the TS repo is present).
const (
	// Vector 1: intent carries actionRef = "aref_fixed", verdict permit.
	wantPayloadSHA256V1 = "d8424ab2a9e6b08b2901731f25ef92c090bc0b3ebd18ccef1ed5ae30acb8b5fc"
	wantSignatureV1     = "8d9e4b23097c44d67f681cd649d9978e7c05685f39d676a0b06cafd90925713255cfec3cfa644393ac8125d772cc04d2b33a564f693a77bcb24abaefac34f401"
	wantChainRootV1     = "414a35cc7f08bbb8378a9c334bdc29abf6a03ce4db64da45a7562f157b939263"

	// Vector 2: intent has NO actionRef, so metadata.actionRef is JSON null;
	// verdict narrow, single-hop chain.
	wantPayloadSHA256V2 = "63cba775ddd92cbd81011c986c295795a2d2a0e034a480b8b96178d9ec339dc7"
	wantSignatureV2     = "d184a4882b3d22a0f68b83560a8a2c49bfc3af1a079e72fd110e5fbb61bbd3aadb9ad031b6f7985dc281cb036d1921346bd25e76035d7a66fb223c3a9b88d10c"
	wantChainRootV2     = "7dfdbd601f103bb46ca6c3c13f72a34c2905ba025d4771cf8ea9b7041cda1630"
)

// buildVector1 returns the EmitInput for the actionRef-present vector. pub is
// the seed's derived public key, embedded into the intent so the intent digest
// matches the TS side exactly.
func buildVector1(pub string) EmitInput {
	intent := map[string]interface{}{
		"intentId":       "int_fixed_001",
		"agentId":        "ag_intoto_001",
		"agentPublicKey": pub,
		"delegationId":   "del_fixed_001",
		"action": map[string]interface{}{
			"type": "code_execution", "target": "repo://x", "scopeRequired": "compute:exec",
		},
		"actionRef": "aref_fixed",
		"createdAt": "2026-06-03T11:00:00Z",
		"signature": "deadbeef",
	}
	receipt := map[string]interface{}{
		"receiptId": "rcpt_fixed_001", "version": "2.3.0", "timestamp": "2026-06-03T11:45:00Z",
		"agentId": "ag_intoto_001", "delegationId": "del_fixed_001",
		"action": map[string]interface{}{
			"type": "code_execution", "target": "repo://x", "scopeUsed": "compute:exec",
		},
		"result":          map[string]interface{}{"status": "success", "summary": "done"},
		"delegationChain": []interface{}{"fp_root", "fp_leaf"},
		"signature":       "beefcafe",
	}
	chain := []interface{}{
		map[string]interface{}{
			"delegationId": "del_root_001", "delegatedTo": "ag_mid_001", "delegatedBy": "principal_001",
			"scope": []interface{}{"compute:exec", "data:read"}, "expiresAt": "2026-06-04T00:00:00Z",
			"maxDepth": 3, "currentDepth": 1, "createdAt": "2026-06-01T00:00:00Z", "signature": "sig_root",
		},
		map[string]interface{}{
			"delegationId": "del_leaf_001", "delegatedTo": "ag_intoto_001", "delegatedBy": "ag_mid_001",
			"scope": []interface{}{"compute:exec"}, "expiresAt": "2026-06-03T18:00:00Z",
			"maxDepth": 3, "currentDepth": 2, "createdAt": "2026-06-02T00:00:00Z", "signature": "sig_leaf",
		},
	}
	return EmitInput{
		Intent: intent, Receipt: receipt, DelegationChain: chain,
		EpistemicClaims: EpistemicClaims{
			PolicyEvaluated: "closed", AuthorityConsumed: "witnessed",
			ScopeWithinBounds: "closed", EffectOccurred: "witnessed-by-subject",
		},
		Verdict: "permit", Reason: "within floor", PolicyID: "floor-validator-v1",
		FloorVersion: "floor@0.1", IssuerID: "did:aps:issuer001",
		IssuedAt: fixedIssuedAt, ActionRef: "aref_fixed", APSVersion: "2.3.0-alpha",
		SignerPrivateKey: deriveSeed(), SignerKeyID: "ed25519:fixedkeyid01",
	}
}

// buildVector2 returns the EmitInput for the actionRef-absent vector.
func buildVector2(pub string) EmitInput {
	intent := map[string]interface{}{
		"intentId": "int_noref_002", "agentId": "ag_intoto_002", "agentPublicKey": pub,
		"delegationId": "del_noref_002",
		"action": map[string]interface{}{
			"type": "web_search", "target": "https://x", "scopeRequired": "data:read",
		},
		"createdAt": "2026-06-03T10:00:00Z", "signature": "aa11",
	}
	receipt := map[string]interface{}{
		"receiptId": "rcpt_noref_002", "version": "2.3.0", "timestamp": "2026-06-03T10:30:00Z",
		"agentId": "ag_intoto_002", "delegationId": "del_noref_002",
		"action": map[string]interface{}{
			"type": "web_search", "target": "https://x", "scopeUsed": "data:read",
		},
		"result":          map[string]interface{}{"status": "success", "summary": "ok"},
		"delegationChain": []interface{}{"fp_a"}, "signature": "bb22",
	}
	chain := []interface{}{
		map[string]interface{}{
			"delegationId": "del_only_002", "delegatedTo": "ag_intoto_002", "delegatedBy": "principal_002",
			"scope": []interface{}{"data:read"}, "expiresAt": "2026-06-05T00:00:00Z",
			"maxDepth": 2, "currentDepth": 1, "createdAt": "2026-06-01T00:00:00Z", "signature": "sig_only",
		},
	}
	return EmitInput{
		Intent: intent, Receipt: receipt, DelegationChain: chain,
		EpistemicClaims: EpistemicClaims{
			PolicyEvaluated: "closed", AuthorityConsumed: "witnessed",
			ScopeWithinBounds: "unresolved", EffectOccurred: "self-asserted",
		},
		Verdict: "narrow", Reason: "scope narrowed", PolicyID: "floor-validator-v2",
		FloorVersion: "floor@0.2", IssuerID: "did:aps:issuer002",
		IssuedAt: fixedIssuedAt, ActionRef: "", APSVersion: "2.3.0-alpha",
		SignerPrivateKey: deriveSeed(), SignerKeyID: "ed25519:norefkey02",
	}
}

func payloadSHA256(env DecisionReceiptEnvelope) string {
	sum := sha256.Sum256([]byte(env.Payload))
	return hex.EncodeToString(sum[:])
}

// TestEmitMatchesPins asserts the Go envelope is byte/hex-identical to the
// pinned TS reference values for both vectors, and that the Go envelope
// self-verifies under the Go verifier. These pins were produced by the live TS
// SDK; the oracle test below regenerates and reconfirms them when the TS repo
// is present.
func TestEmitMatchesPins(t *testing.T) {
	seed := deriveSeed()
	pub, err := keys.PublicKeyFromPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name            string
		in              EmitInput
		wantPayloadHash string
		wantSig         string
		wantChainRoot   string
	}{
		{"vector1_actionref_present", buildVector1(pub), wantPayloadSHA256V1, wantSignatureV1, wantChainRootV1},
		{"vector2_actionref_null", buildVector2(pub), wantPayloadSHA256V2, wantSignatureV2, wantChainRootV2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, err := EmitDecisionReceipt(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := payloadSHA256(env); got != c.wantPayloadHash {
				t.Errorf("payload sha256 = %s, want %s (TS reference)", got, c.wantPayloadHash)
			}
			if env.Digest.SHA256 != c.wantPayloadHash {
				t.Errorf("_digest = %s, want %s", env.Digest.SHA256, c.wantPayloadHash)
			}
			if got := env.Signatures[0].Sig; got != c.wantSig {
				t.Errorf("signature = %s, want %s (TS reference)", got, c.wantSig)
			}
			root, err := ComputeDelegationChainRoot(c.in.DelegationChain)
			if err != nil {
				t.Fatal(err)
			}
			if root != c.wantChainRoot {
				t.Errorf("chain root = %s, want %s (TS reference)", root, c.wantChainRoot)
			}
			if !VerifyEnvelope(env, pub, 0) {
				t.Error("Go envelope did not verify under Go VerifyEnvelope")
			}
		})
	}
}

// tsOracleResult is the JSON the tsx harness prints.
type tsOracleResult struct {
	Pub           string `json:"pub"`
	Payload       string `json:"payload"`
	PayloadSHA256 string `json:"payloadSha256"`
	Signature     string `json:"signature"`
	ChainRoot     string `json:"chainRoot"`
	TSVerifiesGo  bool   `json:"tsVerifiesGo"`
}

// tsHarness is the inline tsx program. It mocks the global Date so the SDK's
// new Date().toISOString() is deterministic, runs the real emitDecisionReceipt
// on the same inputs as the Go side, and also verifies a Go-produced payload +
// signature under the TS verify() (the Go -> TS direction). Inputs are passed
// in as env vars to keep the two sides driven by one source of truth.
const tsHarness = `
const FIXED = process.env.FIXED_ISO;
const RealDate = Date;
class MockDate extends RealDate {
  constructor(...args){ if(args.length===0){super(FIXED);}else{super(...args);} }
  static now(){ return new RealDate(FIXED).getTime(); }
}
globalThis.Date = MockDate;
const { createHash } = await import('node:crypto');
const dr = await import(process.env.TS_REPO + '/src/decisionReceipt.ts');
const keysMod = await import(process.env.TS_REPO + '/src/crypto/keys.ts');
const seed = createHash('sha256').update(process.env.SEED_STRING).digest('hex');
const pub = keysMod.publicKeyFromPrivate(seed);
const inp = JSON.parse(process.env.EMIT_INPUT);
inp.intent.agentPublicKey = pub;
const env = dr.emitDecisionReceipt({
  intent: inp.intent,
  decision: inp.decision,
  receipt: inp.receipt,
  delegationChain: inp.delegationChain,
  epistemicClaims: inp.epistemicClaims,
  policyId: inp.policyId,
  signerPrivateKey: seed,
  signerKeyId: inp.signerKeyId,
  issuerId: inp.issuerId,
  apsVersion: inp.apsVersion,
});
const payloadSha256 = createHash('sha256').update(env.payload).digest('hex');
let tsVerifiesGo = false;
if (process.env.GO_PAYLOAD && process.env.GO_SIG) {
  tsVerifiesGo = keysMod.verify(process.env.GO_PAYLOAD, process.env.GO_SIG, pub);
}
console.log(JSON.stringify({
  pub, payload: env.payload, payloadSha256,
  signature: env.signatures[0].sig,
  chainRoot: dr.computeDelegationChainRoot(inp.delegationChain),
  tsVerifiesGo,
}));
`

// emitInputJSON shapes the EmitInput as the SDK's EmitDecisionReceiptInput JSON.
// agentPublicKey is overwritten inside the harness with the seed-derived key.
func emitInputJSON(in EmitInput) ([]byte, error) {
	decision := map[string]interface{}{
		"verdict":      in.Verdict,
		"reason":       in.Reason,
		"floorVersion": in.FloorVersion,
	}
	return json.Marshal(map[string]interface{}{
		"intent":          in.Intent,
		"decision":        decision,
		"receipt":         in.Receipt,
		"delegationChain": in.DelegationChain,
		"epistemicClaims": map[string]interface{}{
			"policy_evaluated":    in.EpistemicClaims.PolicyEvaluated,
			"authority_consumed":  in.EpistemicClaims.AuthorityConsumed,
			"scope_within_bounds": in.EpistemicClaims.ScopeWithinBounds,
			"effect_occurred":     in.EpistemicClaims.EffectOccurred,
		},
		"policyId":    in.PolicyID,
		"signerKeyId": in.SignerKeyID,
		"issuerId":    in.IssuerID,
		"apsVersion":  in.APSVersion,
	})
}

// runTSOracle executes the tsx harness for one vector. It returns the live TS
// result, or skips the test if the TS repo or npx is unavailable.
func runTSOracle(t *testing.T, in EmitInput, goEnv DecisionReceiptEnvelope) tsOracleResult {
	t.Helper()
	if _, err := os.Stat(filepath.Join(tsRepo, "src", "decisionReceipt.ts")); err != nil {
		t.Skipf("TS reference repo not present at %s; skipping live oracle (pins still asserted)", tsRepo)
	}
	npx, err := exec.LookPath("npx")
	if err != nil {
		t.Skip("npx not on PATH; skipping live TS oracle (pins still asserted)")
	}

	inputJSON, err := emitInputJSON(in)
	if err != nil {
		t.Fatal(err)
	}

	// tsx -e defaults to a CJS output format that rejects top-level await, so
	// the harness is written to a temp .mjs file (ESM) and run by path instead.
	harnessPath := filepath.Join(t.TempDir(), "oracle.mjs")
	if err := os.WriteFile(harnessPath, []byte(tsHarness), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(npx, "tsx", harnessPath)
	cmd.Dir = tsRepo
	cmd.Env = append(os.Environ(),
		"FIXED_ISO=2026-06-03T12:00:00Z",
		"SEED_STRING="+seedString,
		"TS_REPO="+tsRepo,
		"EMIT_INPUT="+string(inputJSON),
		"GO_PAYLOAD="+goEnv.Payload,
		"GO_SIG="+goEnv.Signatures[0].Sig,
	)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("tsx oracle failed: %v\nstderr:\n%s", err, ee.Stderr)
		}
		t.Fatalf("tsx oracle failed: %v", err)
	}
	var res tsOracleResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("decoding tsx output failed: %v\nraw:\n%s", err, out)
	}
	return res
}

// TestEmitDecisionReceiptCrossImpl is the round-trip oracle. For each vector it
// builds the Go envelope, runs the live TS SDK on identical inputs, and asserts:
//   - Go canonical payload bytes == TS canonical payload bytes
//   - Go signature hex == TS signature hex
//   - Go delegation-chain root == TS root
//   - TS-created envelope verifies under Go VerifyEnvelope (TS -> Go)
//   - Go-created payload+signature verifies under TS verify() (Go -> TS)
//
// It also reconfirms the pinned constants drift-free. Skips cleanly when the TS
// repo or npx is not available; the pin test still runs in that case.
func TestEmitDecisionReceiptCrossImpl(t *testing.T) {
	seed := deriveSeed()
	pub, err := keys.PublicKeyFromPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   EmitInput
		pin  string // pinned payload sha256, for drift detection
	}{
		{"vector1_actionref_present", buildVector1(pub), wantPayloadSHA256V1},
		{"vector2_actionref_null", buildVector2(pub), wantPayloadSHA256V2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			goEnv, err := EmitDecisionReceipt(c.in)
			if err != nil {
				t.Fatal(err)
			}
			ts := runTSOracle(t, c.in, goEnv)

			// (c) byte/hex identity Go == TS.
			if goEnv.Payload != ts.Payload {
				t.Errorf("payload bytes differ\n Go: %s\n TS: %s", goEnv.Payload, ts.Payload)
			}
			if got := payloadSHA256(goEnv); got != ts.PayloadSHA256 {
				t.Errorf("payload sha256 Go=%s TS=%s", got, ts.PayloadSHA256)
			}
			if goEnv.Signatures[0].Sig != ts.Signature {
				t.Errorf("signature differs\n Go: %s\n TS: %s", goEnv.Signatures[0].Sig, ts.Signature)
			}
			goRoot, err := ComputeDelegationChainRoot(c.in.DelegationChain)
			if err != nil {
				t.Fatal(err)
			}
			if goRoot != ts.ChainRoot {
				t.Errorf("chain root Go=%s TS=%s", goRoot, ts.ChainRoot)
			}

			// Drift guard: the live TS value must still equal the pinned hex.
			if ts.PayloadSHA256 != c.pin {
				t.Errorf("PIN DRIFT: live TS payload sha256 %s != pinned %s", ts.PayloadSHA256, c.pin)
			}

			// (d) cross-verification both ways.
			// TS -> Go: rebuild an envelope from the TS payload + signature and
			// verify it under the Go verifier.
			tsEnv := DecisionReceiptEnvelope{
				PayloadType: IntotoPayloadType,
				Payload:     ts.Payload,
				Signatures:  []DSSESignature{{KeyID: c.in.SignerKeyID, Sig: ts.Signature}},
				Digest:      Digest{SHA256: ts.PayloadSHA256},
			}
			if !VerifyEnvelope(tsEnv, ts.Pub, 0) {
				t.Error("TS-created envelope did not verify under Go VerifyEnvelope (TS -> Go)")
			}
			// Go -> TS: the harness verified the Go payload+sig under TS verify().
			if !ts.TSVerifiesGo {
				t.Error("Go-created payload+signature did not verify under TS verify() (Go -> TS)")
			}
		})
	}
}

// TestParseRoundTrip confirms ParseDecisionReceiptStatement is the JCS inverse
// of the payload: re-canonicalizing the parsed statement reproduces the payload
// byte-for-byte, mirroring the SDK round-trip property.
func TestParseRoundTrip(t *testing.T) {
	seed := deriveSeed()
	pub, err := keys.PublicKeyFromPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EmitDecisionReceipt(buildVector1(pub))
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := ParseDecisionReceiptStatement(env)
	if err != nil {
		t.Fatal(err)
	}
	recanon, err := jcs.Canonicalize(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if recanon != env.Payload {
		t.Errorf("round-trip mismatch\n re: %s\n in: %s", recanon, env.Payload)
	}
	// Spot-check parsed structure.
	if stmt["_type"] != IntotoStatementV1 {
		t.Errorf("_type = %v, want %s", stmt["_type"], IntotoStatementV1)
	}
	if stmt["predicateType"] != DecisionReceiptPredicateType {
		t.Errorf("predicateType = %v, want %s", stmt["predicateType"], DecisionReceiptPredicateType)
	}
	pred, ok := stmt["predicate"].(map[string]interface{})
	if !ok {
		t.Fatal("predicate not an object")
	}
	if pred["decision"] != "permit" {
		t.Errorf("predicate.decision = %v, want permit", pred["decision"])
	}
}

// TestVerifyEnvelopeRejectsTamper confirms the verifier rejects a flipped
// payload byte and a wrong public key, and that it does not blindly trust the
// supplied payload string (a mutated payload that no longer canonicalizes to
// itself is rejected before the signature is even checked).
func TestVerifyEnvelopeRejectsTamper(t *testing.T) {
	seed := deriveSeed()
	pub, err := keys.PublicKeyFromPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EmitDecisionReceipt(buildVector1(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEnvelope(env, pub, 0) {
		t.Fatal("baseline envelope should verify")
	}

	// Wrong key.
	other, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyEnvelope(env, other.PublicKey, 0) {
		t.Error("verify should fail under a different public key")
	}

	// Flipped reason: payload no longer matches the signature, and the
	// non-canonical insertion would also be caught by the recanonicalization
	// gate. Either way verify must fail.
	tampered := env
	tampered.Payload = `{"x":1}` + env.Payload
	if VerifyEnvelope(tampered, pub, 0) {
		t.Error("verify should fail on a tampered payload")
	}

	// Out-of-range signature index.
	if VerifyEnvelope(env, pub, 5) {
		t.Error("verify should fail for an out-of-range signature index")
	}
}

// TestConstants pins the protocol identifier constants to their wire values, so
// a rename can never silently change the predicate / statement / payload types.
func TestConstants(t *testing.T) {
	if DecisionReceiptPredicateType != "https://veritasacta.com/attestation/decision-receipt/v0.1" {
		t.Errorf("DecisionReceiptPredicateType drifted: %s", DecisionReceiptPredicateType)
	}
	if IntotoStatementV1 != "https://in-toto.io/Statement/v1" {
		t.Errorf("IntotoStatementV1 drifted: %s", IntotoStatementV1)
	}
	if IntotoPayloadType != "application/vnd.in-toto+json" {
		t.Errorf("IntotoPayloadType drifted: %s", IntotoPayloadType)
	}
	if DefaultAPSVersion != "2.3.0-alpha" {
		t.Errorf("DefaultAPSVersion drifted: %s", DefaultAPSVersion)
	}
}

// TestComputeDelegationChainRootEmpty confirms the root of an empty chain
// equals SHA-256(JCS([])), the deterministic baseline.
func TestComputeDelegationChainRootEmpty(t *testing.T) {
	root, err := ComputeDelegationChainRoot([]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Canonicalize([]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canon))
	if want := hex.EncodeToString(sum[:]); root != want {
		t.Errorf("empty chain root = %s, want %s", root, want)
	}
}

// TestEmitValidation confirms the create primitive rejects malformed inputs
// without ever touching key material.
func TestEmitValidation(t *testing.T) {
	seed := deriveSeed()
	base := buildVector1("pub")

	noKeyID := base
	noKeyID.SignerKeyID = ""
	if _, err := EmitDecisionReceipt(noKeyID); err == nil {
		t.Error("expected error for empty signerKeyId")
	}

	nilIntent := base
	nilIntent.Intent = nil
	nilIntent.SignerKeyID = "k"
	if _, err := EmitDecisionReceipt(nilIntent); err == nil {
		t.Error("expected error for nil intent")
	}

	badIntent := base
	badIntent.Intent = map[string]interface{}{"intentId": "x"} // no action.type
	badIntent.SignerKeyID = "k"
	if _, err := EmitDecisionReceipt(badIntent); err == nil {
		t.Error("expected error for intent missing action.type")
	}

	// A well-formed call still works with the real seed (sanity).
	pub, _ := keys.PublicKeyFromPrivate(seed)
	ok := buildVector1(pub)
	if _, err := EmitDecisionReceipt(ok); err != nil {
		t.Errorf("well-formed emit failed: %v", err)
	}
}
