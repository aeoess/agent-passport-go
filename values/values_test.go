// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package values

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// Deterministic keys, derived the SAME way in Go and TS: the private seed is
// sha256("aps-go-values-key") for the attesting agent and
// sha256("aps-go-values-verifier") for the report verifier. No randomness, no
// wall clock. The public keys below are the hex public keys those seeds derive
// to (confirmed against the TS reference at build time via npx tsx).
const (
	attestSeedSource   = "aps-go-values-key"
	verifierSeedSource = "aps-go-values-verifier"

	// Public key derived from sha256("aps-go-values-key").
	attestPubHex = "2b9db5cc0768586676d96ec660a5f29102d47b5ccc6de34bdb3fa795282de556"
	// Public key derived from sha256("aps-go-values-verifier").
	verifierPubHex = "6d75dae090d15b1c2c9e1d1caf112445ec76142f579ab43aba24f70914ad8933"
)

// seedHex returns the 32-byte Ed25519 seed hex for a source string, derived
// identically to the TS probe: hex(sha256(source)).
func seedHex(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────────
// ATTESTATION CROSS-IMPL ORACLE
//
// The constants below were produced by the REAL TS reference at build time:
//
//   import { canonicalize } from 'src/core/canonical.ts'
//   import { sign }         from 'src/crypto/keys.ts'
//   const attestation = {
//     attestationId:'att_000000000001', agentId:'ag_values_001',
//     publicKey:<derived>, floorVersion:'2.0',
//     extensions:['ext-b','ext-a'],
//     attestedAt:'2026-06-03T12:00:00.000Z',
//     expiresAt:'2027-06-03T12:00:00.000Z',
//     commitment:`floor:2.0|ext:ext-a,ext-b|ts:2026-06-03T12:00:00.000Z` }
//   sign(canonicalize(attestation), <seed sha256("aps-go-values-key")>)
//
// The TS probe also confirmed canonicalize(attestation) === canonicalizeJCS(
// attestation), so the Phase-0 jcs.Canonicalize produces the same preimage.
// ─────────────────────────────────────────────────────────────────────────

const (
	// sha256 of the TS legacy-canonical bytes of the unsigned attestation.
	wantAttestCanonSHA256 = "38f6377ad21c048bb2e013f6ce9bf19c1bcbb4dd04ee02682b1e1abde4e6a8ad"
	// Ed25519 signature the TS reference produced over those bytes.
	wantAttestSig = "9b30b334636586d6f4c46afa90fabb926af96de657d09d43a723024e933663ccb8d201325904dad9705afb569edb6155235d94e5c256dda31cc64c332649f007"
)

func buildTestAttestation(t *testing.T) FloorAttestation {
	t.Helper()
	att, err := AttestFloor(
		"att_000000000001",
		"ag_values_001",
		attestPubHex,
		"2.0",
		[]string{"ext-b", "ext-a"},
		"2026-06-03T12:00:00.000Z",
		"2027-06-03T12:00:00.000Z",
		seedHex(attestSeedSource),
	)
	if err != nil {
		t.Fatalf("AttestFloor: %v", err)
	}
	return att
}

func TestAttestFloor_CrossImpl(t *testing.T) {
	// Sanity: our derived public key matches the TS-derived one.
	gotPub, err := keys.PublicKeyFromPrivate(seedHex(attestSeedSource))
	if err != nil {
		t.Fatal(err)
	}
	if gotPub != attestPubHex {
		t.Fatalf("derived pub %s != pinned %s", gotPub, attestPubHex)
	}

	att := buildTestAttestation(t)

	// (c) canonical bytes match: hash the same preimage TS hashed.
	canonMap := attestationToMap(att)
	delete(canonMap, "signature")
	canon, err := jcs.Canonicalize(canonMap)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canon))
	gotCanonSHA := hex.EncodeToString(sum[:])
	if gotCanonSHA != wantAttestCanonSHA256 {
		t.Errorf("attestation canonical sha256:\n got  %s\n want %s (TS reference)\n canon=%s", gotCanonSHA, wantAttestCanonSHA256, canon)
	}

	// (c) signature hex matches the TS reference byte for byte.
	if att.Signature != wantAttestSig {
		t.Errorf("attestation signature:\n got  %s\n want %s (TS reference)", att.Signature, wantAttestSig)
	}

	// The commitment must sort a COPY of extensions but the artifact keeps order.
	if att.Commitment != "floor:2.0|ext:ext-a,ext-b|ts:2026-06-03T12:00:00.000Z" {
		t.Errorf("commitment mismatch: %s", att.Commitment)
	}
	if att.Extensions[0] != "ext-b" || att.Extensions[1] != "ext-a" {
		t.Errorf("extensions order should be preserved, got %v", att.Extensions)
	}
}

func TestVerifyAttestation_GoVerifiesTS(t *testing.T) {
	// (d) A TS-created artifact (its signature is the pinned TS hex) verifies
	// under the Go verify path. We reconstruct the artifact and plant the TS
	// signature, then verify.
	att := buildTestAttestation(t)
	att.Signature = wantAttestSig // the TS-produced signature
	valid, errs := VerifyAttestation(att, "2026-06-03T12:00:00.000Z")
	if !valid {
		t.Errorf("Go VerifyAttestation rejected TS-signed attestation: %v", errs)
	}
}

func TestVerifyAttestation_Expired(t *testing.T) {
	att := buildTestAttestation(t)
	// now is after expiry.
	valid, errs := VerifyAttestation(att, "2028-01-01T00:00:00.000Z")
	if valid {
		t.Error("expected expired attestation to be invalid")
	}
	found := false
	for _, e := range errs {
		if e == "Attestation expired" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Attestation expired' in %v", errs)
	}
}

func TestVerifyAttestation_TamperedSignature(t *testing.T) {
	att := buildTestAttestation(t)
	att.FloorVersion = "9.9" // mutate a signed field; signature now stale
	valid, errs := VerifyAttestation(att, "2026-06-03T12:00:00.000Z")
	if valid {
		t.Error("expected tampered attestation to fail signature check")
	}
	found := false
	for _, e := range errs {
		if e == "Invalid attestation signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Invalid attestation signature' in %v", errs)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// COMPLIANCE REPORT CROSS-IMPL ORACLE
//
// Produced by the REAL TS reference at build time. The hand-built report
// object below is byte-for-byte the object the real evaluateCompliance(...)
// builds for these inputs (confirmed: REAL_CHECKS / REAL_OVERALL / REAL_PERIOD
// from the TS probe equal the values here). Signed with
// canonicalize(report) under seed sha256("aps-go-values-verifier"); the TS
// probe also confirmed canonicalize(report) === canonicalizeJCS(report).
// ─────────────────────────────────────────────────────────────────────────

const (
	// sha256 of the TS legacy-canonical bytes of the unsigned report.
	wantReportCanonSHA256 = "79153993b84f091ca32db52b7c73596754bafc5f3501f8ff691d82908eae6890"
	// Ed25519 signature the TS reference produced over those bytes.
	wantReportSig = "f2da927176d51fdee2c3d84586c9253c1fc524c9260323c4b859831390e5e74466fe88f6ec423068254cc4b3441b4a0604a2238346b9e1c7693846ab754a6203"
)

func testFloor() ValuesFloor {
	return ValuesFloor{
		Version:       "2.0",
		Schema:        "aps-floor-v2",
		LastUpdated:   "2026-01-01T00:00:00.000Z",
		GovernanceURI: "https://aeoess.org/floor",
		Floor: []FloorPrinciple{
			{ID: "F-001", Name: "Traceability", Principle: "All actions traceable", Enforcement: Enforcement{Mode: ModeInline, Mechanism: "delegation-chain"}, Weight: "mandatory"},
			{ID: "F-002", Name: "Honest Identity", Principle: "Consistent identity", Enforcement: Enforcement{Mode: ModeAudit, Mechanism: "agentId"}, Weight: "mandatory"},
			{ID: "F-005", Name: "Auditability", Principle: "All receipts signed", Enforcement: Enforcement{Mode: ModeInline, Mechanism: "signature"}, Weight: "mandatory"},
			{ID: "F-006", Name: "Non-Deception", Principle: "No deception", Enforcement: Enforcement{Mode: ModeWarn, Mechanism: "reasoning"}, Weight: "strong_consideration"},
		},
	}
}

func testReceipts() []ActionReceipt {
	sig := ""
	for i := 0; i < 64; i++ {
		sig += "aa"
	}
	sig2 := ""
	for i := 0; i < 64; i++ {
		sig2 += "bb"
	}
	return []ActionReceipt{
		{ReceiptID: "rcpt_001", Version: "1.0", Timestamp: "2026-06-03T10:00:00.000Z", AgentID: "ag_values_001", DelegationID: "dlg_001",
			Action: ReceiptAction{Type: "web_search", Target: "example.com", ScopeUsed: "data:read"}, Result: ReceiptResult{Status: "success", Summary: "ok"},
			DelegationChain: []string{"fp_root", "fp_leaf"}, Signature: sig},
		{ReceiptID: "rcpt_002", Version: "1.0", Timestamp: "2026-06-03T11:00:00.000Z", AgentID: "ag_values_001", DelegationID: "dlg_001",
			Action: ReceiptAction{Type: "code_execution", Target: "sandbox", ScopeUsed: "compute:exec"}, Result: ReceiptResult{Status: "success", Summary: "done"},
			DelegationChain: []string{"fp_root", "fp_leaf"}, Signature: sig2},
	}
}

func buildTestReport(t *testing.T) ComplianceReport {
	t.Helper()
	delegations := map[string]DelegationState{
		"dlg_001": {Scope: []string{"data:read", "compute:exec"}, Revoked: false},
	}
	report, err := EvaluateCompliance(
		"ag_values_001",
		"comp_000000000001",
		"2026-06-03T12:00:00.000Z",
		"", "",
		testReceipts(),
		testFloor(),
		delegations,
		seedHex(verifierSeedSource),
	)
	if err != nil {
		t.Fatalf("EvaluateCompliance: %v", err)
	}
	return report
}

func TestEvaluateCompliance_CrossImpl(t *testing.T) {
	gotPub, err := keys.PublicKeyFromPrivate(seedHex(verifierSeedSource))
	if err != nil {
		t.Fatal(err)
	}
	if gotPub != verifierPubHex {
		t.Fatalf("derived verifier pub %s != pinned %s", gotPub, verifierPubHex)
	}

	report := buildTestReport(t)

	// Structural facts mirror the TS evaluateCompliance output.
	if report.OverallCompliance != 0.95 {
		t.Errorf("overallCompliance = %v, want 0.95", report.OverallCompliance)
	}
	if report.Period.From != "2026-06-03T10:00:00.000Z" || report.Period.To != "2026-06-03T11:00:00.000Z" {
		t.Errorf("period = %+v, want [10:00, 11:00]", report.Period)
	}
	if report.Checks[0].Evidence != "rcpt_001" {
		t.Errorf("F-001 evidence = %q, want rcpt_001", report.Checks[0].Evidence)
	}
	if report.Checks[3].Status != "attested" {
		t.Errorf("F-006 status = %q, want attested", report.Checks[3].Status)
	}

	// (c) canonical bytes match.
	canonMap := reportToMap(report)
	delete(canonMap, "signature")
	canon, err := jcs.Canonicalize(canonMap)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canon))
	gotCanonSHA := hex.EncodeToString(sum[:])
	if gotCanonSHA != wantReportCanonSHA256 {
		t.Errorf("report canonical sha256:\n got  %s\n want %s (TS reference)\n canon=%s", gotCanonSHA, wantReportCanonSHA256, canon)
	}

	// (c) signature hex matches.
	if report.Signature != wantReportSig {
		t.Errorf("report signature:\n got  %s\n want %s (TS reference)", report.Signature, wantReportSig)
	}
}

func TestVerifyComplianceReport_GoVerifiesTS(t *testing.T) {
	// (d) TS-created signature verifies under Go.
	report := buildTestReport(t)
	report.Signature = wantReportSig
	if !VerifyComplianceReport(report, verifierPubHex) {
		t.Error("Go VerifyComplianceReport rejected TS-signed report")
	}
	// And the freshly Go-signed report also verifies (Go-created verified by Go).
	fresh := buildTestReport(t)
	if !VerifyComplianceReport(fresh, verifierPubHex) {
		t.Error("Go VerifyComplianceReport rejected Go-signed report")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// PURE COMPUTE
// ─────────────────────────────────────────────────────────────────────────

func TestResolveEnforcementMode(t *testing.T) {
	tTrue := true
	tFalse := false
	cases := []struct {
		name string
		in   Enforcement
		want EnforcementMode
	}{
		{"explicit mode wins", Enforcement{Mode: ModeWarn, Technical: &tTrue}, ModeWarn},
		{"technical true -> inline", Enforcement{Technical: &tTrue}, ModeInline},
		{"technical false -> audit", Enforcement{Technical: &tFalse}, ModeAudit},
		{"nothing -> audit", Enforcement{}, ModeAudit},
	}
	for _, c := range cases {
		if got := ResolveEnforcementMode(c.in); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestEffectiveEnforcementMode(t *testing.T) {
	cases := []struct {
		floor EnforcementMode
		exts  []EnforcementMode
		want  EnforcementMode
	}{
		{ModeAudit, []EnforcementMode{ModeInline}, ModeInline},                     // extension escalates
		{ModeInline, []EnforcementMode{ModeAudit}, ModeInline},                     // floor cannot be weakened
		{ModeWarn, []EnforcementMode{ModeAudit}, ModeAudit},                        // warn -> audit
		{ModeWarn, []EnforcementMode{}, ModeWarn},                                  // no extensions
		{ModeWarn, []EnforcementMode{ModeWarn, ModeInline, ModeAudit}, ModeInline}, // strictest wins
	}
	for _, c := range cases {
		if got := EffectiveEnforcementMode(c.floor, c.exts...); got != c.want {
			t.Errorf("EffectiveEnforcementMode(%s, %v) = %s, want %s", c.floor, c.exts, got, c.want)
		}
	}
}

func TestLoadFloor(t *testing.T) {
	input := `{"version":"2.0","schema":"aps-floor-v2","lastUpdated":"2026-01-01T00:00:00.000Z","governanceUri":"https://aeoess.org/floor","floor":[{"id":"F-001","name":"Traceability","principle":"trace","enforcement":{"mechanism":"chain","technical":true},"weight":"mandatory"},{"id":"F-002","name":"Honest","principle":"id","enforcement":{"mode":"audit","mechanism":"id"},"weight":"mandatory"}]}`
	floor, err := LoadFloor(input)
	if err != nil {
		t.Fatal(err)
	}
	if floor.Version != "2.0" || len(floor.Floor) != 2 {
		t.Fatalf("unexpected floor: %+v", floor)
	}
	// F-001 had no mode but technical:true -> resolved to inline.
	if floor.Floor[0].Enforcement.Mode != ModeInline {
		t.Errorf("F-001 mode = %s, want inline (technical:true)", floor.Floor[0].Enforcement.Mode)
	}
	if floor.Floor[1].Enforcement.Mode != ModeAudit {
		t.Errorf("F-002 mode = %s, want audit", floor.Floor[1].Enforcement.Mode)
	}
	if _, err := LoadFloor(`{"version":"2.0"}`); err == nil {
		t.Error("expected error for floor without a floor array")
	}
}

func TestNegotiateCommonGround(t *testing.T) {
	now := "2026-06-03T12:00:00.000Z"
	aa := FloorAttestation{AgentID: "ag_A", FloorVersion: "2.0", Extensions: []string{"ext-x", "ext-y"}, ExpiresAt: "2099-01-01T00:00:00.000Z"}
	ab := FloorAttestation{AgentID: "ag_B", FloorVersion: "2.5", Extensions: []string{"ext-y", "ext-z"}, ExpiresAt: "2099-01-01T00:00:00.000Z"}

	r := NegotiateCommonGround("pub_A", aa, "pub_B", ab, now)
	if !r.Compatible {
		t.Error("expected compatible (same major version 2)")
	}
	if r.FloorVersion == nil || *r.FloorVersion != "2.0" {
		t.Errorf("floorVersion = %v, want 2.0", r.FloorVersion)
	}
	if len(r.SharedExtensions) != 1 || r.SharedExtensions[0] != "ext-y" {
		t.Errorf("sharedExtensions = %v, want [ext-y]", r.SharedExtensions)
	}
	if r.AgentA != "pub_A" || r.AgentB != "pub_B" {
		t.Errorf("agent keys = %s/%s", r.AgentA, r.AgentB)
	}
	if len(r.IncompatibilityReasons) != 0 {
		t.Errorf("expected no reasons, got %v", r.IncompatibilityReasons)
	}

	// Incompatible major version.
	ab2 := ab
	ab2.FloorVersion = "3.0"
	r2 := NegotiateCommonGround("pub_A", aa, "pub_B", ab2, now)
	if r2.Compatible {
		t.Error("expected incompatible (major 2 vs 3)")
	}
	if r2.FloorVersion != nil {
		t.Errorf("floorVersion should be nil when incompatible, got %v", *r2.FloorVersion)
	}
	if len(r2.IncompatibilityReasons) != 1 {
		t.Errorf("expected 1 reason, got %v", r2.IncompatibilityReasons)
	}
	// Extensions intersection still computed even when incompatible.
	if len(r2.SharedExtensions) != 1 || r2.SharedExtensions[0] != "ext-y" {
		t.Errorf("sharedExtensions = %v, want [ext-y]", r2.SharedExtensions)
	}
}

// Guard that scopeAuthorizes reuses the Phase-0 ScopeCovers semantics (wildcard
// and prefix). This underpins the F-003 compliance check.
func TestScopeAuthorizesReusesCore(t *testing.T) {
	if !scopeAuthorizes([]string{"data:*"}, "data:read") {
		t.Error("data:* should authorize data:read")
	}
	if scopeAuthorizes([]string{"data:read"}, "compute:exec") {
		t.Error("data:read must not authorize compute:exec")
	}
	if !verify.ScopeCovers("*", "anything:goes") {
		t.Error("sanity: core ScopeCovers wildcard")
	}
}
