// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package attribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

// Deterministic inputs shared by Go and the TS reference. No randomness, no
// wall-clock: the private key is sha256("aps-go-attribution-key"), timestamps
// and IDs are fixed strings.
const keySeed = "aps-go-attribution-key"

// tsRepo is the reference TypeScript SDK checkout, resolved from APS_TS_REPO.
// The cross-impl oracle tests interpolate it into their tsx import paths. When
// APS_TS_REPO is unset they skip (see skipUnlessTSRepo); the pinned constants
// still guard the cross-impl invariant.
var tsRepo = os.Getenv("APS_TS_REPO")

// skipUnlessTSRepo skips the calling cross-impl test when APS_TS_REPO is unset
// or empty, with the canonical message, before any use of the repo path or tsx.
func skipUnlessTSRepo(t *testing.T) {
	t.Helper()
	if tsRepo == "" {
		t.Skip("set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	}
}

// deriveSeed reproduces sha256("aps-go-attribution-key") as lowercase hex, the
// same derivation the TS cross-check uses, so both sides sign with one key.
func deriveSeed() string {
	sum := sha256.Sum256([]byte(keySeed))
	return hex.EncodeToString(sum[:])
}

// fixtureReceipt is the deterministic ActionReceipt used across hash and trace
// tests. It carries no null fields, so the legacy canonicalize() and RFC 8785
// jcs.Canonicalize agree byte for byte.
func fixtureReceipt() ActionReceipt {
	return ActionReceipt{
		ReceiptID:    "rcpt_001",
		Version:      "1.0.0",
		Timestamp:    "2026-06-03T12:00:00Z",
		AgentID:      "ag_exec",
		DelegationID: "del_001",
		Action: ReceiptAction{
			Type:      "code_execution",
			Target:    "repo/x",
			ScopeUsed: "compute:exec",
		},
		Result: ReceiptResult{
			Status:  "success",
			Summary: "done",
		},
		DelegationChain: []string{"pk_principal", "pk_agent"},
		Signature:       "sig_placeholder",
	}
}

func fixtureEntries() []AttributionEntry {
	return []AttributionEntry{
		{ReceiptID: "rcpt_001", AgentID: "ag_exec", Action: "code_execution", ScopeUsed: "compute:exec", Spend: 0, ResultStatus: "success", Weight: 0.6, Timestamp: "2026-06-03T12:00:00Z"},
		{ReceiptID: "rcpt_002", AgentID: "ag_exec", Action: "web_search", ScopeUsed: "data:read", Spend: 1.25, ResultStatus: "success", Weight: 0.4, Timestamp: "2026-06-03T12:05:00Z"},
	}
}

// fixtureReport builds the deterministic AttributionReport (without signature)
// used by the signing and verification cross-impl tests.
func fixtureReport(t *testing.T) AttributionReport {
	t.Helper()
	entries := fixtureEntries()
	eh, err := entriesHash(entries)
	if err != nil {
		t.Fatalf("entriesHash: %v", err)
	}
	return AttributionReport{
		ReportID:     "report_001",
		Beneficiary:  "human_alice",
		AgentID:      "ag_exec",
		Period:       AttributionPeriod{From: "2026-06-01T00:00:00Z", To: "2026-06-30T23:59:59Z"},
		Entries:      entries,
		TotalWeight:  1.0,
		ReceiptCount: 2,
		MerkleRoot:   BuildMerkleRoot([]string{"rh1", "rh2"}),
		EntriesHash:  eh,
		GeneratedAt:  "2026-06-03T12:10:00Z",
	}
}

func entriesHash(entries []AttributionEntry) (string, error) {
	canon, err := canonicalizeGeneric(entries)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

// runTSX executes a tsx snippet against the reference repo and returns trimmed
// stdout. It is the build-time oracle: the live TS SDK computes the same
// primitive on the same deterministic inputs. Skips (not fails) when the TS
// toolchain is unavailable, so the pure-Go cross-pins still gate.
func runTSX(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("npx", "tsx", "-e", script)
	cmd.Dir = tsRepo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("tsx oracle unavailable (%v): %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

// ── HashReceipt ────────────────────────────────────────────────────────────

// TestHashReceiptCrossImpl pins the value produced by the TS reference
// hashReceipt (src/core/attribution.ts) at build time for fixtureReceipt, and
// re-derives it live from the TS SDK to guard against drift.
func TestHashReceiptCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	// Produced by the TS reference hashReceipt() at build time for fixtureReceipt.
	const tsHash = "1c2dadd5fab4b8eae7cb88caad5995f0224bd0a79dcaae8258f328d8bb7765b5"

	got, err := HashReceipt(fixtureReceipt())
	if err != nil {
		t.Fatal(err)
	}
	if got != tsHash {
		t.Fatalf("HashReceipt = %s, want %s (TS reference, pinned)", got, tsHash)
	}

	live := runTSX(t, `
import { hashReceipt } from '`+tsRepo+`/src/core/attribution.ts';
const receipt = {
  receiptId: 'rcpt_001', version: '1.0.0', timestamp: '2026-06-03T12:00:00Z',
  agentId: 'ag_exec', delegationId: 'del_001',
  action: { type: 'code_execution', target: 'repo/x', scopeUsed: 'compute:exec' },
  result: { status: 'success', summary: 'done' },
  delegationChain: ['pk_principal','pk_agent'], signature: 'sig_placeholder'
};
process.stdout.write(hashReceipt(receipt));
`)
	if live != got {
		t.Fatalf("live TS hashReceipt = %s, Go = %s (Go != TS)", live, got)
	}
}

// ── Merkle root ────────────────────────────────────────────────────────────

// TestBuildMerkleRootCrossImpl checks the even, odd, single, and empty cases
// against pinned TS values and a live TS recompute. Leaves are passed unsorted
// to exercise the sort-for-determinism step.
func TestBuildMerkleRootCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	cases := []struct {
		name   string
		leaves []string
		want   string // produced by TS reference buildMerkleRoot at build time
	}{
		// Pinned values regenerated 2026-07-11 (Day-145 audit, receipt format
		// v1.1 -> v1.2) from the domain-separated TS reference (leaf tag 0x00,
		// node tag 0x01, odd node promoted unchanged). A single leaf now
		// hashes under the leaf tag instead of passing through.
		{"even5", []string{"ee", "aa", "cc", "bb", "dd"}, "a7e88df9557e8d7b30bf37ac4ce18684f032a78249ab3c9d9b39555cc8d63620"},
		{"odd3", []string{"z1", "z2", "z3"}, "2e929d3177b7f07074571158a9060ab10f7b0031b0927c121b724773c2ba3674"},
		{"empty", []string{}, "2e1cfa82b035c26cbbbdae632cea070514eb8b773f616aaeaf668e2f0be8f10d"},
		{"single", []string{"solo"}, "9e1aa6e57d3133fa3a54ae7e99acb0fea339327259f24f1317e9099e94d965c3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildMerkleRoot(c.leaves)
			if got != c.want {
				t.Fatalf("BuildMerkleRoot(%v) = %s, want %s (TS pinned)", c.leaves, got, c.want)
			}
		})
	}

	live := runTSX(t, `
import { buildMerkleRoot } from '`+tsRepo+`/src/core/attribution.ts';
const r = {
  even5: buildMerkleRoot(['ee','aa','cc','bb','dd']),
  odd3: buildMerkleRoot(['z1','z2','z3']),
  empty: buildMerkleRoot([]),
  single: buildMerkleRoot(['solo'])
};
process.stdout.write(JSON.stringify(r));
`)
	var got map[string]string
	if err := json.Unmarshal([]byte(live), &got); err != nil {
		t.Fatalf("decode tsx output %q: %v", live, err)
	}
	if got["even5"] != BuildMerkleRoot([]string{"ee", "aa", "cc", "bb", "dd"}) {
		t.Fatalf("even5: live TS = %s, Go differs (Go != TS)", got["even5"])
	}
	if got["odd3"] != BuildMerkleRoot([]string{"z1", "z2", "z3"}) {
		t.Fatalf("odd3: live TS = %s, Go differs (Go != TS)", got["odd3"])
	}
	if got["empty"] != BuildMerkleRoot([]string{}) {
		t.Fatalf("empty: live TS = %s, Go differs (Go != TS)", got["empty"])
	}
}

// ── Merkle proof generate + verify ─────────────────────────────────────────

// TestMerkleProofCrossImpl pins a full TS-generated proof (even and odd cases),
// asserts Go regenerates an identical proof, and that VerifyMerkleProof accepts
// the TS-generated proof (cross-verification) and the Go-generated proof.
func TestMerkleProofCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	even := []string{"ee", "aa", "cc", "bb", "dd"}
	odd := []string{"z1", "z2", "z3"}

	// Pinned full proof JSON produced by TS generateMerkleProof at build time.
	// Regenerated 2026-07-11 (Day-145 audit, receipt format v1.1 -> v1.2) from
	// the domain-separated TS reference. The odd proof now carries a single
	// node: the lone odd leaf is promoted unchanged and contributes no
	// self-duplicate proof entry.
	const tsEvenProof = `{"receiptHash":"cc","root":"a7e88df9557e8d7b30bf37ac4ce18684f032a78249ab3c9d9b39555cc8d63620","proof":[{"hash":"f68f271d79f737d2e97b8f327a3e554f42452c27c39028c3de569a55e20a5ef6","position":"right"},{"hash":"41cccca33c4ab9beac49f38f89ce9927a2839825da89e01c6fdb19c83bfabe3e","position":"left"},{"hash":"2463b6d83b3f4b640b7d2e4b995d726657ce4a8b235576e6ecdcda9eae1d8c0b","position":"right"}],"index":2}`
	const tsOddProof = `{"receiptHash":"z3","root":"2e929d3177b7f07074571158a9060ab10f7b0031b0927c121b724773c2ba3674","proof":[{"hash":"577e9da927d8dc7f8536d2da141f922c92212084b4bce10ee78cee05ad4be8ce","position":"left"}],"index":2}`

	// Go proof must serialize byte-identically to the TS proof JSON.
	goEven := GenerateMerkleProof(even, "cc")
	if goEven == nil {
		t.Fatal("GenerateMerkleProof even returned nil")
	}
	goEvenJSON := mustJSON(t, goEven)
	if goEvenJSON != tsEvenProof {
		t.Fatalf("even proof Go != TS\n Go: %s\n TS: %s", goEvenJSON, tsEvenProof)
	}

	goOdd := GenerateMerkleProof(odd, "z3")
	if goOdd == nil {
		t.Fatal("GenerateMerkleProof odd returned nil")
	}
	goOddJSON := mustJSON(t, goOdd)
	if goOddJSON != tsOddProof {
		t.Fatalf("odd proof Go != TS\n Go: %s\n TS: %s", goOddJSON, tsOddProof)
	}

	// Go verifies its own proof.
	if !VerifyMerkleProof(*goEven) {
		t.Fatal("Go failed to verify its own even proof")
	}
	if !VerifyMerkleProof(*goOdd) {
		t.Fatal("Go failed to verify its own odd proof")
	}

	// Cross-verification: a TS-generated proof verifies under Go VerifyMerkleProof.
	var tsProof MerkleProof
	if err := json.Unmarshal([]byte(tsEvenProof), &tsProof); err != nil {
		t.Fatal(err)
	}
	if !VerifyMerkleProof(tsProof) {
		t.Fatal("Go failed to verify TS-generated proof (Go != TS)")
	}

	// Negative: a missing target yields nil, matching the reference.
	if GenerateMerkleProof(even, "not-present") != nil {
		t.Fatal("expected nil proof for absent target")
	}
	if GenerateMerkleProof([]string{}, "cc") != nil {
		t.Fatal("expected nil proof for empty leaves")
	}

	// Live oracle: the TS SDK regenerates the same proofs and verifies the Go
	// proof (Go-created artifact verifies under TS verify).
	live := runTSX(t, `
import { generateMerkleProof, verifyMerkleProof } from '`+tsRepo+`/src/core/attribution.ts';
const evenP = generateMerkleProof(['ee','aa','cc','bb','dd'], 'cc');
const oddP = generateMerkleProof(['z1','z2','z3'], 'z3');
const goEven = `+"`"+goEvenJSON+"`"+`;
const out = {
  even: JSON.stringify(evenP),
  odd: JSON.stringify(oddP),
  verifyGoEven: verifyMerkleProof(JSON.parse(goEven))
};
process.stdout.write(JSON.stringify(out));
`)
	var lr struct {
		Even         string `json:"even"`
		Odd          string `json:"odd"`
		VerifyGoEven bool   `json:"verifyGoEven"`
	}
	if err := json.Unmarshal([]byte(live), &lr); err != nil {
		t.Fatalf("decode tsx output %q: %v", live, err)
	}
	if lr.Even != goEvenJSON {
		t.Fatalf("live TS even proof != Go\n TS: %s\n Go: %s", lr.Even, goEvenJSON)
	}
	if lr.Odd != goOddJSON {
		t.Fatalf("live TS odd proof != Go\n TS: %s\n Go: %s", lr.Odd, goOddJSON)
	}
	if !lr.VerifyGoEven {
		t.Fatal("TS verifyMerkleProof rejected Go-generated proof (Go != TS)")
	}
}

// ── TraceBeneficiary ───────────────────────────────────────────────────────

// signedTraceFixture builds a real signed receipt + a real signed delegation
// chain from two deterministic seeds, so both `resolved` and `verified` are
// true under the honest split semantics (lookup AND real ed25519). It mirrors
// the exact literals the TS oracle signs in TestTraceBeneficiaryCrossImpl, so
// Ed25519's determinism yields byte-identical signatures across the two impls.
//
// The delegation literal deliberately OMITS spentAmount (unlike TS
// createDelegation, which bakes in spentAmount:0), because the canonical
// delegation preimage shared with delegation.CreateDelegation / VerifyDelegation
// carries no spentAmount field. Both sides sign the same field set, so the
// cross-impl signature is identical.
func signedTraceFixture(t *testing.T) (receipt ActionReceipt, delegations []TraceDelegation, bmap map[string]BeneficiaryInfo, principalPub, agentPub string) {
	t.Helper()
	principalSeed := seedFromLabel("aps-go-trace-principal")
	agentSeed := seedFromLabel("aps-go-trace-agent")
	var err error
	principalPub, err = keys.PublicKeyFromPrivate(principalSeed)
	if err != nil {
		t.Fatalf("principal pub: %v", err)
	}
	agentPub, err = keys.PublicKeyFromPrivate(agentSeed)
	if err != nil {
		t.Fatalf("agent pub: %v", err)
	}

	del := signTraceDelegation(t, principalSeed, "del_pa", principalPub, agentPub, []string{"compute:exec"})
	delegations = []TraceDelegation{del}

	receipt = ActionReceipt{
		ReceiptID:    "rcpt_001",
		Version:      "1.1",
		Timestamp:    "2026-06-03T12:00:00Z",
		AgentID:      "ag_exec",
		DelegationID: "del_pa",
		Action: ReceiptAction{
			Type:      "code_execution",
			Target:    "repo/x",
			ScopeUsed: "compute:exec",
		},
		Result:          ReceiptResult{Status: "success", Summary: "done"},
		DelegationChain: []string{principalPub, agentPub},
	}
	receipt.Signature = signReceipt(t, receipt, agentSeed)

	bmap = map[string]BeneficiaryInfo{
		principalPub: {PrincipalID: "human_alice", Relationship: "owner", RegisteredAt: "2026-01-01T00:00:00Z"},
	}
	return receipt, delegations, bmap, principalPub, agentPub
}

// TestTraceBeneficiaryCrossImpl compares the Go trace (minus the random traceId,
// which the reference mints from a uuid) against the live TS trace minus its
// traceId, on identical deterministic inputs. The fixture is a REAL signed
// receipt + delegation chain so both resolved and verified are true. This test
// goes RED against the old lookup-only Verified (no Resolved field, verified
// asserted from a placeholder signature) and GREEN once Verified does real
// ed25519 crypto and Resolved is reported.
func TestTraceBeneficiaryCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	receipt, delegations, bmap, principalPub, agentPub := signedTraceFixture(t)

	got := TraceBeneficiary("trace_fixed", receipt, delegations, bmap)
	if got.Beneficiary != "human_alice" || !got.Resolved || !got.Verified || got.TotalDepth != 1 {
		t.Fatalf("unexpected trace: %+v", got)
	}

	// Compare the deterministic part (everything except traceId) byte for byte.
	goRest := traceRestJSON(t, got)

	live := runTSX(t, `
import { createHash } from 'node:crypto';
import { sign, publicKeyFromPrivate } from '`+tsRepo+`/src/crypto/keys.ts';
import { canonicalize } from '`+tsRepo+`/src/core/canonical.ts';
import { traceBeneficiary } from '`+tsRepo+`/src/core/attribution.ts';
const principalSeed = createHash('sha256').update('aps-go-trace-principal').digest('hex');
const agentSeed = createHash('sha256').update('aps-go-trace-agent').digest('hex');
const principalPub = publicKeyFromPrivate(principalSeed);
const agentPub = publicKeyFromPrivate(agentSeed);
const delegationUnsigned = {
  delegationId: 'del_pa', delegatedTo: agentPub, delegatedBy: principalPub,
  scope: ['compute:exec'], expiresAt: '2099-01-01T00:00:00.000Z',
  maxDepth: 1, currentDepth: 0,
  createdAt: '2026-01-01T00:00:00.000Z', notBefore: '2026-01-01T00:00:00.000Z'
};
const delegation = { ...delegationUnsigned, signature: sign(canonicalize(delegationUnsigned), principalSeed) };
const receiptUnsigned = {
  receiptId: 'rcpt_001', version: '1.1', timestamp: '2026-06-03T12:00:00Z',
  agentId: 'ag_exec', delegationId: 'del_pa',
  action: { type: 'code_execution', target: 'repo/x', scopeUsed: 'compute:exec' },
  result: { status: 'success', summary: 'done' },
  delegationChain: [principalPub, agentPub]
};
const receipt = { ...receiptUnsigned, signature: sign(canonicalize(receiptUnsigned), agentSeed) };
const bmap = new Map();
bmap.set(principalPub, { principalId: 'human_alice', relationship: 'owner', registeredAt: '2026-01-01T00:00:00Z' });
const trace = traceBeneficiary(receipt, [delegation], bmap);
const { traceId, ...rest } = trace;
process.stdout.write(JSON.stringify(rest));
`)
	_ = principalPub
	_ = agentPub
	// Re-canonicalize both sides through JSON so key order does not matter.
	if canonJSON(t, live) != canonJSON(t, goRest) {
		t.Fatalf("trace mismatch (Go != TS)\n Go: %s\n TS: %s", goRest, live)
	}
}

// ── AttributionReport sign + verify ────────────────────────────────────────

// TestAttributionReportCrossImpl is the central round-trip oracle for the
// signed report: Go builds the report from deterministic inputs, signs it with
// the caller-supplied seed, and asserts the canonical signed bytes (sha256) AND
// the Ed25519 signature hex are byte/hex-identical to the TS reference. It also
// asserts cross-verification both directions.
func TestAttributionReportCrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	seed := deriveSeed()
	pub, err := keys.PublicKeyFromPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}

	// Pinned values produced by the TS reference at build time (sign over
	// canonicalize(report minus signature); seed = sha256("aps-go-attribution-key")).
	// tsCanonSHA and tsSig regenerated 2026-07-11 (Day-145 audit, receipt
	// format v1.1 -> v1.2): the report preimage embeds merkleRoot =
	// buildMerkleRoot(['rh1','rh2']), whose value moved with the
	// domain-separated Merkle construction. entriesHash carries no Merkle
	// material and is unchanged.
	const (
		tsCanonSHA    = "ee75fb9c1f3202a5b09dc243a01bda304ed13572f73f90a7211bec7b1e04a100"
		tsSig         = "8c53c181e570ed777615ccb435470e96ed835db91ab344b9b0bbdb608385fc836ecd0f75554f1e6a0d45769afce7bab6d5f37a83acb5c1478dcf92ec71d39909"
		tsEntriesHash = "dea9dca26512375d77e506b0eb91ba6085362bd87c709e88bd5230d155d78ebb"
	)

	report := fixtureReport(t)
	if report.EntriesHash != tsEntriesHash {
		t.Fatalf("entries hash Go = %s, want %s (TS)", report.EntriesHash, tsEntriesHash)
	}

	// Canonical signed-bytes sha256 must match the TS reference.
	preimage, err := ReportSignedBytes(report)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(preimage))
	goCanonSHA := hex.EncodeToString(sum[:])
	if goCanonSHA != tsCanonSHA {
		t.Fatalf("canonical signed-bytes sha256 Go = %s, want %s (Go != TS)", goCanonSHA, tsCanonSHA)
	}

	// Signature hex must match the TS reference (Ed25519 is deterministic).
	signed, err := SignReport(report, seed)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature != tsSig {
		t.Fatalf("signature Go = %s, want %s (Go != TS)", signed.Signature, tsSig)
	}

	// Go verifies the Go-signed report.
	valid, errs := VerifyAttributionReport(signed, pub)
	if !valid {
		t.Fatalf("Go failed to verify Go-signed report: %v", errs)
	}

	// Tamper: flip a weight, expect total-weight and entries-hash errors.
	tampered := signed
	tampered.Entries = append([]AttributionEntry(nil), signed.Entries...)
	tampered.Entries[0].Weight = 0.9
	if ok, _ := VerifyAttributionReport(tampered, pub); ok {
		t.Fatal("tampered report unexpectedly verified")
	}

	// Live oracle: TS recomputes the canonical sha + signature and verifies the
	// Go-signed report (Go-created artifact verifies under TS verify); and Go
	// verifies the TS-signed report (TS-created artifact verifies under Go).
	goSignedJSON := mustJSON(t, signed)
	live := runTSX(t, `
import { createHash } from 'node:crypto';
import { sign, publicKeyFromPrivate } from '`+tsRepo+`/src/crypto/keys.ts';
import { canonicalize } from '`+tsRepo+`/src/core/canonical.ts';
import { verifyAttributionReport, buildMerkleRoot } from '`+tsRepo+`/src/core/attribution.ts';
const seed = createHash('sha256').update('`+keySeed+`').digest('hex');
const pub = publicKeyFromPrivate(seed);
const entries = [
  { receiptId: 'rcpt_001', agentId: 'ag_exec', action: 'code_execution', scopeUsed: 'compute:exec', spend: 0, resultStatus: 'success', weight: 0.6, timestamp: '2026-06-03T12:00:00Z' },
  { receiptId: 'rcpt_002', agentId: 'ag_exec', action: 'web_search', scopeUsed: 'data:read', spend: 1.25, resultStatus: 'success', weight: 0.4, timestamp: '2026-06-03T12:05:00Z' }
];
const entriesHash = createHash('sha256').update(canonicalize(entries)).digest('hex');
const report = {
  reportId: 'report_001', beneficiary: 'human_alice', agentId: 'ag_exec',
  period: { from: '2026-06-01T00:00:00Z', to: '2026-06-30T23:59:59Z' },
  entries, totalWeight: 1.0, receiptCount: 2,
  merkleRoot: buildMerkleRoot(['rh1','rh2']), entriesHash,
  generatedAt: '2026-06-03T12:10:00Z'
};
const canon = canonicalize(report);
const sig = sign(canon, seed);
const goSigned = JSON.parse(`+"`"+goSignedJSON+"`"+`);
const out = {
  canonSha: createHash('sha256').update(canon).digest('hex'),
  sig,
  verifyGoSigned: verifyAttributionReport(goSigned, pub).valid
};
process.stdout.write(JSON.stringify(out));
`)
	var lr struct {
		CanonSha       string `json:"canonSha"`
		Sig            string `json:"sig"`
		VerifyGoSigned bool   `json:"verifyGoSigned"`
	}
	if err := json.Unmarshal([]byte(live), &lr); err != nil {
		t.Fatalf("decode tsx output %q: %v", live, err)
	}
	if lr.CanonSha != goCanonSHA {
		t.Fatalf("live TS canon sha = %s, Go = %s (Go != TS)", lr.CanonSha, goCanonSHA)
	}
	if lr.Sig != signed.Signature {
		t.Fatalf("live TS signature = %s, Go = %s (Go != TS)", lr.Sig, signed.Signature)
	}
	if !lr.VerifyGoSigned {
		t.Fatal("TS verifyAttributionReport rejected Go-signed report (Go != TS)")
	}

	// TS-created artifact verifies under Go: build a TS-signed report and check.
	tsReport := report
	tsReport.Signature = lr.Sig
	if ok, errs := VerifyAttributionReport(tsReport, pub); !ok {
		t.Fatalf("Go failed to verify TS-signed report: %v (Go != TS)", errs)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func traceRestJSON(t *testing.T, tr BeneficiaryTrace) string {
	t.Helper()
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "traceId")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// canonJSON re-serializes a JSON string through map decode/encode so two
// objects with the same fields compare equal regardless of key order.
func canonJSON(t *testing.T, s string) string {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("canonJSON decode %q: %v", s, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
