// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package completion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// tsSDKDir is the reference SDK checkout used by the cross-impl oracle,
// resolved from APS_TS_REPO. The tsx scripts interpolate it into their import
// paths at runtime. When APS_TS_REPO is unset the cross-impl tests skip (see
// skipUnlessTSRepo); the pinned constants still guard the invariant.
var tsSDKDir = os.Getenv("APS_TS_REPO")

// skipUnlessTSRepo skips the calling cross-impl test when APS_TS_REPO is unset
// or empty, with the canonical message, before any use of the repo path or tsx.
func skipUnlessTSRepo(t *testing.T) {
	t.Helper()
	if tsSDKDir == "" {
		t.Skip("set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	}
}

// detSeedHex derives the deterministic private seed the same way on both sides:
// sha256("aps-go-completion-key") as 64-char hex (a 32-byte Ed25519 seed). No
// randomness, no wall clock.
func detSeedHex() string {
	sum := sha256.Sum256([]byte("aps-go-completion-key"))
	return hex.EncodeToString(sum[:])
}

func canonSHA(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	h, err := jcs.CanonicalHash(body)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	return h
}

// ---------------------------------------------------------------------------
// Pinned TS-reference values.
//
// These hex values were produced at build time by the REAL reference SDK
// (src/core/completion.ts signs canonicalize(body) via src/crypto/keys.ts
// sign()) over the deterministic bodies below, derived seed
// sha256("aps-go-completion-key"). The cross-impl tests below also re-run the
// TS SDK live via `npx tsx` and assert against the freshly produced values, so
// these constants are a redundant drift guard, not the sole oracle.
// ---------------------------------------------------------------------------

const (
	tsPubKey = "b91dee8f0ed7bb76876495064232b041f85da0ebfcf008d2689bbb71c2da9b83"

	// No-citations completion receipt body.
	tsCanonSHA = "d40404f763b7cd899fdebcc4da2f978781d45f6f4b402725c77d2aadef5fb890"
	tsSig      = "5b5359c17093fc9a2ddceff06c1fb2425feb996d636d0a9a2af2557d6852d2cff3290657ec25f5d0c8298a3cd90dfaf6eb2c06c21523e135ea665a43a88c0008"

	// Citations-bearing completion receipt body.
	tsCanonSHACite = "f30ac596ffb288d15aff4beb9306c6446928de0a6e447a5d03085b1f7d03285b"
	tsSigCite      = "a2eb450825186d74e3cc7947740ec02a025089a0d37e67d4de6d86193b56e95d350fac21712c685a46588c8a8587d5cb2f52d8da52d362134a06ba4463066005"

	// linkPermitAndCompletion: legacy-canonical sha256 of the null-stripped
	// permit body {agentId, decision, receiptId}.
	tsPermitHash = "bd6b527f8aa62fe2fcc6ba1754f49d4cbc89c0b0a2053d71e0735d4aeb503ae3"
)

// fixedNoCite builds the deterministic no-citations options used everywhere.
func fixedNoCiteOpts() CompletionReceiptOptions {
	return CompletionReceiptOptions{
		CompletionID:      "cmp_000000000001",
		PermitReceiptHash: strings.Repeat("a", 64),
		ExecutionResult:   "success",
		ResultSummary:     "task done",
		ResultHash:        strings.Repeat("b", 64),
		ExecutedAt:        "2026-06-03T12:00:00Z",
		DurationMs:        1500,
		SignedAt:          "2026-06-03T12:00:05Z",
		PrivateKey:        detSeedHex(),
	}
}

func fixedCiteOpts() CompletionReceiptOptions {
	return CompletionReceiptOptions{
		CompletionID:      "cmp_000000000002",
		PermitReceiptHash: strings.Repeat("c", 64),
		ExecutionResult:   "partial",
		ResultSummary:     "",
		ResultHash:        "",
		ExecutedAt:        "2026-06-03T12:00:00Z",
		DurationMs:        0,
		SignedAt:          "2026-06-03T12:00:05Z",
		PrivateKey:        detSeedHex(),
		Citations: []ArtifactCitation{
			{ReceiptID: "rcpt_attr_001", CitedPrincipal: "did:aps:principal:alice", CitationContent: "the sky is blue"},
		},
	}
}

// runTSX executes a tsx script against the reference SDK and returns trimmed
// stdout. It is the same mechanism the action_ref cross-impl check uses.
func runTSX(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("npx", "tsx", "-e", script)
	cmd.Dir = tsSDKDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tsx failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// parseKV parses simple KEY=VALUE lines emitted by the tsx scripts.
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}

// TestCreateCompletionReceipt_NoCitations_CrossImpl is the round-trip oracle for
// the no-citations body: Go-built canonical bytes and signature must be
// byte/hex-identical to the live TS reference, and each side must verify the
// other's signature.
func TestCreateCompletionReceipt_NoCitations_CrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	opts := fixedNoCiteOpts()
	r, err := CreateCompletionReceipt(opts)
	if err != nil {
		t.Fatal(err)
	}

	goCanon := canonSHA(t, receiptBody(&r))
	if goCanon != tsCanonSHA {
		t.Fatalf("canonical sha256 drift: go=%s pinned=%s", goCanon, tsCanonSHA)
	}
	if r.Signature != tsSig {
		t.Fatalf("signature drift: go=%s pinned=%s", r.Signature, tsSig)
	}

	// Live TS run over the SAME deterministic body.
	script := `
import { createHash } from "node:crypto";
import { canonicalize } from "` + tsSDKDir + `/src/core/canonical.ts";
import { sign, publicKeyFromPrivate } from "` + tsSDKDir + `/src/crypto/keys.ts";
const priv = createHash("sha256").update("aps-go-completion-key").digest("hex");
const body = {
  completionId: "cmp_000000000001",
  permitReceiptHash: "a".repeat(64),
  executionResult: "success",
  resultSummary: "task done",
  resultHash: "b".repeat(64),
  executedAt: "2026-06-03T12:00:00Z",
  durationMs: 1500,
  signedAt: "2026-06-03T12:00:05Z",
};
const c = canonicalize(body);
console.log("CANON_SHA256=" + createHash("sha256").update(c, "utf8").digest("hex"));
console.log("SIG=" + sign(c, priv));
console.log("PUB=" + publicKeyFromPrivate(priv));
`
	kv := parseKV(runTSX(t, script))
	if kv["CANON_SHA256"] != goCanon {
		t.Fatalf("Go != TS canonical: go=%s ts=%s", goCanon, kv["CANON_SHA256"])
	}
	if kv["SIG"] != r.Signature {
		t.Fatalf("Go != TS signature: go=%s ts=%s", r.Signature, kv["SIG"])
	}
	if kv["PUB"] != tsPubKey {
		t.Fatalf("public key drift: ts=%s pinned=%s", kv["PUB"], tsPubKey)
	}

	// Cross-verify: TS signature verifies under Go verify.
	res := VerifyCompletionReceipt(&r, tsPubKey, nil)
	if !res.Valid {
		t.Fatalf("Go verify of TS-matching receipt failed: %v", res.Errors)
	}

	// Cross-verify the other direction: a Go-created artifact verifies under TS.
	assertTSVerifies(t, &r, tsPubKey, true)
}

// TestCreateCompletionReceipt_Citations_CrossImpl is the same byte/hex oracle
// for the citations-bearing body. Citations are part of the signed canonical
// bytes. It pins the fixed-body canonical sha256 and signature, then re-derives
// them live from the TS reference. The TS end-to-end verifyCompletionReceipt
// (with a real attribution receipt) is exercised separately below.
func TestCreateCompletionReceipt_Citations_CrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	opts := fixedCiteOpts()
	r, err := CreateCompletionReceipt(opts)
	if err != nil {
		t.Fatal(err)
	}

	goCanon := canonSHA(t, receiptBody(&r))
	if goCanon != tsCanonSHACite {
		t.Fatalf("canonical sha256 drift (cite): go=%s pinned=%s", goCanon, tsCanonSHACite)
	}
	if r.Signature != tsSigCite {
		t.Fatalf("signature drift (cite): go=%s pinned=%s", r.Signature, tsSigCite)
	}

	script := `
import { createHash } from "node:crypto";
import { canonicalize } from "` + tsSDKDir + `/src/core/canonical.ts";
import { sign } from "` + tsSDKDir + `/src/crypto/keys.ts";
const priv = createHash("sha256").update("aps-go-completion-key").digest("hex");
const body = {
  completionId: "cmp_000000000002",
  permitReceiptHash: "c".repeat(64),
  executionResult: "partial",
  resultSummary: "",
  resultHash: "",
  executedAt: "2026-06-03T12:00:00Z",
  durationMs: 0,
  signedAt: "2026-06-03T12:00:05Z",
  citations: [
    { receipt_id: "rcpt_attr_001", cited_principal: "did:aps:principal:alice", citation_content: "the sky is blue" },
  ],
};
const c = canonicalize(body);
console.log("CANON_SHA256=" + createHash("sha256").update(c, "utf8").digest("hex"));
console.log("SIG=" + sign(c, priv));
`
	kv := parseKV(runTSX(t, script))
	if kv["CANON_SHA256"] != goCanon {
		t.Fatalf("Go != TS canonical (cite): go=%s ts=%s", goCanon, kv["CANON_SHA256"])
	}
	if kv["SIG"] != r.Signature {
		t.Fatalf("Go != TS signature (cite): go=%s ts=%s", r.Signature, kv["SIG"])
	}

	// Go-side structural citation checks (the portion of checkArtifactCitations
	// inside this package's boundary).
	resNoRcpt := VerifyCompletionReceipt(&r, tsPubKey, nil)
	if resNoRcpt.Valid {
		t.Fatal("expected verify to fail when citations present and no receipts supplied")
	}
	resOK := VerifyCompletionReceipt(&r, tsPubKey, []AttributionReceipt{
		{ID: "rcpt_attr_001", CitedPrincipal: "did:aps:principal:alice", CitationContent: "the sky is blue"},
	})
	if !resOK.Valid {
		t.Fatalf("expected valid with matching receipt: %v", resOK.Errors)
	}
	resDup := VerifyCompletionReceipt(&r, tsPubKey, []AttributionReceipt{
		{ID: "rcpt_attr_999", CitedPrincipal: "did:aps:principal:alice", CitationContent: "the sky is blue"},
	})
	if resDup.Valid {
		t.Fatal("expected failure when no receipt matches the citation id")
	}
}

// TestCitationsCompletion_TSEndToEnd builds a fully signed attribution receipt
// in the real TS SDK, has Go construct and sign a completion receipt that cites
// that receipt's real id/principal/content, and asserts the live TS
// verifyCompletionReceipt accepts the Go-produced receipt end to end (signature
// path through the AttributionConsent gate). This proves a Go-created citations
// artifact verifies under TS - the (d) cross-verification direction for the
// citations branch.
func TestCitationsCompletion_TSEndToEnd(t *testing.T) {
	skipUnlessTSRepo(t)
	// Step 1: build a real attribution receipt in TS and read back its fields.
	buildScript := `
import { createHybridTimestampAt } from "` + tsSDKDir + `/src/core/time.ts";
import { createAttributionReceipt, signAttributionConsent } from "` + tsSDKDir + `/src/v2/attribution-consent/index.ts";
import { createHash } from "node:crypto";
import { publicKeyFromPrivate } from "` + tsSDKDir + `/src/crypto/keys.ts";
const citerPriv = createHash("sha256").update("aps-go-completion-citer").digest("hex");
const principalPriv = createHash("sha256").update("aps-go-completion-principal").digest("hex");
const now = Date.now();
// Wide validity window so the verifier's wall-clock check passes regardless of
// the moment the test runs.
const created = { logicalTime: 1, wallClockEarliest: 0, wallClockLatest: now + 1, gatewayId: "g" };
const expires = { logicalTime: 2, wallClockEarliest: 0, wallClockLatest: now + 3.15e12, gatewayId: "g" };
let receipt = createAttributionReceipt({
  citer: "did:aps:agent:citer",
  citer_public_key: publicKeyFromPrivate(citerPriv),
  citer_private_key: citerPriv,
  cited_principal: "did:aps:principal:alice",
  cited_principal_public_key: publicKeyFromPrivate(principalPriv),
  citation_content: "the sky is blue",
  binding_context: "ctx_completion",
  created_at: created,
  expires_at: expires,
});
receipt = signAttributionConsent(receipt, principalPriv);
console.log("RECEIPT=" + JSON.stringify(receipt));
console.log("ID=" + receipt.id);
`
	kv := parseKV(runTSX(t, buildScript))
	receiptID := kv["ID"]
	receiptJSON := kv["RECEIPT"]
	if receiptID == "" || receiptJSON == "" {
		t.Fatalf("failed to build TS attribution receipt: %q", runTSX(t, buildScript))
	}

	// Step 2: Go builds a completion receipt citing that exact receipt id.
	r, err := CreateCompletionReceipt(CompletionReceiptOptions{
		CompletionID:      "cmp_e2e_0001",
		PermitReceiptHash: strings.Repeat("d", 64),
		ExecutionResult:   "success",
		ResultSummary:     "cited work",
		ResultHash:        strings.Repeat("e", 64),
		ExecutedAt:        "2026-06-03T12:00:00Z",
		DurationMs:        42,
		SignedAt:          "2026-06-03T12:00:05Z",
		PrivateKey:        detSeedHex(),
		Citations: []ArtifactCitation{
			{ReceiptID: receiptID, CitedPrincipal: "did:aps:principal:alice", CitationContent: "the sky is blue"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Go verifies its own receipt with a matching structural receipt.
	goRes := VerifyCompletionReceipt(&r, tsPubKey, []AttributionReceipt{
		{ID: receiptID, CitedPrincipal: "did:aps:principal:alice", CitationContent: "the sky is blue"},
	})
	if !goRes.Valid {
		t.Fatalf("Go verify failed: %v", goRes.Errors)
	}

	// Step 3: TS verifyCompletionReceipt accepts the Go receipt + the real
	// attribution receipt array end to end.
	completionJSON, err := json.Marshal(map[string]interface{}{
		"completionId":      r.CompletionID,
		"permitReceiptHash": r.PermitReceiptHash,
		"executionResult":   r.ExecutionResult,
		"resultSummary":     r.ResultSummary,
		"resultHash":        r.ResultHash,
		"executedAt":        r.ExecutedAt,
		"durationMs":        r.DurationMs,
		"signedAt":          r.SignedAt,
		"signature":         r.Signature,
		"citations": []map[string]string{{
			"receipt_id":       receiptID,
			"cited_principal":  "did:aps:principal:alice",
			"citation_content": "the sky is blue",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyScript := `
import { verifyCompletionReceipt } from "` + tsSDKDir + `/src/core/completion.ts";
const receipt = ` + string(completionJSON) + `;
const attr = [` + receiptJSON + `];
const r = verifyCompletionReceipt(receipt, "` + tsPubKey + `", attr);
console.log("VALID=" + r.valid);
console.log("ERRORS=" + JSON.stringify(r.errors));
`
	vkv := parseKV(runTSX(t, verifyScript))
	if vkv["VALID"] != "true" {
		t.Fatalf("TS end-to-end verify failed: errors=%s", vkv["ERRORS"])
	}
}

// assertTSVerifies feeds a Go-produced no-citations receipt JSON to the real TS
// verifyCompletionReceipt and asserts its valid flag, proving a Go-created
// artifact verifies under TS.
func assertTSVerifies(t *testing.T, r *CompletionReceipt, pub string, wantValid bool) {
	t.Helper()
	receiptJSON, err := json.Marshal(map[string]interface{}{
		"completionId":      r.CompletionID,
		"permitReceiptHash": r.PermitReceiptHash,
		"executionResult":   r.ExecutionResult,
		"resultSummary":     r.ResultSummary,
		"resultHash":        r.ResultHash,
		"executedAt":        r.ExecutedAt,
		"durationMs":        r.DurationMs,
		"signedAt":          r.SignedAt,
		"signature":         r.Signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := `
import { verifyCompletionReceipt } from "` + tsSDKDir + `/src/core/completion.ts";
const receipt = ` + string(receiptJSON) + `;
const r = verifyCompletionReceipt(receipt, "` + pub + `");
console.log("VALID=" + r.valid);
console.log("ERRORS=" + JSON.stringify(r.errors));
`
	kv := parseKV(runTSX(t, script))
	got := kv["VALID"] == "true"
	if got != wantValid {
		t.Fatalf("TS verifyCompletionReceipt valid=%v want=%v errors=%s", got, wantValid, kv["ERRORS"])
	}
}

// TestVerifyCompletionReceipt_Tamper confirms a mutated body fails Go verify.
func TestVerifyCompletionReceipt_Tamper(t *testing.T) {
	r, err := CreateCompletionReceipt(fixedNoCiteOpts())
	if err != nil {
		t.Fatal(err)
	}
	r.ResultSummary = "tampered"
	res := VerifyCompletionReceipt(&r, tsPubKey, nil)
	if res.Valid {
		t.Fatal("expected verify to fail after tampering with signed field")
	}
}

// TestVerifyCompletionReceipt_BadResult exercises the executionResult taxonomy
// check on the verify path independent of the signature.
func TestVerifyCompletionReceipt_BadResult(t *testing.T) {
	r, err := CreateCompletionReceipt(fixedNoCiteOpts())
	if err != nil {
		t.Fatal(err)
	}
	// Mutate to an invalid result after signing; both signature and taxonomy
	// checks should now report problems.
	r.ExecutionResult = "exploded"
	res := VerifyCompletionReceipt(&r, tsPubKey, nil)
	if res.Valid {
		t.Fatal("expected invalid for bad executionResult")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "Invalid executionResult") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected executionResult error, got %v", res.Errors)
	}
}

// TestLinkPermitAndCompletion_CrossImpl checks the pure hash-link primitive
// against the TS reference: matching hash -> linked, mismatch -> not linked, and
// the permit hash itself equals the live TS legacy-canonical sha256.
func TestLinkPermitAndCompletion_CrossImpl(t *testing.T) {
	skipUnlessTSRepo(t)
	permit := map[string]interface{}{
		"receiptId": "rcpt_permit_0001",
		"decision":  "allow",
		"agentId":   "ag_test_001",
		"signature": "deadbeef",
	}

	// Live TS legacy-canonical hash of the null-stripped permit body.
	script := `
import { createHash } from "node:crypto";
import { canonicalize } from "` + tsSDKDir + `/src/core/canonical.ts";
const permit = { receiptId: "rcpt_permit_0001", decision: "allow", agentId: "ag_test_001", signature: "deadbeef" };
const { signature, ...rest } = permit;
const c = canonicalize(rest);
console.log("PERMIT_HASH=" + createHash("sha256").update(c).digest("hex"));
`
	kv := parseKV(runTSX(t, script))
	tsHash := kv["PERMIT_HASH"]
	if tsHash != tsPermitHash {
		t.Fatalf("TS permit hash drift: live=%s pinned=%s", tsHash, tsPermitHash)
	}

	// Matching completion (claims the TS-computed hash).
	matching := &CompletionReceipt{PermitReceiptHash: tsHash}
	link, err := LinkPermitAndCompletion(permit, matching)
	if err != nil {
		t.Fatal(err)
	}
	if !link.Linked {
		t.Fatalf("expected linked, errors=%v", link.Errors)
	}
	if link.PermitHash != tsHash {
		t.Fatalf("Go permit hash != TS: go=%s ts=%s", link.PermitHash, tsHash)
	}

	// Mismatching completion.
	bad := &CompletionReceipt{PermitReceiptHash: strings.Repeat("0", 64)}
	link2, err := LinkPermitAndCompletion(permit, bad)
	if err != nil {
		t.Fatal(err)
	}
	if link2.Linked {
		t.Fatal("expected not linked on hash mismatch")
	}
	if len(link2.Errors) == 0 {
		t.Fatal("expected mismatch error")
	}
}

// TestSignArtifactMatchesManualCanonical sanity-checks that keys.SignArtifact
// over the body equals signing jcs.Canonicalize(body) directly, so the
// completion package and the keys core agree on the preimage.
func TestSignArtifactMatchesManualCanonical(t *testing.T) {
	r, err := CreateCompletionReceipt(fixedNoCiteOpts())
	if err != nil {
		t.Fatal(err)
	}
	body := receiptBody(&r)
	canon, err := jcs.Canonicalize(body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keys.Sign(canon, detSeedHex())
	if err != nil {
		t.Fatal(err)
	}
	if sig != r.Signature {
		t.Fatalf("manual canonical sign != SignArtifact: %s vs %s", sig, r.Signature)
	}
	if !verify.VerifyEd25519([]byte(canon), sig, tsPubKey) {
		t.Fatal("VerifyEd25519 failed on manual canonical")
	}
}
