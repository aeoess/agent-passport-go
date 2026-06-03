// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package coordination

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

// ── Deterministic key material ───────────────────────────────────────────────
//
// Seeds are sha256 of a fixed string, derived identically in Go and in the TS
// cross-check harness (createHash("sha256").update(s).digest("hex")). No
// randomness, no wall-clock. The public keys below were produced by the TS
// reference (src/crypto/keys.ts) from these same seeds at build time and are
// pinned so a drift in either derivation path is caught.
const (
	opSeedInput = "aps-go-coordination-operator"
	agSeedInput = "aps-go-coordination-agent"

	// Produced by the TS reference at build time from the seeds above.
	tsOpPub = "c0edca39d668b3099df88e8f9b56098ad5f91dfdb566121244692a79b8943fce"
	tsAgPub = "50020df3a746eabb43de27e64d5ecfdf59265e7e28738ac60cabc79fb69c0433"
)

func seedHex(seedInput string) string {
	s := sha256.Sum256([]byte(seedInput))
	return hex.EncodeToString(s[:])
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// keyset derives the operator and agent keys and asserts the Go-derived public
// keys equal the TS reference public keys (custody-safe: no key material in any
// log or error string).
func keyset(t *testing.T) (opPriv, opPub, agPriv, agPub string) {
	t.Helper()
	opPriv = seedHex(opSeedInput)
	agPriv = seedHex(agSeedInput)
	var err error
	opPub, err = keys.PublicKeyFromPrivate(opPriv)
	if err != nil {
		t.Fatalf("derive operator public key: %v", err)
	}
	agPub, err = keys.PublicKeyFromPrivate(agPriv)
	if err != nil {
		t.Fatalf("derive agent public key: %v", err)
	}
	if opPub != tsOpPub {
		t.Fatalf("operator public key %s != TS reference %s", opPub, tsOpPub)
	}
	if agPub != tsAgPub {
		t.Fatalf("agent public key %s != TS reference %s", agPub, tsAgPub)
	}
	return
}

const taskID = "task-fixed-001"

// assertMatch checks that the Go artifact's canonical-byte sha256 and its
// signature hex equal the TS reference values captured at build time. The
// pinned constants are produced by the live TS SDK (canonicalize + sign);
// none are authored from memory.
func assertMatch(t *testing.T, label string, content map[string]interface{}, gotSig, wantSHA, wantSig string) {
	t.Helper()
	canon, err := canonicalBytes(content)
	if err != nil {
		t.Fatalf("%s: canonicalize: %v", label, err)
	}
	if gotSHA := sha256Hex(canon); gotSHA != wantSHA {
		t.Errorf("%s: canonical sha256 = %s, want %s (TS reference)\n  canonical=%s", label, gotSHA, wantSHA, canon)
	}
	if gotSig != wantSig {
		t.Errorf("%s: signature = %s, want %s (TS reference)", label, gotSig, wantSig)
	}
}

// ── Cross-impl pins ──────────────────────────────────────────────────────────
//
// Every WANT_*_SHA / WANT_*_SIG below was produced by the reference TypeScript
// SDK at build time over the identical deterministic inputs constructed in each
// test, via:
//
//	canon = canonicalize(content)   // src/core/canonical.ts
//	sig   = sign(canon, privHex)    // src/crypto/keys.ts
//	sha   = sha256(canon)
//
// They are pinned to guard against drift in the Go JCS path, struct->map field
// ordering, number formatting, or null-stripping behavior.
const (
	wantBriefSHA = "9b913c393c6eb3f73fa490f3ef1e6c5015f1e54ff72509e26df904e0cbd5055b"
	wantBriefSig = "191ef32f6d7d6616781f0ae639c1a7115f76926703a017f339373f8963ce5c183a180eb3c0baa806ffbb6c1fafdbd7ee788ddf076086f149192e4aced1224907"

	wantAssignSHA = "e4573725cee2410e2205cfdcc0b95c86b35ae4899828893986dd10e6137c4177"
	wantAssignSig = "139d4ad3d4aae4ae05b52d1dfde1d0a88ef7990a57f2b10d0082265c0987b8a8de164cbf9711d5e7333006662057360b7c2d40983c2c80e333aaba95e1dee00b"

	wantAcceptSHA = "0ab51d246f5ea59bd8f65fd867cf6edfa9612b744387908ccc81e1494b9c1cf3"
	wantAcceptSig = "46a499d477cc480ca76ae55d010f852ab9de496a82431b4dbf752f238599333b4166960ce43d490cad53bd654b3a955fcdd3ebd30c452e75744df07de3915e08"

	wantEvidenceSHA = "636735fe257a17df8cd0eba88e48815191efe004f4811f6d6846d569864d847f"
	wantEvidenceSig = "61e1e4302672c9ecffdc14a57b61fd93e13666a5182284c4fc8592c1391c4af7f2c802a4289f2d7f8913e366a9790c57a86a2a578d60215c289574acc9adac02"

	wantReviewSHA = "1f4c7653e4dc7f338b0850b35033faca4141a9269fc0a34b3330c94345283307"
	wantReviewSig = "02dedafe70294147a2024b4d6225cf78b6f8abbfb355fdecfddf4d5c2ea4fce945b30862bb34e723d73ccdfc9e6b4b2d79d691b9e2dadcd99fb600373ac50b07"

	wantHandoffSHA = "def5bd66ad02daba6c38203297b6c9ea16505118a8b90533de57c65d245382af"
	wantHandoffSig = "81ea243b2c0b4f20db4a24a6d6555b090cd43429958be1b672839ceb8f557a186a38f111a17f1de47b027176adf52c4510d375554a3e39522a1b80b27c5b9909"

	wantDeliverableSHA = "66ff5d6bd5e77131aaaff323e94ceec48204b30d4c4df79f50f6dbdd62a1e5c2"
	wantDeliverableSig = "b930d4b090cea28992ff81eba37252428add91f81c3bd28f6511f1872fe5ee289488db7fa6245ca204b10213021bf14e336a4bb94940bc5b60d0b52301f65207"

	wantCompletionSHA = "c3a489a85aa69bd6e9ac53b70471bdf640f517c136b80373aa6fe3d0d3a4581a"
	wantCompletionSig = "d74a3ab095fc1544505a5268a970c6499cdd4ac7ddf3b3b403cf9ec5f163597b3a9c6c8c68d46ff5c3caaea47201b2450c08900967c9e87fac0ac58962e91d0c"
)

// ── builders for the fixed artifacts ─────────────────────────────────────────

func fixedBrief(opPub string) TaskBrief {
	return TaskBrief{
		TaskID:      taskID,
		Version:     "1.0",
		Title:       "Map the standards landscape",
		Description: "Identify active multi-agent identity standards bodies.",
		CreatedBy:   opPub,
		CreatedAt:   "2026-06-03T12:00:00Z",
		Deadline:    "2026-06-10T12:00:00Z",
		Roles: []TaskRoleSpec{
			{Role: "researcher", Description: "find sources", AllowedScopes: []string{"data:read"}, ForbiddenScopes: []string{"payment:send"}},
		},
		Deliverables: []DeliverableSpec{
			{DeliverableID: taskID + "-del-0", Name: "landscape", Description: "matrix of bodies", Format: "markdown", ProducedBy: "researcher"},
		},
		AcceptanceCriteria: []string{"at least 5 bodies", "each with a citation"},
		Status:             "draft",
	}
}

func fixedAssignment(opPub, agPub string) TaskAssignment {
	return TaskAssignment{
		AssignmentID:   "assign-fixed-001",
		TaskID:         taskID,
		Role:           "researcher",
		AgentID:        "agent-007",
		AgentPublicKey: agPub,
		DelegationID:   "deleg-fixed-001",
		AssignedBy:     opPub,
		AssignedAt:     "2026-06-03T12:05:00Z",
	}
}

func fixedEvidence(agPub string) EvidencePacket {
	return EvidencePacket{
		PacketID:    "evid-fixed-001",
		TaskID:      taskID,
		SubmittedBy: agPub,
		Role:        "researcher",
		SubmittedAt: "2026-06-03T12:20:00Z",
		Claims: []EvidenceClaim{
			{
				ClaimID:    "evid-fixed-001-c0",
				Dimension:  "governance",
				Subject:    "W3C",
				Claim:      "W3C hosts the DID working group",
				Quote:      "the decentralized identifier working group is chartered",
				SourceURL:  "https://www.w3.org/groups/wg/did",
				Confidence: "high",
			},
		},
		Metadata: EvidenceMetadata{
			SourcesSearched: 1,
			TotalClaims:     1,
			CitedClaims:     1,
			GapCount:        0,
			Methodology:     "web search of standards bodies",
		},
	}
}

func fixedReview(opPub string) ReviewDecision {
	return ReviewDecision{
		ReviewID:   "review-fixed-001",
		TaskID:     taskID,
		PacketID:   "evid-fixed-001",
		ReviewedBy: opPub,
		ReviewedAt: "2026-06-03T12:30:00Z",
		Verdict:    "approve",
		Score:      85,
		Threshold:  70,
		Rationale:  "claims cited and within scope",
		// Issues nil -> stripped from canonical form (matches TS undefined).
	}
}

func fixedHandoff(opPub, agPub string) EvidenceHandoff {
	return EvidenceHandoff{
		HandoffID: "handoff-fixed-001",
		TaskID:    taskID,
		PacketID:  "evid-fixed-001",
		ReviewID:  "review-fixed-001",
		FromRole:  "researcher",
		ToRole:    "analyst",
		FromAgent: agPub,
		ToAgent:   opPub,
		HandoffAt: "2026-06-03T12:40:00Z",
	}
}

func fixedDeliverable(agPub string) Deliverable {
	return Deliverable{
		DeliverableID:     "deliv-fixed-001",
		TaskID:            taskID,
		SpecID:            taskID + "-del-0",
		SubmittedBy:       agPub,
		Role:              "analyst",
		SubmittedAt:       "2026-06-03T12:50:00Z",
		Content:           "Landscape matrix with five bodies.",
		EvidencePacketIDs: []string{"evid-fixed-001"},
		CitationCount:     5,
		GapsFlagged:       1,
	}
}

func fixedCompletion(opPub string) TaskCompletion {
	return TaskCompletion{
		TaskID:         taskID,
		CompletedBy:    opPub,
		CompletedAt:    "2026-06-03T13:00:00Z",
		Status:         "completed",
		DeliverableIDs: []string{"deliv-fixed-001"},
		Metrics: TaskMetrics{
			TotalDuration:        3600,
			CoordinationOverhead: 120,
			TaskWorkTime:         3480,
			OverheadRatio:        0.03,
			EvidenceGapRate:      0,
			ReworkCount:          0,
			ErrorsCaught:         0,
			AgentCount:           1,
		},
		Retrospective: "clean run, no rework",
	}
}

// ── cross-impl byte/hex match tests ──────────────────────────────────────────

func TestTaskBriefCrossImpl(t *testing.T) {
	opPriv, opPub, _, _ := keyset(t)
	b, err := CreateTaskBrief(fixedBrief(opPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "TaskBrief", b.contentMap(), b.Signature, wantBriefSHA, wantBriefSig)
	if res := VerifyTaskBrief(b); !res.Valid {
		t.Errorf("Go VerifyTaskBrief failed: %v", res.Errors)
	}
}

func TestAssignmentCrossImpl(t *testing.T) {
	opPriv, opPub, _, agPub := keyset(t)
	a, err := CreateAssignment(fixedAssignment(opPub, agPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Assignment", a.contentMap(), a.OperatorSignature, wantAssignSHA, wantAssignSig)
	if res := VerifyAssignment(a); !res.Valid {
		t.Errorf("Go VerifyAssignment failed: %v", res.Errors)
	}
}

func TestAcceptCrossImpl(t *testing.T) {
	opPriv, opPub, agPriv, agPub := keyset(t)
	a, err := CreateAssignment(fixedAssignment(opPub, agPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	a, err = AcceptTask(a, "2026-06-03T12:10:00Z", agPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Accept", acceptContent(a.AssignmentID, a.TaskID, a.AcceptedAt), a.AgentSignature, wantAcceptSHA, wantAcceptSig)
	if res := VerifyAcceptance(a); !res.Valid {
		t.Errorf("Go VerifyAcceptance failed: %v", res.Errors)
	}
}

func TestEvidenceCrossImpl(t *testing.T) {
	_, _, agPriv, agPub := keyset(t)
	p, err := SubmitEvidence(fixedEvidence(agPub), agPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Evidence", p.contentMap(), p.Signature, wantEvidenceSHA, wantEvidenceSig)
	if res := VerifyEvidence(p); !res.Valid {
		t.Errorf("Go VerifyEvidence failed: %v", res.Errors)
	}
}

func TestReviewCrossImpl(t *testing.T) {
	opPriv, opPub, _, _ := keyset(t)
	r, err := ReviewEvidence(fixedReview(opPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Review", r.contentMap(), r.Signature, wantReviewSHA, wantReviewSig)
	if res := VerifyReview(r); !res.Valid {
		t.Errorf("Go VerifyReview failed: %v", res.Errors)
	}
}

func TestHandoffCrossImpl(t *testing.T) {
	opPriv, opPub, _, agPub := keyset(t)
	review := fixedReview(opPub)
	h, err := HandoffEvidence(fixedHandoff(opPub, agPub), review, opPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Handoff", h.contentMap(), h.OperatorSignature, wantHandoffSHA, wantHandoffSig)
	if res := VerifyHandoff(h, opPub); !res.Valid {
		t.Errorf("Go VerifyHandoff failed: %v", res.Errors)
	}
}

func TestDeliverableCrossImpl(t *testing.T) {
	_, _, agPriv, agPub := keyset(t)
	d, err := SubmitDeliverable(fixedDeliverable(agPub), agPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Deliverable", d.contentMap(), d.Signature, wantDeliverableSHA, wantDeliverableSig)
	if res := VerifyDeliverable(d); !res.Valid {
		t.Errorf("Go VerifyDeliverable failed: %v", res.Errors)
	}
}

func TestCompletionCrossImpl(t *testing.T) {
	opPriv, opPub, _, _ := keyset(t)
	c, err := CompleteTask(fixedCompletion(opPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch(t, "Completion", c.contentMap(), c.Signature, wantCompletionSHA, wantCompletionSig)
	if res := VerifyCompletion(c, opPub); !res.Valid {
		t.Errorf("Go VerifyCompletion failed: %v", res.Errors)
	}
}

// ── cross-verification: TS-created artifact verifies under Go Verify ──────────
//
// The signature constants above were produced by the TS sign(). We reconstruct
// each Go artifact with the TS signature pinned in (not re-signed in Go) and
// confirm the Go Verify path accepts it. Because the Go signatures already match
// the TS signatures byte for byte in the tests above, a passing Go-created
// verify is equivalent to TS-created-verifies-under-Go and vice versa; this test
// makes the TS-origin direction explicit by injecting the TS sig directly.

func TestTSArtifactsVerifyUnderGo(t *testing.T) {
	_, opPub, _, agPub := keyset(t)

	b := fixedBrief(opPub)
	b.Signature = wantBriefSig
	if res := VerifyTaskBrief(b); !res.Valid {
		t.Errorf("TS brief signature rejected by Go Verify: %v", res.Errors)
	}

	a := fixedAssignment(opPub, agPub)
	a.OperatorSignature = wantAssignSig
	if res := VerifyAssignment(a); !res.Valid {
		t.Errorf("TS assignment signature rejected by Go Verify: %v", res.Errors)
	}

	a2 := fixedAssignment(opPub, agPub)
	a2.AcceptedAt = "2026-06-03T12:10:00Z"
	a2.AgentSignature = wantAcceptSig
	if res := VerifyAcceptance(a2); !res.Valid {
		t.Errorf("TS acceptance signature rejected by Go Verify: %v", res.Errors)
	}

	p := fixedEvidence(agPub)
	p.Signature = wantEvidenceSig
	if res := VerifyEvidence(p); !res.Valid {
		t.Errorf("TS evidence signature rejected by Go Verify: %v", res.Errors)
	}

	r := fixedReview(opPub)
	r.Signature = wantReviewSig
	if res := VerifyReview(r); !res.Valid {
		t.Errorf("TS review signature rejected by Go Verify: %v", res.Errors)
	}

	h := fixedHandoff(opPub, agPub)
	h.OperatorSignature = wantHandoffSig
	if res := VerifyHandoff(h, opPub); !res.Valid {
		t.Errorf("TS handoff signature rejected by Go Verify: %v", res.Errors)
	}

	d := fixedDeliverable(agPub)
	d.Signature = wantDeliverableSig
	if res := VerifyDeliverable(d); !res.Valid {
		t.Errorf("TS deliverable signature rejected by Go Verify: %v", res.Errors)
	}

	c := fixedCompletion(opPub)
	c.Signature = wantCompletionSig
	if res := VerifyCompletion(c, opPub); !res.Valid {
		t.Errorf("TS completion signature rejected by Go Verify: %v", res.Errors)
	}
}

// ── tamper detection ─────────────────────────────────────────────────────────

func TestTamperRejected(t *testing.T) {
	opPriv, opPub, _, _ := keyset(t)
	b, err := CreateTaskBrief(fixedBrief(opPub), opPriv)
	if err != nil {
		t.Fatal(err)
	}
	b.Title = "Tampered title"
	if res := VerifyTaskBrief(b); res.Valid {
		t.Error("tampered brief verified as valid")
	}
}

// ── guard behavior ───────────────────────────────────────────────────────────

func TestReviewApproveBelowThresholdRejected(t *testing.T) {
	opPriv, opPub, _, _ := keyset(t)
	r := fixedReview(opPub)
	r.Score = 50
	r.Threshold = 70
	r.Verdict = "approve"
	if _, err := ReviewEvidence(r, opPriv); err != ErrApproveBelowThreshold {
		t.Errorf("expected ErrApproveBelowThreshold, got %v", err)
	}
}

func TestHandoffNotApprovedRejected(t *testing.T) {
	opPriv, opPub, _, agPub := keyset(t)
	review := fixedReview(opPub)
	review.Verdict = "rework"
	if _, err := HandoffEvidence(fixedHandoff(opPub, agPub), review, opPriv); err != ErrHandoffNotApproved {
		t.Errorf("expected ErrHandoffNotApproved, got %v", err)
	}
}

func TestHandoffPacketMismatchRejected(t *testing.T) {
	opPriv, opPub, _, agPub := keyset(t)
	review := fixedReview(opPub)
	review.PacketID = "evid-other"
	if _, err := HandoffEvidence(fixedHandoff(opPub, agPub), review, opPriv); err != ErrHandoffPacketMismatch {
		t.Errorf("expected ErrHandoffPacketMismatch, got %v", err)
	}
}

// ── pure-compute primitive ───────────────────────────────────────────────────

func TestComputeEvidenceMetadata(t *testing.T) {
	claims := []EvidenceClaim{
		{Confidence: "high", SourceURL: "https://a"},
		{Confidence: "medium", SourceURL: "https://b"},
		{Confidence: "not_found", SourceURL: ""},
		{Confidence: "high", SourceURL: "https://a"}, // duplicate source
	}
	m := ComputeEvidenceMetadata(claims, "method")
	if m.TotalClaims != 4 {
		t.Errorf("TotalClaims = %d, want 4", m.TotalClaims)
	}
	if m.SourcesSearched != 2 {
		t.Errorf("SourcesSearched = %d, want 2 (distinct)", m.SourcesSearched)
	}
	if m.CitedClaims != 3 {
		t.Errorf("CitedClaims = %d, want 3", m.CitedClaims)
	}
	if m.GapCount != 1 {
		t.Errorf("GapCount = %d, want 1", m.GapCount)
	}
}
