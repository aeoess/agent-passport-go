// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package coordination ports the APS Layer 6 coordination primitives from the
// reference SDK (src/core/coordination.ts) into Go. It covers the signed-message
// create + verify pairs that drive a multi-agent task lifecycle:
//
//	Brief -> Assign -> Accept -> Evidence -> Review -> Handoff -> Deliver -> Complete
//
// Every artifact is Ed25519 signed over its canonical (RFC 8785 / JCS) form with
// the signature field removed, exactly as the reference SDK signs
// canonicalize(content). The Go canonical bytes and signature hex are byte and
// hex identical to the TypeScript reference; see coordination_test.go for the
// cross-implementation pins captured from the live TS SDK.
//
// Scope: this package ports protocol primitives only. It deliberately excludes
// the stateful TaskUnit store and lifecycle helpers (createTaskUnit,
// getTaskStatus, validateTaskUnit) from the reference module, which manage an
// in-memory aggregate rather than emit a single signed artifact.
//
// Key-custody rules, non-negotiable:
//   - Private keys are supplied by the caller. The package keeps no global
//     mutable key state.
//   - Private key material is never logged and never placed in an error string.
//
// To keep fan-out packages independent and parallel-buildable, this package
// imports only the Phase-0 core (keys, jcs) and the Go standard library. It
// never imports a sibling fan-out package; any delegation reference is just an
// opaque string id supplied by the caller.
package coordination

import (
	"errors"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// VerifyResult mirrors the reference SDK's { valid, errors } verification shape.
type VerifyResult struct {
	Valid  bool
	Errors []string
}

// ── Task Brief ──────────────────────────────────────────────────────────────

// TaskRoleSpec is a role slot in a task brief. AssignedTo and DelegationId are
// filled in once a role is assigned; when empty they are omitted from the
// canonical form (the reference canonicalize strips undefined keys), so an
// unassigned role canonicalizes without those keys.
type TaskRoleSpec struct {
	Role                 string
	Description          string
	AllowedScopes        []string
	ForbiddenScopes      []string
	RequiredCapabilities []string
	AssignedTo           string
	DelegationID         string
}

// DeliverableSpec describes one expected output of a task.
type DeliverableSpec struct {
	DeliverableID  string
	Name           string
	Description    string
	Format         string
	ProducedBy     string
	RequiredFields []string
	MinCitations   *int
}

// TaskBrief is an operator's signed decomposition of work into roles and
// deliverables.
type TaskBrief struct {
	TaskID             string
	Version            string
	Title              string
	Description        string
	CreatedBy          string
	CreatedAt          string
	Deadline           string
	Roles              []TaskRoleSpec
	Deliverables       []DeliverableSpec
	AcceptanceCriteria []string
	Status             string
	Signature          string
}

func roleSpecToMap(r TaskRoleSpec) map[string]interface{} {
	m := map[string]interface{}{
		"role":            r.Role,
		"description":     r.Description,
		"allowedScopes":   stringSliceToIface(r.AllowedScopes),
		"forbiddenScopes": stringSliceToIface(r.ForbiddenScopes),
	}
	if len(r.RequiredCapabilities) > 0 {
		m["requiredCapabilities"] = stringSliceToIface(r.RequiredCapabilities)
	}
	if r.AssignedTo != "" {
		m["assignedTo"] = r.AssignedTo
	}
	if r.DelegationID != "" {
		m["delegationId"] = r.DelegationID
	}
	return m
}

func deliverableSpecToMap(d DeliverableSpec) map[string]interface{} {
	m := map[string]interface{}{
		"deliverableId": d.DeliverableID,
		"name":          d.Name,
		"description":   d.Description,
		"format":        d.Format,
		"producedBy":    d.ProducedBy,
	}
	if len(d.RequiredFields) > 0 {
		m["requiredFields"] = stringSliceToIface(d.RequiredFields)
	}
	if d.MinCitations != nil {
		m["minCitations"] = *d.MinCitations
	}
	return m
}

func (b TaskBrief) contentMap() map[string]interface{} {
	roles := make([]interface{}, len(b.Roles))
	for i, r := range b.Roles {
		roles[i] = roleSpecToMap(r)
	}
	dels := make([]interface{}, len(b.Deliverables))
	for i, d := range b.Deliverables {
		dels[i] = deliverableSpecToMap(d)
	}
	m := map[string]interface{}{
		"taskId":             b.TaskID,
		"version":            b.Version,
		"title":              b.Title,
		"description":        b.Description,
		"createdBy":          b.CreatedBy,
		"createdAt":          b.CreatedAt,
		"roles":              roles,
		"deliverables":       dels,
		"acceptanceCriteria": stringSliceToIface(b.AcceptanceCriteria),
		"status":             b.Status,
	}
	if b.Deadline != "" {
		m["deadline"] = b.Deadline
	}
	return m
}

// CreateTaskBrief builds a TaskBrief from caller-supplied deterministic inputs
// and signs it with the operator private key. The caller owns id, timestamp,
// and key material; this primitive performs no clock or randomness access.
//
// version defaults to "1.0" when empty, matching the reference literal.
func CreateTaskBrief(b TaskBrief, operatorPrivateKey string) (TaskBrief, error) {
	if b.Version == "" {
		b.Version = "1.0"
	}
	if b.Status == "" {
		b.Status = "draft"
	}
	sig, err := keys.SignCanonical(b.contentMap(), operatorPrivateKey)
	if err != nil {
		return TaskBrief{}, err
	}
	b.Signature = sig
	return b, nil
}

// VerifyTaskBrief checks the operator signature and the structural invariants
// the reference SDK enforces.
func VerifyTaskBrief(b TaskBrief) VerifyResult {
	var errs []string
	if !verifyContent(b.contentMap(), b.Signature, b.CreatedBy) {
		errs = append(errs, "Invalid operator signature on task brief")
	}
	if len(b.Roles) == 0 {
		errs = append(errs, "Task brief must have at least one role")
	}
	if len(b.Deliverables) == 0 {
		errs = append(errs, "Task brief must have at least one deliverable")
	}
	if len(b.AcceptanceCriteria) == 0 {
		errs = append(errs, "Task brief must have acceptance criteria")
	}
	roleNames := map[string]bool{}
	for _, r := range b.Roles {
		roleNames[r.Role] = true
	}
	for _, d := range b.Deliverables {
		if !roleNames[d.ProducedBy] {
			errs = append(errs, "Deliverable \""+d.Name+"\" assigned to role \""+d.ProducedBy+"\" which is not in the task")
		}
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Task Assignment ──────────────────────────────────────────────────────────

// TaskAssignment links a delegation to a role. The operator signs the
// assignment content; the agent later signs an acceptance (see AcceptTask).
type TaskAssignment struct {
	AssignmentID      string
	TaskID            string
	Role              string
	AgentID           string
	AgentPublicKey    string
	DelegationID      string
	AssignedBy        string
	AssignedAt        string
	AcceptedAt        string
	AgentSignature    string
	OperatorSignature string
}

// assignmentContent is the operator-signed preimage: every field except the
// agent acceptance fields and the operator signature itself.
func (a TaskAssignment) contentMap() map[string]interface{} {
	return map[string]interface{}{
		"assignmentId":   a.AssignmentID,
		"taskId":         a.TaskID,
		"role":           a.Role,
		"agentId":        a.AgentID,
		"agentPublicKey": a.AgentPublicKey,
		"delegationId":   a.DelegationID,
		"assignedBy":     a.AssignedBy,
		"assignedAt":     a.AssignedAt,
	}
}

// CreateAssignment builds and operator-signs a TaskAssignment. assignedBy is the
// operator public key; sign with the matching operator private key.
func CreateAssignment(a TaskAssignment, operatorPrivateKey string) (TaskAssignment, error) {
	sig, err := keys.SignCanonical(a.contentMap(), operatorPrivateKey)
	if err != nil {
		return TaskAssignment{}, err
	}
	a.OperatorSignature = sig
	return a, nil
}

// VerifyAssignment checks the operator signature over the assignment content.
func VerifyAssignment(a TaskAssignment) VerifyResult {
	var errs []string
	if !verifyContent(a.contentMap(), a.OperatorSignature, a.AssignedBy) {
		errs = append(errs, "Invalid operator signature on assignment")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// acceptContent is the agent-signed preimage for acceptance.
func acceptContent(assignmentID, taskID, acceptedAt string) map[string]interface{} {
	return map[string]interface{}{
		"assignmentId": assignmentID,
		"taskId":       taskID,
		"acceptedAt":   acceptedAt,
	}
}

// AcceptTask records an agent's acceptance of an assignment. The agent signs the
// minimal { assignmentId, taskId, acceptedAt } tuple, matching the reference SDK.
func AcceptTask(a TaskAssignment, acceptedAt, agentPrivateKey string) (TaskAssignment, error) {
	sig, err := keys.SignCanonical(acceptContent(a.AssignmentID, a.TaskID, acceptedAt), agentPrivateKey)
	if err != nil {
		return TaskAssignment{}, err
	}
	a.AcceptedAt = acceptedAt
	a.AgentSignature = sig
	return a, nil
}

// VerifyAcceptance checks the agent acceptance signature against the agent
// public key recorded on the assignment.
func VerifyAcceptance(a TaskAssignment) VerifyResult {
	var errs []string
	if a.AcceptedAt == "" || a.AgentSignature == "" {
		errs = append(errs, "Assignment has not been accepted")
		return VerifyResult{Valid: false, Errors: errs}
	}
	if !verifyContent(acceptContent(a.AssignmentID, a.TaskID, a.AcceptedAt), a.AgentSignature, a.AgentPublicKey) {
		errs = append(errs, "Invalid agent signature on acceptance")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Evidence Packet ──────────────────────────────────────────────────────────

// EvidenceClaim is one cited factual claim in an evidence packet.
type EvidenceClaim struct {
	ClaimID    string
	Dimension  string
	Subject    string
	Claim      string
	Quote      string
	SourceURL  string
	Confidence string
}

func claimToMap(c EvidenceClaim) map[string]interface{} {
	return map[string]interface{}{
		"claimId":    c.ClaimID,
		"dimension":  c.Dimension,
		"subject":    c.Subject,
		"claim":      c.Claim,
		"quote":      c.Quote,
		"sourceUrl":  c.SourceURL,
		"confidence": c.Confidence,
	}
}

// EvidenceMetadata is the computed summary block on an evidence packet.
type EvidenceMetadata struct {
	SourcesSearched int
	TotalClaims     int
	CitedClaims     int
	GapCount        int
	Methodology     string
}

// EvidencePacket is a researcher's signed research output.
type EvidencePacket struct {
	PacketID    string
	TaskID      string
	SubmittedBy string
	Role        string
	SubmittedAt string
	Claims      []EvidenceClaim
	Metadata    EvidenceMetadata
	Signature   string
}

func (p EvidencePacket) contentMap() map[string]interface{} {
	claims := make([]interface{}, len(p.Claims))
	for i, c := range p.Claims {
		claims[i] = claimToMap(c)
	}
	return map[string]interface{}{
		"packetId":    p.PacketID,
		"taskId":      p.TaskID,
		"submittedBy": p.SubmittedBy,
		"role":        p.Role,
		"submittedAt": p.SubmittedAt,
		"claims":      claims,
		"metadata": map[string]interface{}{
			"sourcesSearched": p.Metadata.SourcesSearched,
			"totalClaims":     p.Metadata.TotalClaims,
			"citedClaims":     p.Metadata.CitedClaims,
			"gapCount":        p.Metadata.GapCount,
			"methodology":     p.Metadata.Methodology,
		},
	}
}

// ComputeEvidenceMetadata derives the packet metadata from its claims the same
// way the reference submitEvidence does: distinct cited sources, total claims,
// cited (non not_found with a sourceUrl) claims, and not_found gap count.
func ComputeEvidenceMetadata(claims []EvidenceClaim, methodology string) EvidenceMetadata {
	sources := map[string]bool{}
	cited := 0
	gaps := 0
	for _, c := range claims {
		if c.SourceURL != "" {
			sources[c.SourceURL] = true
		}
		if c.Confidence == "not_found" {
			gaps++
		} else if c.SourceURL != "" {
			cited++
		}
	}
	return EvidenceMetadata{
		SourcesSearched: len(sources),
		TotalClaims:     len(claims),
		CitedClaims:     cited,
		GapCount:        gaps,
		Methodology:     methodology,
	}
}

// SubmitEvidence signs an evidence packet with the submitter private key. The
// caller supplies fully-formed claims (with claim ids) and the metadata block;
// use ComputeEvidenceMetadata to derive metadata deterministically.
func SubmitEvidence(p EvidencePacket, submitterPrivateKey string) (EvidencePacket, error) {
	sig, err := keys.SignCanonical(p.contentMap(), submitterPrivateKey)
	if err != nil {
		return EvidencePacket{}, err
	}
	p.Signature = sig
	return p, nil
}

// VerifyEvidence checks the submitter signature and the reference quality rule
// that a non not_found claim quote has at least three space-separated words.
func VerifyEvidence(p EvidencePacket) VerifyResult {
	var errs []string
	if !verifyContent(p.contentMap(), p.Signature, p.SubmittedBy) {
		errs = append(errs, "Invalid signature on evidence packet")
	}
	for _, c := range p.Claims {
		if c.Confidence != "not_found" && wordCount(c.Quote) < 3 {
			errs = append(errs, "Claim "+c.ClaimID+": quote too short (< 3 words)")
		}
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Review Decision ──────────────────────────────────────────────────────────

// ReviewIssue is a specific problem a reviewer flagged on a claim.
type ReviewIssue struct {
	ClaimID  string
	Issue    string
	Severity string
}

func issueToMap(i ReviewIssue) map[string]interface{} {
	return map[string]interface{}{
		"claimId":  i.ClaimID,
		"issue":    i.Issue,
		"severity": i.Severity,
	}
}

// ReviewDecision is an operator's signed quality gate on an evidence packet.
type ReviewDecision struct {
	ReviewID   string
	TaskID     string
	PacketID   string
	ReviewedBy string
	ReviewedAt string
	Verdict    string
	Score      int
	Threshold  int
	Rationale  string
	Issues     []ReviewIssue
	Signature  string
}

func (r ReviewDecision) contentMap() map[string]interface{} {
	m := map[string]interface{}{
		"reviewId":   r.ReviewID,
		"taskId":     r.TaskID,
		"packetId":   r.PacketID,
		"reviewedBy": r.ReviewedBy,
		"reviewedAt": r.ReviewedAt,
		"verdict":    r.Verdict,
		"score":      r.Score,
		"threshold":  r.Threshold,
		"rationale":  r.Rationale,
	}
	// Reference: issues is optional. When nil/undefined the key is stripped from
	// the canonical form. An explicit empty slice is encoded as [].
	if r.Issues != nil {
		issues := make([]interface{}, len(r.Issues))
		for i, is := range r.Issues {
			issues[i] = issueToMap(is)
		}
		m["issues"] = issues
	}
	return m
}

// ErrApproveBelowThreshold is returned when an approve verdict is requested for
// a score below the threshold, matching the reference guard.
var ErrApproveBelowThreshold = errors.New("coordination: cannot approve, score below threshold")

// ReviewEvidence builds and signs a review decision with the reviewer private
// key. It enforces the reference rule: an approve verdict requires score >=
// threshold.
func ReviewEvidence(r ReviewDecision, reviewerPrivateKey string) (ReviewDecision, error) {
	if r.Score < r.Threshold && r.Verdict == "approve" {
		return ReviewDecision{}, ErrApproveBelowThreshold
	}
	sig, err := keys.SignCanonical(r.contentMap(), reviewerPrivateKey)
	if err != nil {
		return ReviewDecision{}, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyReview checks the reviewer signature and the 0-100 score bound.
func VerifyReview(r ReviewDecision) VerifyResult {
	var errs []string
	if !verifyContent(r.contentMap(), r.Signature, r.ReviewedBy) {
		errs = append(errs, "Invalid signature on review decision")
	}
	if r.Score < 0 || r.Score > 100 {
		errs = append(errs, "Score must be 0-100")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Evidence Handoff ─────────────────────────────────────────────────────────

// EvidenceHandoff is an operator's signed transfer of approved evidence from one
// role to another.
type EvidenceHandoff struct {
	HandoffID         string
	TaskID            string
	PacketID          string
	ReviewID          string
	FromRole          string
	ToRole            string
	FromAgent         string
	ToAgent           string
	HandoffAt         string
	OperatorSignature string
}

func (h EvidenceHandoff) contentMap() map[string]interface{} {
	return map[string]interface{}{
		"handoffId": h.HandoffID,
		"taskId":    h.TaskID,
		"packetId":  h.PacketID,
		"reviewId":  h.ReviewID,
		"fromRole":  h.FromRole,
		"toRole":    h.ToRole,
		"fromAgent": h.FromAgent,
		"toAgent":   h.ToAgent,
		"handoffAt": h.HandoffAt,
	}
}

// ErrHandoffNotApproved is returned when a handoff is built from a review whose
// verdict is not "approve", matching the reference guard.
var ErrHandoffNotApproved = errors.New("coordination: cannot handoff, evidence not approved")

// ErrHandoffPacketMismatch is returned when the review does not reference the
// same packet being handed off.
var ErrHandoffPacketMismatch = errors.New("coordination: review does not match evidence packet")

// HandoffEvidence builds and operator-signs a handoff. It enforces the reference
// guards: the review must be an approval and must reference the same packet.
func HandoffEvidence(h EvidenceHandoff, review ReviewDecision, operatorPrivateKey string) (EvidenceHandoff, error) {
	if review.Verdict != "approve" {
		return EvidenceHandoff{}, ErrHandoffNotApproved
	}
	if review.PacketID != h.PacketID {
		return EvidenceHandoff{}, ErrHandoffPacketMismatch
	}
	sig, err := keys.SignCanonical(h.contentMap(), operatorPrivateKey)
	if err != nil {
		return EvidenceHandoff{}, err
	}
	h.OperatorSignature = sig
	return h, nil
}

// VerifyHandoff checks the operator signature over the handoff content.
func VerifyHandoff(h EvidenceHandoff, operatorPublicKey string) VerifyResult {
	var errs []string
	if !verifyContent(h.contentMap(), h.OperatorSignature, operatorPublicKey) {
		errs = append(errs, "Invalid operator signature on handoff")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Deliverable ──────────────────────────────────────────────────────────────

// Deliverable is a role's final signed output, tied to the task and the evidence
// it drew on.
type Deliverable struct {
	DeliverableID     string
	TaskID            string
	SpecID            string
	SubmittedBy       string
	Role              string
	SubmittedAt       string
	Content           string
	EvidencePacketIDs []string
	CitationCount     int
	GapsFlagged       int
	Signature         string
}

func (d Deliverable) contentMap() map[string]interface{} {
	return map[string]interface{}{
		"deliverableId":     d.DeliverableID,
		"taskId":            d.TaskID,
		"specId":            d.SpecID,
		"submittedBy":       d.SubmittedBy,
		"role":              d.Role,
		"submittedAt":       d.SubmittedAt,
		"content":           d.Content,
		"evidencePacketIds": stringSliceToIface(d.EvidencePacketIDs),
		"citationCount":     d.CitationCount,
		"gapsFlagged":       d.GapsFlagged,
	}
}

// SubmitDeliverable signs a deliverable with the submitter private key.
func SubmitDeliverable(d Deliverable, submitterPrivateKey string) (Deliverable, error) {
	sig, err := keys.SignCanonical(d.contentMap(), submitterPrivateKey)
	if err != nil {
		return Deliverable{}, err
	}
	d.Signature = sig
	return d, nil
}

// VerifyDeliverable checks the submitter signature over the deliverable content.
func VerifyDeliverable(d Deliverable) VerifyResult {
	var errs []string
	if !verifyContent(d.contentMap(), d.Signature, d.SubmittedBy) {
		errs = append(errs, "Invalid signature on deliverable")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── Task Completion ──────────────────────────────────────────────────────────

// TaskMetrics is the computed summary block on a task completion. The ratio
// fields carry the same rounding the reference SDK applies (two decimals).
type TaskMetrics struct {
	TotalDuration        int
	CoordinationOverhead int
	TaskWorkTime         int
	OverheadRatio        float64
	EvidenceGapRate      float64
	ReworkCount          int
	ErrorsCaught         int
	AgentCount           int
}

func (m TaskMetrics) toMap() map[string]interface{} {
	return map[string]interface{}{
		"totalDuration":        m.TotalDuration,
		"coordinationOverhead": m.CoordinationOverhead,
		"taskWorkTime":         m.TaskWorkTime,
		"overheadRatio":        m.OverheadRatio,
		"evidenceGapRate":      m.EvidenceGapRate,
		"reworkCount":          m.ReworkCount,
		"errorsCaught":         m.ErrorsCaught,
		"agentCount":           m.AgentCount,
	}
}

// TaskCompletion is an operator's signed close-out of a task unit.
type TaskCompletion struct {
	TaskID         string
	CompletedBy    string
	CompletedAt    string
	Status         string
	DeliverableIDs []string
	Metrics        TaskMetrics
	Retrospective  string
	Signature      string
}

func (c TaskCompletion) contentMap() map[string]interface{} {
	m := map[string]interface{}{
		"taskId":         c.TaskID,
		"completedBy":    c.CompletedBy,
		"completedAt":    c.CompletedAt,
		"status":         c.Status,
		"deliverableIds": stringSliceToIface(c.DeliverableIDs),
		"metrics":        c.Metrics.toMap(),
	}
	if c.Retrospective != "" {
		m["retrospective"] = c.Retrospective
	}
	return m
}

// CompleteTask signs a task completion with the operator private key. The caller
// supplies the completion fields and metrics (the reference computeTask metrics
// derivation depends on a whole TaskUnit and wall-clock time, which is out of
// scope for a pure primitive).
func CompleteTask(c TaskCompletion, operatorPrivateKey string) (TaskCompletion, error) {
	sig, err := keys.SignCanonical(c.contentMap(), operatorPrivateKey)
	if err != nil {
		return TaskCompletion{}, err
	}
	c.Signature = sig
	return c, nil
}

// VerifyCompletion checks the operator signature over the completion content.
func VerifyCompletion(c TaskCompletion, operatorPublicKey string) VerifyResult {
	var errs []string
	if !verifyContent(c.contentMap(), c.Signature, operatorPublicKey) {
		errs = append(errs, "Invalid operator signature on task completion")
	}
	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// ── shared helpers ───────────────────────────────────────────────────────────

// verifyContent canonicalizes content and verifies sigHex under pubHex. A
// canonicalization error (which cannot carry key material) reports as invalid.
func verifyContent(content map[string]interface{}, sigHex, pubHex string) bool {
	canon, err := jcs.Canonicalize(content)
	if err != nil {
		return false
	}
	return keys.Verify(canon, sigHex, pubHex)
}

// canonicalBytes returns the canonical (signed-preimage) string for an artifact
// content map. Exposed only within the package for the cross-impl test.
func canonicalBytes(content map[string]interface{}) (string, error) {
	return jcs.Canonicalize(content)
}

// stringSliceToIface converts a []string to []interface{} so it canonicalizes
// through jcs. A nil slice becomes an empty array, matching JSON [] for a
// present-but-empty list.
func stringSliceToIface(s []string) []interface{} {
	out := make([]interface{}, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// wordCount counts space-separated tokens the same way the reference
// quote.split(' ').length does: split on single spaces, count non-handling of
// empties is preserved by using the JS-equivalent split semantics.
func wordCount(s string) int {
	// JS "a b".split(' ') => ["a","b"]; "".split(' ') => [""] (length 1).
	// We replicate: count = number of ' '-delimited segments.
	if s == "" {
		return 1
	}
	count := 1
	for _, r := range s {
		if r == ' ' {
			count++
		}
	}
	return count
}
