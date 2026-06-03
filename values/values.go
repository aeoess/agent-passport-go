// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package values ports the Human Values Floor protocol primitives from the APS
// reference SDK (src/core/values.ts): floor loading, enforcement-mode
// resolution, the signed floor attestation, and the signed compliance report.
// It also ports the pure shared-ground negotiation decision.
//
// Layer 2 of the Agent Social Contract. The Floor produces FACTS, not opinions:
// "this principle is technically enforced" is a fact; "this agent is 94.3%
// compliant" is an opinion disguised as a fact. The compliance report still
// emits a number because consumers ask for one, but every per-principle status
// is a verifiable fact.
//
// Signed artifacts (attestation, compliance report) sign over
// jcs.Canonicalize(artifact minus its "signature" field), matching the
// reference exactly. The reference signs with the legacy canonicalize()
// (src/core/canonical.ts); for these artifact shapes, which carry no null or
// undefined fields, that output is byte-identical to RFC 8785 JCS, so the
// Phase-0 jcs.Canonicalize produces the same preimage. The cross-impl tests pin
// the TS-produced canonical-byte hash and Ed25519 signature to guard the
// equivalence.
//
// Key-custody rules: private keys are caller-supplied; the package keeps no
// global mutable key state and never logs or embeds key material in an error.
//
// Boundary: this package ports create + verify + pure-compute primitives only.
// It does not manage any global mutable store and computes no analytics.
package values

import (
	"errors"
	"sort"
	"strings"

	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// EnforcementMode is the graduated enforcement level for a floor principle.
// Strictness ordering is inline > audit > warn; extensions may escalate but
// never de-escalate. Matches the reference EnforcementMode union.
type EnforcementMode string

const (
	// ModeInline is a hard deny: the agent cannot proceed.
	ModeInline EnforcementMode = "inline"
	// ModeAudit logs and flags for human review; the agent proceeds.
	ModeAudit EnforcementMode = "audit"
	// ModeWarn surfaces immediately to the caller; the agent proceeds.
	ModeWarn EnforcementMode = "warn"
)

// enforcementEscalationOrder mirrors ENFORCEMENT_ESCALATION_ORDER in the
// reference SDK (src/types/passport.ts).
var enforcementEscalationOrder = map[EnforcementMode]int{
	ModeWarn:   0,
	ModeAudit:  1,
	ModeInline: 2,
}

// Enforcement describes how a principle is enforced. JSON field names match the
// reference FloorPrinciple["enforcement"] shape.
type Enforcement struct {
	Mode        EnforcementMode `json:"mode"`
	Technical   *bool           `json:"technical,omitempty"` // deprecated, kept for backward compat
	Mechanism   string          `json:"mechanism"`
	ProtocolRef string          `json:"protocolRef,omitempty"`
}

// FloorPrinciple is one principle in the Values Floor.
type FloorPrinciple struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Principle   string      `json:"principle"`
	Enforcement Enforcement `json:"enforcement"`
	Weight      string      `json:"weight"` // mandatory | strong_consideration | advisory
}

// ValuesFloor is the parsed floor manifest.
type ValuesFloor struct {
	Version       string           `json:"version"`
	Schema        string           `json:"schema"`
	LastUpdated   string           `json:"lastUpdated"`
	GovernanceURI string           `json:"governanceUri"`
	Floor         []FloorPrinciple `json:"floor"`
}

// FloorAttestation is the signed artifact in which an agent recognizes a floor
// version. Field names and JSON shape match the reference FloorAttestation.
type FloorAttestation struct {
	AttestationID string   `json:"attestationId"`
	AgentID       string   `json:"agentId"`
	PublicKey     string   `json:"publicKey"`
	FloorVersion  string   `json:"floorVersion"`
	Extensions    []string `json:"extensions"`
	AttestedAt    string   `json:"attestedAt"`
	ExpiresAt     string   `json:"expiresAt"`
	Commitment    string   `json:"commitment"`
	Signature     string   `json:"signature"`
}

// ComplianceCheck is the per-principle fact emitted by a compliance evaluation.
// Status is one of: enforced, attested, violation, unverifiable. Evidence is
// present only when a receipt or delegation id proves the fact; the reference
// omits it otherwise, and the legacy canonicalize strips it, so we omit it too.
type ComplianceCheck struct {
	PrincipleID     string          `json:"principleId"`
	PrincipleName   string          `json:"principleName"`
	Status          string          `json:"status"`
	EnforcementMode EnforcementMode `json:"enforcementMode,omitempty"`
	Evidence        string          `json:"evidence,omitempty"`
	Detail          string          `json:"detail"`
}

// CompliancePeriod is the time window the report covers.
type CompliancePeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ComplianceReport is the signed evidence bundle a verifier emits about an
// agent. overallCompliance is a documented number (fraction of principles with
// no violations, weighted by enforcement type), not a verdict.
type ComplianceReport struct {
	ReportID          string            `json:"reportId"`
	AgentID           string            `json:"agentId"`
	FloorVersion      string            `json:"floorVersion"`
	Period            CompliancePeriod  `json:"period"`
	ReceiptsAnalyzed  int               `json:"receiptsAnalyzed"`
	Checks            []ComplianceCheck `json:"checks"`
	OverallCompliance float64           `json:"overallCompliance"`
	GeneratedAt       string            `json:"generatedAt"`
	Signature         string            `json:"signature"`
}

// SharedGround is the result of negotiating common ethical ground between two
// agents. Matches the reference SharedGround shape.
type SharedGround struct {
	FloorVersion           *string  `json:"floorVersion"` // null when incompatible
	SharedExtensions       []string `json:"sharedExtensions"`
	AgentA                 string   `json:"agentA"` // public key
	AgentB                 string   `json:"agentB"` // public key
	NegotiatedAt           string   `json:"negotiatedAt"`
	Compatible             bool     `json:"compatible"`
	IncompatibilityReasons []string `json:"incompatibilityReasons"`
}

// ActionReceipt is the minimal receipt shape EvaluateCompliance inspects. Field
// names match the reference ActionReceipt. It is defined here (not imported
// from a sibling) so this package stays independent.
type ActionReceipt struct {
	ReceiptID       string        `json:"receiptId"`
	Version         string        `json:"version"`
	Timestamp       string        `json:"timestamp"`
	AgentID         string        `json:"agentId"`
	DelegationID    string        `json:"delegationId"`
	Action          ReceiptAction `json:"action"`
	Result          ReceiptResult `json:"result"`
	DelegationChain []string      `json:"delegationChain"`
	Signature       string        `json:"signature"`
}

// ReceiptAction is the action block of a receipt.
type ReceiptAction struct {
	Type      string `json:"type"`
	Target    string `json:"target"`
	Method    string `json:"method,omitempty"`
	ScopeUsed string `json:"scopeUsed"`
}

// ReceiptResult is the result block of a receipt.
type ReceiptResult struct {
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// DelegationState is the minimal delegation context EvaluateCompliance needs:
// the granted scope and whether the delegation has been revoked. Callers supply
// this map; the package keeps no store of its own.
type DelegationState struct {
	Scope   []string
	Revoked bool
}

var errBadFloor = errors.New("values: input is not a recognizable floor (need a floor array)")

// ══════════════════════════════════════
// FLOOR LOADING
// ══════════════════════════════════════

// LoadFloor parses a Values Floor from JSON. The canonical representation is
// JSON, not YAML: the floor is a protocol artifact, not a config file. (The
// reference also accepts a hand-authored YAML subset; that authoring
// convenience is out of scope for the verify-first Go SDK and is not ported.)
//
// After parsing, any principle missing an explicit enforcement.mode has its
// mode resolved via ResolveEnforcementMode, matching the reference post-process
// step.
func LoadFloor(input string) (ValuesFloor, error) {
	floor, err := parseFloorJSON(input)
	if err != nil {
		return ValuesFloor{}, err
	}
	for i := range floor.Floor {
		if floor.Floor[i].Enforcement.Mode == "" {
			floor.Floor[i].Enforcement.Mode = ResolveEnforcementMode(floor.Floor[i].Enforcement)
		}
	}
	return floor, nil
}

// ══════════════════════════════════════
// ENFORCEMENT MODE RESOLUTION
// ══════════════════════════════════════

// ResolveEnforcementMode returns the effective enforcement mode for a
// principle, with the reference backward-compat rules:
//   - mode present        -> use it
//   - mode absent, technical:true  -> inline
//   - mode absent, technical:false -> audit
//   - nothing -> audit (safe default: log but do not block)
func ResolveEnforcementMode(e Enforcement) EnforcementMode {
	if e.Mode != "" {
		return e.Mode
	}
	if e.Technical != nil && *e.Technical {
		return ModeInline
	}
	if e.Technical != nil && !*e.Technical {
		return ModeAudit
	}
	return ModeAudit
}

// EffectiveEnforcementMode computes the strictest mode across a floor mode and
// any extension modes. Extensions can only escalate (warn->audit->inline),
// never de-escalate; the strictest wins. Mirrors effectiveEnforcementMode in
// the reference SDK.
func EffectiveEnforcementMode(floorMode EnforcementMode, extensionModes ...EnforcementMode) EnforcementMode {
	strictest := floorMode
	for _, m := range extensionModes {
		if enforcementEscalationOrder[m] > enforcementEscalationOrder[strictest] {
			strictest = m
		}
	}
	return strictest
}

// ══════════════════════════════════════
// FLOOR ATTESTATION
// ══════════════════════════════════════

// AttestFloor builds and signs a FloorAttestation. The attestation is minimal:
// the agent signs {floorVersion, extensions, timestamp...}. It says "I
// recognize this floor version" - truth about behavior lives in the receipts,
// not here.
//
// All identifiers and timestamps are caller-supplied so the result is
// deterministic and verifiable: there is no wall-clock or randomness inside. In
// the reference, attestationId is "att_" + a uuid slice, attestedAt/expiresAt
// come from new Date(); callers compute those once and pass them in so the
// signed bytes are reproducible.
//
// The commitment string is derived exactly as the reference does:
//
//	"floor:<version>|ext:<sorted-extensions-joined-by-comma-or-'none'>|ts:<attestedAt>"
//
// Note the commitment sorts a COPY of the extensions; the extensions field on
// the artifact keeps its original order.
//
// privateKey is the 32-byte Ed25519 seed hex of the attesting agent. It is
// never logged and never placed in an error.
func AttestFloor(attestationID, agentID, publicKey, floorVersion string, extensions []string, attestedAt, expiresAt, privateKey string) (FloorAttestation, error) {
	if extensions == nil {
		extensions = []string{}
	}
	att := FloorAttestation{
		AttestationID: attestationID,
		AgentID:       agentID,
		PublicKey:     publicKey,
		FloorVersion:  floorVersion,
		Extensions:    extensions,
		AttestedAt:    attestedAt,
		ExpiresAt:     expiresAt,
		Commitment:    buildCommitment(floorVersion, extensions, attestedAt),
	}
	sig, err := keys.SignArtifact(attestationToMap(att), "signature", privateKey)
	if err != nil {
		return FloorAttestation{}, err
	}
	att.Signature = sig
	return att, nil
}

// buildCommitment reproduces the reference commitment string. It sorts a copy
// of the extensions and joins with commas, or "none" when empty.
func buildCommitment(floorVersion string, extensions []string, attestedAt string) string {
	sorted := append([]string(nil), extensions...)
	sort.Strings(sorted)
	ext := strings.Join(sorted, ",")
	if ext == "" {
		ext = "none"
	}
	return "floor:" + floorVersion + "|ext:" + ext + "|ts:" + attestedAt
}

// VerifyAttestation checks an attestation's signature over its canonical bytes
// (artifact minus signature) and validates the non-crypto invariants. The
// caller supplies now (RFC 3339) so expiry is checked deterministically against
// a fixed instant rather than the wall clock. It returns whether the
// attestation is valid plus the list of errors found.
func VerifyAttestation(att FloorAttestation, now string) (bool, []string) {
	var errs []string

	if !verify.VerifyCanonicalSignature(attestationToMap(att), "signature", att.Signature, att.PublicKey) {
		errs = append(errs, "Invalid attestation signature")
	}
	if att.ExpiresAt != "" && now != "" && timeLess(att.ExpiresAt, now) {
		errs = append(errs, "Attestation expired")
	}
	if att.FloorVersion == "" {
		errs = append(errs, "No floor version specified")
	}
	return len(errs) == 0, errs
}

// ══════════════════════════════════════
// COMPLIANCE - FACTS, NOT SCORES
// ══════════════════════════════════════

// EvaluateCompliance produces FACTS about each floor principle for the named
// agent, then signs the report with the verifier's key. The score weighting
// matches the reference: enforced 1.0, attested 0.8, unverifiable 0.5,
// violation 0.0; overallCompliance is the mean rounded to three decimals.
//
// reportID, generatedAt, and (when there are no receipts) the period bounds are
// caller-supplied so the signed bytes are deterministic. When receipts exist,
// the period is [min receipt timestamp, max receipt timestamp] computed from
// the data, exactly as the reference does.
//
// verifierPrivateKey is the 32-byte Ed25519 seed hex of the report signer; it
// is never logged and never placed in an error.
func EvaluateCompliance(agentID, reportID, generatedAt string, fallbackFrom, fallbackTo string, receipts []ActionReceipt, floor ValuesFloor, delegations map[string]DelegationState, verifierPrivateKey string) (ComplianceReport, error) {
	agentReceipts := make([]ActionReceipt, 0, len(receipts))
	for _, r := range receipts {
		if r.AgentID == agentID {
			agentReceipts = append(agentReceipts, r)
		}
	}

	checks := make([]ComplianceCheck, 0, len(floor.Floor))
	for _, p := range floor.Floor {
		checks = append(checks, evaluatePrinciple(p, agentReceipts, delegations))
	}

	total := len(checks)
	var sum float64
	for _, c := range checks {
		switch c.Status {
		case "enforced":
			sum += 1.0
		case "attested":
			sum += 0.8
		case "unverifiable":
			sum += 0.5
		}
	}
	var score float64
	if total > 0 {
		score = sum / float64(total)
	}

	from, to := periodBounds(agentReceipts, fallbackFrom, fallbackTo)

	report := ComplianceReport{
		ReportID:          reportID,
		AgentID:           agentID,
		FloorVersion:      floor.Version,
		Period:            CompliancePeriod{From: from, To: to},
		ReceiptsAnalyzed:  len(agentReceipts),
		Checks:            checks,
		OverallCompliance: roundTo3(score),
		GeneratedAt:       generatedAt,
	}

	sig, err := keys.SignArtifact(reportToMap(report), "signature", verifierPrivateKey)
	if err != nil {
		return ComplianceReport{}, err
	}
	report.Signature = sig
	return report, nil
}

// VerifyComplianceReport checks the verifier signature over the report's
// canonical bytes (report minus signature).
func VerifyComplianceReport(report ComplianceReport, verifierPublicKey string) bool {
	return verify.VerifyCanonicalSignature(reportToMap(report), "signature", report.Signature, verifierPublicKey)
}

// evaluatePrinciple ports the per-principle switch in the reference. Statuses
// and detail strings are reproduced verbatim so the signed report bytes match.
func evaluatePrinciple(principle FloorPrinciple, receipts []ActionReceipt, delegations map[string]DelegationState) ComplianceCheck {
	mode := ResolveEnforcementMode(principle.Enforcement)
	base := ComplianceCheck{PrincipleID: principle.ID, PrincipleName: principle.Name, EnforcementMode: mode}

	switch principle.ID {
	case "F-001": // Traceability
		if len(receipts) == 0 {
			base.Status = "unverifiable"
			base.Detail = "No receipts to analyze"
			return base
		}
		traced := 0
		for _, r := range receipts {
			if len(r.DelegationChain) > 0 {
				traced++
			}
		}
		if traced == len(receipts) {
			base.Status = "enforced"
			base.Detail = "All " + itoa(len(receipts)) + " receipts have delegation chains"
			if len(receipts) > 0 {
				base.Evidence = receipts[0].ReceiptID
			}
		} else {
			base.Status = "violation"
			base.Detail = itoa(len(receipts)-traced) + " receipts missing delegation chain"
		}
		return base

	case "F-002": // Honest Identity
		ids := map[string]struct{}{}
		for _, r := range receipts {
			ids[r.AgentID] = struct{}{}
		}
		if len(ids) <= 1 {
			base.Status = "enforced"
			base.Detail = "Consistent agent identity across all receipts"
		} else {
			base.Status = "violation"
			base.Detail = "Multiple agent IDs: " + strings.Join(sortedKeys(ids), ", ")
		}
		return base

	case "F-003": // Scoped Authority
		var bad []ActionReceipt
		for _, r := range receipts {
			d, ok := delegations[r.DelegationID]
			if ok && !scopeAuthorizes(d.Scope, r.Action.ScopeUsed) {
				bad = append(bad, r)
			}
		}
		if len(bad) == 0 {
			base.Status = "enforced"
			base.Detail = "All actions within delegated scope"
		} else {
			base.Status = "violation"
			base.Detail = itoa(len(bad)) + " out-of-scope actions"
			base.Evidence = bad[0].ReceiptID
		}
		return base

	case "F-004": // Revocability
		var revoked []ActionReceipt
		for _, r := range receipts {
			if d, ok := delegations[r.DelegationID]; ok && d.Revoked {
				revoked = append(revoked, r)
			}
		}
		if len(revoked) == 0 {
			base.Status = "enforced"
			base.Detail = "No actions under revoked delegations"
		} else {
			base.Status = "violation"
			base.Detail = itoa(len(revoked)) + " actions under revoked delegations"
			base.Evidence = revoked[0].ReceiptID
		}
		return base

	case "F-005": // Auditability
		if len(receipts) == 0 {
			base.Status = "unverifiable"
			base.Detail = "No receipts to audit"
			return base
		}
		signed := 0
		for _, r := range receipts {
			if len(r.Signature) > 0 {
				signed++
			}
		}
		if signed == len(receipts) {
			base.Status = "enforced"
			base.Detail = "All " + itoa(len(receipts)) + " receipts cryptographically signed"
		} else {
			base.Status = "violation"
			base.Detail = "Unsigned receipts found"
		}
		return base

	case "F-006": // Non-Deception
		base.Status = "attested"
		base.Detail = "Requires reasoning-level verification"
		return base

	case "F-007": // Proportionality
		base.Status = "attested"
		base.Detail = "Requires reputation context"
		return base

	default:
		base.Status = "unverifiable"
		base.Detail = "Unknown principle " + principle.ID
		return base
	}
}

// ══════════════════════════════════════
// COMMON GROUND NEGOTIATION (pure decision)
// ══════════════════════════════════════

// NegotiateCommonGround determines shared ethical ground between two agents:
// same major floor version plus the intersection of extensions. This is the
// pure decision logic from the reference negotiateCommonGround. The reference
// reads new Date() for both expiry comparison and the negotiatedAt stamp; to
// keep this deterministic and free of wall-clock state, the caller supplies now
// (RFC 3339, used for both the expiry check and the stamp). The compatibility
// rule and extension intersection are reproduced exactly.
//
// The intersection preserves attestationB's extension order, matching the
// reference filter over attestationB.extensions.
func NegotiateCommonGround(pubKeyA string, attestationA FloorAttestation, pubKeyB string, attestationB FloorAttestation, now string) SharedGround {
	var reasons []string

	if attestationA.ExpiresAt != "" && now != "" && timeLess(attestationA.ExpiresAt, now) {
		reasons = append(reasons, "Agent "+attestationA.AgentID+" attestation expired")
	}
	if attestationB.ExpiresAt != "" && now != "" && timeLess(attestationB.ExpiresAt, now) {
		reasons = append(reasons, "Agent "+attestationB.AgentID+" attestation expired")
	}

	majorA := majorVersion(attestationA.FloorVersion)
	majorB := majorVersion(attestationB.FloorVersion)
	compatible := majorA == majorB
	if !compatible {
		reasons = append(reasons, "Incompatible floor versions: "+attestationA.FloorVersion+" vs "+attestationB.FloorVersion)
	}

	extA := map[string]struct{}{}
	for _, e := range attestationA.Extensions {
		extA[e] = struct{}{}
	}
	shared := []string{}
	for _, e := range attestationB.Extensions {
		if _, ok := extA[e]; ok {
			shared = append(shared, e)
		}
	}

	var floorVersion *string
	if compatible {
		v := attestationA.FloorVersion
		floorVersion = &v
	}

	return SharedGround{
		FloorVersion:           floorVersion,
		SharedExtensions:       shared,
		AgentA:                 pubKeyA,
		AgentB:                 pubKeyB,
		NegotiatedAt:           now,
		Compatible:             len(reasons) == 0 && compatible,
		IncompatibilityReasons: nonNilStrings(reasons),
	}
}
