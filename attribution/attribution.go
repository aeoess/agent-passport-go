// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package attribution ports the PRIMITIVE half of the APS Beneficiary
// Attribution Protocol (Layer 3): pure Merkle math, beneficiary trace, the
// receipt hash helper, and signed-report verification. It is byte-faithful to
// the reference SDK src/core/attribution.ts.
//
// Scope is verify-first plus pure compute. The weight-based report generators
// (computeAttribution, computeCollaborationAttribution, DEFAULT_SCOPE_WEIGHTS)
// are product policy and live in the gateway, not here; they are intentionally
// not ported. See the package report for the boundary record.
//
// Canonicalization note: the reference module signs and hashes over the LEGACY
// canonicalize() from src/core/canonical.ts, which strips null/undefined object
// values and sorts keys by code point. The Phase-0 jcs.Canonicalize (RFC 8785)
// produces byte-identical output for any object that contains no null values.
// The artifacts here carry no null fields, so the two agree byte for byte. The
// Merkle helpers concatenate raw hex strings and are canonicalizer-independent.
//
// Key-custody: callers supply private keys; no global mutable key state exists
// in this package, and key material is never logged or placed in an error.
package attribution

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// ActionReceipt mirrors ActionReceipt in src/types/passport.ts. Only the fields
// that participate in the canonical hash and beneficiary trace are modeled with
// concrete typing; the optional witness and finality extensions are out of
// scope for the primitive half. Field names and JSON tags match the reference.
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

// ReceiptAction is the action block of an ActionReceipt.
type ReceiptAction struct {
	Type      string        `json:"type"`
	Target    string        `json:"target"`
	Method    string        `json:"method,omitempty"`
	ScopeUsed string        `json:"scopeUsed"`
	Spend     *ReceiptSpend `json:"spend,omitempty"`
}

// ReceiptSpend is the optional spend block on a receipt action.
type ReceiptSpend struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// ReceiptResult is the result block of an ActionReceipt.
type ReceiptResult struct {
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// BeneficiaryInfo mirrors BeneficiaryInfo in src/types/passport.ts: the human
// principal a public key resolves to.
type BeneficiaryInfo struct {
	PrincipalID        string `json:"principalId"`
	PrincipalPublicKey string `json:"principalPublicKey,omitempty"`
	Relationship       string `json:"relationship"`
	RegisteredAt       string `json:"registeredAt"`
}

// DelegationHop is one link of a beneficiary trace. Mirrors DelegationHop.
type DelegationHop struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	DelegationID string   `json:"delegationId"`
	Scope        []string `json:"scope"`
	Depth        int      `json:"depth"`
}

// BeneficiaryTrace mirrors BeneficiaryTrace: the resolved path from an executing
// agent back to the human beneficiary.
type BeneficiaryTrace struct {
	TraceID       string          `json:"traceId"`
	ReceiptID     string          `json:"receiptId"`
	ExecutorAgent string          `json:"executorAgent"`
	Beneficiary   string          `json:"beneficiary"`
	Chain         []DelegationHop `json:"chain"`
	TotalDepth    int             `json:"totalDepth"`
	Verified      bool            `json:"verified"`
}

// TraceDelegation is the minimal delegation shape traceBeneficiary reads:
// delegatedBy, delegatedTo, delegationId, scope. It is declared inline here
// rather than imported from a sibling package so this package stays
// independent and builds in parallel.
type TraceDelegation struct {
	DelegationID string   `json:"delegationId"`
	DelegatedBy  string   `json:"delegatedBy"`
	DelegatedTo  string   `json:"delegatedTo"`
	Scope        []string `json:"scope"`
}

// AttributionEntry mirrors AttributionEntry in src/types/passport.ts.
type AttributionEntry struct {
	ReceiptID    string  `json:"receiptId"`
	AgentID      string  `json:"agentId"`
	Action       string  `json:"action"`
	ScopeUsed    string  `json:"scopeUsed"`
	Spend        float64 `json:"spend"`
	ResultStatus string  `json:"resultStatus"`
	Weight       float64 `json:"weight"`
	Timestamp    string  `json:"timestamp"`
}

// AttributionPeriod is the from/to window of a report.
type AttributionPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// AttributionReport mirrors AttributionReport in src/types/passport.ts. The
// signed bytes are canonicalize(report minus signature). This package verifies
// such a report; it does not generate the weights (that is gateway policy).
type AttributionReport struct {
	ReportID     string             `json:"reportId"`
	Beneficiary  string             `json:"beneficiary"`
	AgentID      string             `json:"agentId"`
	Period       AttributionPeriod  `json:"period"`
	Entries      []AttributionEntry `json:"entries"`
	TotalWeight  float64            `json:"totalWeight"`
	ReceiptCount int                `json:"receiptCount"`
	MerkleRoot   string             `json:"merkleRoot"`
	EntriesHash  string             `json:"entriesHash"`
	GeneratedAt  string             `json:"generatedAt"`
	Signature    string             `json:"signature"`
}

// MerkleProofNode is one sibling on the path from leaf to root.
type MerkleProofNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// MerkleProof is an inclusion proof for a single leaf hash.
type MerkleProof struct {
	ReceiptHash string            `json:"receiptHash"`
	Root        string            `json:"root"`
	Proof       []MerkleProofNode `json:"proof"`
	Index       int               `json:"index"`
}

// sha256Hex returns the lowercase-hex SHA-256 of the UTF-8 bytes of data,
// matching the reference sha256() helper in attribution.ts.
func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// HashReceipt returns sha256(canonicalize(receipt)), byte-identical to
// hashReceipt in attribution.ts. The receipt is canonicalized whole, including
// its signature field (the reference hashes the full receipt). The receipt is
// projected to generic JSON first because jcs.Canonicalize operates on the
// generic shape (map/slice/scalar), the same as the reference object.
func HashReceipt(receipt ActionReceipt) (string, error) {
	canon, err := jcs.Canonicalize(toGeneric(receipt))
	if err != nil {
		return "", err
	}
	return sha256Hex(canon), nil
}

// TraceBeneficiary follows the delegation chain on a receipt back to the human
// principal, mirroring traceBeneficiary in attribution.ts. Because the reference
// mints traceId from a random uuid, the caller supplies traceID here so the
// result is deterministic and key/clock-free; all other fields are computed
// exactly as the reference does.
func TraceBeneficiary(
	traceID string,
	receipt ActionReceipt,
	delegations []TraceDelegation,
	beneficiaryMap map[string]BeneficiaryInfo,
) BeneficiaryTrace {
	chain := []DelegationHop{}
	keyChain := receipt.DelegationChain

	for i := 0; i+1 < len(keyChain); i++ {
		from := keyChain[i]
		to := keyChain[i+1]

		delegationID := "unknown"
		scope := []string{}
		for _, d := range delegations {
			if d.DelegatedBy == from && d.DelegatedTo == to {
				if d.DelegationID != "" {
					delegationID = d.DelegationID
				}
				if d.Scope != nil {
					scope = d.Scope
				}
				break
			}
		}

		chain = append(chain, DelegationHop{
			From:         from,
			To:           to,
			DelegationID: delegationID,
			Scope:        scope,
			Depth:        i,
		})
	}

	var principalKey string
	if len(keyChain) > 0 {
		principalKey = keyChain[0]
	}
	beneficiary, hasBeneficiary := beneficiaryMap[principalKey]

	resolved := principalKey
	if hasBeneficiary && beneficiary.PrincipalID != "" {
		resolved = beneficiary.PrincipalID
	}

	verified := hasBeneficiary
	for _, h := range chain {
		if h.DelegationID == "unknown" {
			verified = false
			break
		}
	}

	return BeneficiaryTrace{
		TraceID:       traceID,
		ReceiptID:     receipt.ReceiptID,
		ExecutorAgent: receipt.AgentID,
		Beneficiary:   resolved,
		Chain:         chain,
		TotalDepth:    len(chain),
		Verified:      verified,
	}
}

// VerifyAttributionReport mirrors verifyAttributionReport in attribution.ts: a
// pure check of the report signature over canonicalize(report minus signature),
// the receipt-count consistency, the total-weight consistency, and (if present)
// the entries hash. It returns whether the report is valid and the list of
// errors, in the same order the reference appends them.
func VerifyAttributionReport(report AttributionReport, publicKey string) (bool, []string) {
	errs := []string{}

	if !verifyReportSignature(report, publicKey) {
		errs = append(errs, "Invalid attribution report signature")
	}

	if report.ReceiptCount != len(report.Entries) {
		errs = append(errs, "Receipt count mismatch: "+itoa(report.ReceiptCount)+" vs "+itoa(len(report.Entries))+" entries")
	}

	var sum float64
	for _, e := range report.Entries {
		sum += e.Weight
	}
	expected := roundTo3(sum)
	if absf(report.TotalWeight-expected) > 0.001 {
		errs = append(errs, "Total weight does not match entry weights")
	}

	if report.EntriesHash != "" {
		canon, err := jcs.Canonicalize(toGeneric(report.Entries))
		if err == nil {
			expectedHash := sha256Hex(canon)
			if report.EntriesHash != expectedHash {
				errs = append(errs, "Entries hash mismatch - weights may have been tampered")
			}
		} else {
			errs = append(errs, "Entries hash mismatch - weights may have been tampered")
		}
	}

	return len(errs) == 0, errs
}

// BuildMerkleRoot builds a Merkle root from leaf hashes, byte-identical to
// buildMerkleRoot in attribution.ts. Empty input returns sha256("empty"); a
// single leaf returns itself; otherwise leaves are sorted ascending (string
// order), then paired left+right with the last node duplicated on odd levels
// (Bitcoin-style), hashing sha256(left + right) on string concatenation.
func BuildMerkleRoot(leafHashes []string) string {
	if len(leafHashes) == 0 {
		return sha256Hex("empty")
	}
	if len(leafHashes) == 1 {
		return leafHashes[0]
	}

	level := make([]string, len(leafHashes))
	copy(level, leafHashes)
	sort.Strings(level)

	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, sha256Hex(left+right))
		}
		level = next
	}

	return level[0]
}

// GenerateMerkleProof builds an inclusion proof for targetHash, byte-identical
// to generateMerkleProof in attribution.ts. It returns nil when the leaf set is
// empty or the target is not present. The sibling-selection and odd-node logic
// match the reference exactly so a Go proof recomputes the same root.
func GenerateMerkleProof(leafHashes []string, targetHash string) *MerkleProof {
	if len(leafHashes) == 0 {
		return nil
	}

	sorted := make([]string, len(leafHashes))
	copy(sorted, leafHashes)
	sort.Strings(sorted)

	targetIndex := indexOf(sorted, targetHash)
	if targetIndex == -1 {
		return nil
	}

	proof := []MerkleProofNode{}
	level := sorted
	index := targetIndex

	for len(level) > 1 {
		var sibling int
		if index%2 == 0 {
			sibling = index + 1
		} else {
			sibling = index - 1
		}

		if sibling < len(level) && sibling != index {
			pos := "left"
			if index%2 == 0 {
				pos = "right"
			}
			proof = append(proof, MerkleProofNode{Hash: level[sibling], Position: pos})
		} else {
			proof = append(proof, MerkleProofNode{Hash: level[index], Position: "right"})
		}

		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, sha256Hex(left+right))
		}

		level = next
		index = index / 2
	}

	return &MerkleProof{
		ReceiptHash: targetHash,
		Root:        level[0],
		Proof:       proof,
		Index:       targetIndex,
	}
}

// VerifyMerkleProof recomputes the root from the leaf hash and proof and
// compares it against the claimed root, byte-identical to verifyMerkleProof in
// attribution.ts: a "left" sibling hashes sha256(sibling + acc), a "right"
// sibling hashes sha256(acc + sibling).
func VerifyMerkleProof(proof MerkleProof) bool {
	hash := proof.ReceiptHash
	for _, node := range proof.Proof {
		if node.Position == "left" {
			hash = sha256Hex(node.Hash + hash)
		} else {
			hash = sha256Hex(hash + node.Hash)
		}
	}
	return hash == proof.Root
}

// verifyReportSignature checks the report signature over the canonical bytes of
// the report with its signature field removed. It re-canonicalizes through a
// map so the stripped-signature preimage matches the reference object-rest
// destructuring exactly.
func verifyReportSignature(report AttributionReport, publicKey string) bool {
	canon, err := jcs.Canonicalize(unsignedReport(report))
	if err != nil {
		return false
	}
	return verifyEd25519Hex([]byte(canon), report.Signature, publicKey)
}

// ReportSignedBytes returns the exact byte preimage that an AttributionReport
// signature covers: canonicalize(report minus its signature field). Callers can
// hash or sign these bytes; the verify side recomputes the same preimage.
func ReportSignedBytes(report AttributionReport) (string, error) {
	return jcs.Canonicalize(unsignedReport(report))
}

// canonicalizeGeneric projects v to its generic JSON form and canonicalizes it
// with the Phase-0 jcs core. It is the one canonicalization entry point this
// package uses for typed values.
func canonicalizeGeneric(v interface{}) (string, error) {
	return jcs.Canonicalize(toGeneric(v))
}

// SignReport signs an AttributionReport with the caller-supplied private key
// (32-byte Ed25519 seed hex) over canonicalize(report minus signature) and
// returns a copy of the report with its Signature field populated. This is the
// create half that pairs with VerifyAttributionReport. Key material is never
// logged; on error the returned error carries no key bytes.
func SignReport(report AttributionReport, privateKeyHex string) (AttributionReport, error) {
	g := unsignedReport(report)
	sig, err := keys.SignCanonical(g, privateKeyHex)
	if err != nil {
		return AttributionReport{}, err
	}
	report.Signature = sig
	return report, nil
}
