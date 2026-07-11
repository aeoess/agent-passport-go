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
//
// Crypto dependency: the honest resolved/verified split (see TraceBeneficiary)
// requires REAL ed25519 verification of the receipt and every delegation hop.
// Rather than reimplement the canonical crypto, this package imports the shared
// verifiers (delegation.VerifyDelegation, verify.VerifyCanonicalSignature, jcs,
// keys). TraceBeneficiary is therefore no longer a standalone lookup helper: an
// empty or forged signature makes `verified` false. The earlier note that this
// package was declared independent of the delegation package (so both build in
// parallel) no longer holds for the trace path; the Merkle and report helpers
// remain pure.
package attribution

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/aeoess/agent-passport-go/delegation"
	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
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
//
// Resolved and Verified are two DISTINCT, honestly-named claims, matching the TS
// reference (src/core/attribution.ts):
//
//	Resolved  Lookup success only. keyChain.length>1 AND the principal maps to a
//	          known beneficiary AND every hop's (from,to) pair maps to a known
//	          delegation record (delegationId != "unknown"). This makes NO
//	          cryptographic claim: a creator-supplied chain that happens to match
//	          known records is Resolved. Do not trust it as proof of authorization.
//
//	Verified  Real ed25519 verification. keyChain.length>1 AND the receipt
//	          signature is authentic against the executor key at the chain tail
//	          AND every hop has SOME matching delegation that passes
//	          delegation.VerifyDelegation. A forged, empty, or missing signature
//	          makes Verified false. This is the field to trust.
type BeneficiaryTrace struct {
	TraceID       string          `json:"traceId"`
	ReceiptID     string          `json:"receiptId"`
	ExecutorAgent string          `json:"executorAgent"`
	Beneficiary   string          `json:"beneficiary"`
	Chain         []DelegationHop `json:"chain"`
	TotalDepth    int             `json:"totalDepth"`
	Resolved      bool            `json:"resolved"`
	Verified      bool            `json:"verified"`
}

// TraceDelegation is the delegation shape TraceBeneficiary reads.
//
// PUBLIC API CHANGE (Beneficiary attribution parity): this struct was enriched
// from the old lookup-only shape (delegationId, delegatedBy, delegatedTo, scope)
// to carry the full field set that delegation.VerifyDelegation needs to check a
// hop cryptographically. Signature, ExpiresAt, NotBefore, CreatedAt, MaxDepth,
// CurrentDepth, and SpendLimit are the canonical delegation preimage fields
// (see delegation.canonicalMap); they were added so a hop can be VERIFIED, not
// just resolved. Callers constructing a TraceDelegation for a chain they want
// Verified=true on MUST populate at least Signature plus the fields the
// canonical delegation preimage includes (DelegatedBy, DelegatedTo, Scope, and
// any timestamps/depth that were signed). Lookup-only callers that only need
// Resolved may leave the crypto fields zero.
//
// The field set and JSON tags mirror types.Delegation so a types.Delegation
// projects to a TraceDelegation without renaming.
type TraceDelegation struct {
	DelegationID   string   `json:"delegationId"`
	DelegatedBy    string   `json:"delegatedBy"`
	DelegatedTo    string   `json:"delegatedTo"`
	Scope          []string `json:"scope"`
	SpendLimit     *float64 `json:"spendLimit,omitempty"`
	SpendLimitUnit string   `json:"spendLimitUnit,omitempty"`
	MaxDepth       *int     `json:"maxDepth,omitempty"`
	CurrentDepth   *int     `json:"currentDepth,omitempty"`
	ExpiresAt      string   `json:"expiresAt,omitempty"`
	NotBefore      string   `json:"notBefore,omitempty"`
	CreatedAt      string   `json:"createdAt,omitempty"`
	Signature      string   `json:"signature,omitempty"`
}

// toTypesDelegation projects a TraceDelegation to the types.Delegation shape the
// shared verifier consumes. The canonical delegation preimage
// (delegation.canonicalMap) reads exactly these fields, so verification uses the
// same bytes the delegator signed.
func (d TraceDelegation) toTypesDelegation() types.Delegation {
	return types.Delegation{
		DelegationID:   d.DelegationID,
		DelegatedBy:    d.DelegatedBy,
		DelegatedTo:    d.DelegatedTo,
		Scope:          d.Scope,
		SpendLimit:     d.SpendLimit,
		SpendLimitUnit: d.SpendLimitUnit,
		MaxDepth:       d.MaxDepth,
		CurrentDepth:   d.CurrentDepth,
		ExpiresAt:      d.ExpiresAt,
		NotBefore:      d.NotBefore,
		CreatedAt:      d.CreatedAt,
		Signature:      d.Signature,
	}
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
//
// It reports two DISTINCT claims (see BeneficiaryTrace):
//
//	Resolved  Lookup only: the principal maps to a known beneficiary, there is
//	          at least one hop, and every hop maps to a known delegation record.
//	          No cryptographic claim.
//
//	Verified  Real ed25519: at least one hop, the receipt signature is authentic
//	          against the executor at the chain tail, AND every hop has SOME
//	          matching delegation that passes delegation.VerifyDelegation. A hop
//	          with no valid delegation, or a forged/absent receipt signature,
//	          breaks Verified. This reuses the canonical verifiers and does not
//	          reimplement crypto.
//
// The reported chain still chooses ONE delegation per hop deterministically
// (valid-first, then by delegationId; the tail hop prefers the delegation the
// receipt was issued under, receipt.DelegationID), matching the TS selection so
// the reported lineage is stable regardless of which duplicate came first.
func TraceBeneficiary(
	traceID string,
	receipt ActionReceipt,
	delegations []TraceDelegation,
	beneficiaryMap map[string]BeneficiaryInfo,
) BeneficiaryTrace {
	chain := []DelegationHop{}
	keyChain := receipt.DelegationChain

	// everyHopAuthentic is a SECURITY concern kept independent of which
	// delegation gets reported: a hop is authentic iff SOME matching delegation
	// passes delegation.VerifyDelegation, so a re-used (from,to) key pair cannot
	// turn a valid lineage into verified=false, and a hop with no valid
	// delegation still breaks Verified.
	everyHopAuthentic := true
	for i := 0; i+1 < len(keyChain); i++ {
		from := keyChain[i]
		to := keyChain[i+1]
		isTail := i == len(keyChain)-2

		type match struct {
			del   TraceDelegation
			valid bool
		}
		matches := []match{}
		anyValid := false
		for _, d := range delegations {
			if d.DelegatedBy == from && d.DelegatedTo == to {
				valid := delegation.VerifyDelegation(d.toTypesDelegation())
				if valid {
					anyValid = true
				}
				matches = append(matches, match{del: d, valid: valid})
			}
		}
		if !anyValid {
			everyHopAuthentic = false
		}

		// Deterministic reported-chain selection: valid first, then by
		// delegationId ascending. Matches the TS sort comparator exactly.
		ordered := make([]match, len(matches))
		copy(ordered, matches)
		sort.SliceStable(ordered, func(a, b int) bool {
			if ordered[a].valid != ordered[b].valid {
				return ordered[a].valid
			}
			return ordered[a].del.DelegationID < ordered[b].del.DelegationID
		})

		var chosen *match
		if isTail {
			for k := range ordered {
				if ordered[k].del.DelegationID == receipt.DelegationID {
					chosen = &ordered[k]
					break
				}
			}
		}
		if chosen == nil && len(ordered) > 0 {
			chosen = &ordered[0]
		}

		delegationID := "unknown"
		scope := []string{}
		if chosen != nil {
			if chosen.del.DelegationID != "" {
				delegationID = chosen.del.DelegationID
			}
			if chosen.del.Scope != nil {
				scope = chosen.del.Scope
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

	beneficiaryOut := principalKey
	if hasBeneficiary && beneficiary.PrincipalID != "" {
		beneficiaryOut = beneficiary.PrincipalID
	}

	// resolved: lookup success only, no cryptographic claim.
	resolved := hasBeneficiary && len(keyChain) > 1
	if resolved {
		for _, h := range chain {
			if h.DelegationID == "unknown" {
				resolved = false
				break
			}
		}
	}

	// verified: real cryptographic verification. The receipt must be signed by
	// the executor at the tail of the chain, every hop must have a valid
	// delegation, and there must be at least one hop. Absent or forged
	// signatures => not verified.
	var executorKey string
	if len(keyChain) > 0 {
		executorKey = keyChain[len(keyChain)-1]
	}
	receiptAuthentic := len(keyChain) > 0 && verifyReceiptSignature(receipt, executorKey)
	verified := len(keyChain) > 1 && receiptAuthentic && everyHopAuthentic

	return BeneficiaryTrace{
		TraceID:       traceID,
		ReceiptID:     receipt.ReceiptID,
		ExecutorAgent: receipt.AgentID,
		Beneficiary:   beneficiaryOut,
		Chain:         chain,
		TotalDepth:    len(chain),
		Resolved:      resolved,
		Verified:      verified,
	}
}

// verifyReceiptSignature checks the receipt signature against agentPublicKey over
// the exact TS verifyReceipt preimage: canonicalize(receipt minus its signature
// field), verified with ed25519. It reuses verify.VerifyCanonicalSignature so the
// field-stripping and canonicalization have a single source of truth.
//
// TS verifyReceipt ALSO requires receipt.version === '1.1'. That version gate is
// enforced here so `verified` matches the TS receiptAuthentic result byte for
// byte: a receipt on any other version is not authentic.
func verifyReceiptSignature(receipt ActionReceipt, agentPublicKey string) bool {
	if receipt.Version != "1.1" {
		return false
	}
	g, ok := toGeneric(receipt).(map[string]interface{})
	if !ok {
		return false
	}
	return verify.VerifyCanonicalSignature(g, "signature", receipt.Signature, agentPublicKey)
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

// Domain separation (CVE-2012-2459 class). Leaves are hashed under a 0x00
// prefix and internal nodes under a 0x01 prefix so an internal node value can
// never be reinterpreted as a leaf. Odd nodes are promoted unchanged rather
// than duplicated (RFC 6962 style), so distinct receipt multisets (for
// example [a,b,c] versus [a,b,c,c]) can never fold to the same root.
// Byte-identical to hashLeafNode / hashInternalNode in attribution.ts.
func hashLeafNode(leaf string) string {
	return sha256Hex("\x00" + leaf)
}

func hashInternalNode(left, right string) string {
	return sha256Hex("\x01" + left + right)
}

// reduceMerkleLevel folds one tree level: adjacent pairs hash under the
// internal-node tag; a trailing odd node is promoted unchanged, never
// duplicated.
func reduceMerkleLevel(level []string) []string {
	next := make([]string, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 < len(level) {
			next = append(next, hashInternalNode(level[i], level[i+1]))
		} else {
			next = append(next, level[i])
		}
	}
	return next
}

// BuildMerkleRoot builds a Merkle root from leaf hashes, byte-identical to
// buildMerkleRoot in attribution.ts. Empty input returns sha256("empty");
// otherwise leaves are sorted ascending (string order) for determinism,
// hashed under the 0x00 leaf tag, then folded pairwise under the 0x01
// internal-node tag with an odd trailing node promoted unchanged. A single
// leaf therefore yields sha256(0x00 || leaf), not the leaf itself.
func BuildMerkleRoot(leafHashes []string) string {
	if len(leafHashes) == 0 {
		return sha256Hex("empty")
	}

	level := make([]string, len(leafHashes))
	copy(level, leafHashes)
	sort.Strings(level)
	for i := range level {
		level[i] = hashLeafNode(level[i])
	}

	for len(level) > 1 {
		level = reduceMerkleLevel(level)
	}

	return level[0]
}

// GenerateMerkleProof builds an inclusion proof for targetHash, byte-identical
// to generateMerkleProof in attribution.ts. It returns nil when the leaf set is
// empty or the target is not present. A lone odd node at any level is promoted
// unchanged: it has no sibling, so it contributes no proof node at that level.
// A single-leaf tree therefore yields an empty proof whose root is the
// domain-separated leaf hash.
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
	level := make([]string, len(sorted))
	for i, leaf := range sorted {
		level[i] = hashLeafNode(leaf)
	}
	index := targetIndex

	for len(level) > 1 {
		isRightChild := index%2 == 1
		siblingIndex := index + 1
		if isRightChild {
			siblingIndex = index - 1
		}

		if siblingIndex < len(level) {
			pos := "right"
			if isRightChild {
				pos = "left"
			}
			proof = append(proof, MerkleProofNode{Hash: level[siblingIndex], Position: pos})
		}

		level = reduceMerkleLevel(level)
		index = index / 2
	}

	return &MerkleProof{
		ReceiptHash: targetHash,
		Root:        level[0],
		Proof:       proof,
		Index:       targetIndex,
	}
}

// VerifyMerkleProof recomputes the root from the domain-separated leaf hash
// and proof path and compares it against the proof's embedded root,
// byte-identical to verifyMerkleProof in attribution.ts: a "left" sibling
// hashes sha256(0x01 || sibling || acc), a "right" sibling hashes
// sha256(0x01 || acc || sibling). The embedded root is claimed by the proof
// itself; callers holding an independently trusted root should use
// VerifyMerkleProofAgainstRoot.
func VerifyMerkleProof(proof MerkleProof) bool {
	return VerifyMerkleProofAgainstRoot(proof, proof.Root)
}

// VerifyMerkleProofAgainstRoot recomputes the root from the proof and compares
// it against a caller-supplied trusted root, ignoring the proof's embedded
// root field. An empty proof path recomputes to sha256(0x00 || leaf), so it is
// accepted only for the single-leaf tree whose committed root IS that value;
// against any multi-leaf root an empty proof is rejected.
func VerifyMerkleProofAgainstRoot(proof MerkleProof, trustedRoot string) bool {
	hash := hashLeafNode(proof.ReceiptHash)
	for _, node := range proof.Proof {
		if node.Position == "left" {
			hash = hashInternalNode(node.Hash, hash)
		} else {
			hash = hashInternalNode(hash, node.Hash)
		}
	}
	return hash == trustedRoot
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
