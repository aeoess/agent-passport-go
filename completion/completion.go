// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package completion ports the APS bilateral completion-receipt primitives from
// the reference SDK (src/core/completion.ts). A completion receipt closes the
// permit-execute-complete loop: the permit receipt proves authorization, the
// completion receipt proves the execution outcome, and LinkPermitAndCompletion
// cryptographically binds the two by hash reference.
//
// Scope: protocol primitives only - create, verify, and the pure permit/
// completion hash link. This package owns no global mutable state and never
// holds key material. Private keys are passed in by the caller, are never
// logged, and never appear in an error string (key-custody rule).
//
// Signed-bytes contract (byte-identical to the TS reference): the signature is
// Ed25519 over the legacy canonical form (src/core/canonical.ts canonicalize,
// which sorts keys by UTF-16 code unit and strips null/undefined object
// values) of the receipt body with its signature field removed. The completion
// body carries no null fields, so that legacy form equals strict RFC 8785 JCS;
// this package therefore uses the shared jcs core for both signing and hashing
// and produces the same canonical bytes as the reference.
package completion

import (
	"errors"
	"sort"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// validResults is the closed taxonomy of executionResult values, matching
// VALID_RESULTS in the reference SDK.
var validResults = map[string]struct{}{
	"success": {},
	"failure": {},
	"partial": {},
	"timeout": {},
}

// ValidExecutionResults returns the closed set of allowed executionResult
// values, in a stable order, for callers that want to surface or validate them.
func ValidExecutionResults() []string {
	out := make([]string, 0, len(validResults))
	for k := range validResults {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ArtifactCitation is one citation referenced from a completion receipt. It
// points at an attribution receipt by id and repeats the cited content and
// principal so tampering with the receipt alone cannot silently swap out what
// was cited. Field tags match ArtifactCitation in the reference SDK
// (src/v2/attribution-consent/types.ts).
type ArtifactCitation struct {
	ReceiptID       string `json:"receipt_id"`
	CitedPrincipal  string `json:"cited_principal"`
	CitationContent string `json:"citation_content"`
}

// CompletionReceiptOptions are the inputs to CreateCompletionReceipt. It mirrors
// CompletionReceiptOptions in the reference SDK, with two adjustments for a
// deterministic, key-custody-clean Go surface:
//
//   - CompletionID and SignedAt are caller-supplied. The TS reference fills
//     these internally from uuidv4() and new Date(); making them explicit lets
//     a caller (and the cross-impl test) reproduce an exact signed body. When
//     CompletionID is empty CreateCompletionReceipt returns an error rather than
//     inventing randomness, keeping the package free of a hidden entropy source.
//   - PrivateKey is the 32-byte Ed25519 seed hex, never retained or logged.
type CompletionReceiptOptions struct {
	CompletionID      string
	PermitReceiptHash string
	ExecutionResult   string
	ResultSummary     string
	ResultHash        string
	ExecutedAt        string
	DurationMs        int64
	SignedAt          string
	PrivateKey        string
	// Citations are optional AttributionConsent citations. When present they
	// are part of the signed body and VerifyCompletionReceipt requires matching
	// receipts to be supplied.
	Citations []ArtifactCitation
}

// CompletionReceipt is a signed record of an execution outcome bound to a permit
// receipt by hash. Field tags match CompletionReceipt in the reference SDK so
// the struct round-trips to the same JSON shape.
type CompletionReceipt struct {
	CompletionID      string             `json:"completionId"`
	PermitReceiptHash string             `json:"permitReceiptHash"`
	ExecutionResult   string             `json:"executionResult"`
	ResultSummary     string             `json:"resultSummary"`
	ResultHash        string             `json:"resultHash"`
	ExecutedAt        string             `json:"executedAt"`
	DurationMs        int64              `json:"durationMs"`
	SignedAt          string             `json:"signedAt"`
	Signature         string             `json:"signature"`
	Citations         []ArtifactCitation `json:"citations,omitempty"`
}

var (
	errCompletionID = errors.New("completion: completionId required")
	errPermitHash   = errors.New("completion: permitReceiptHash required")
	errBadResult    = errors.New("completion: executionResult must be one of failure, partial, success, timeout")
	errExecutedAt   = errors.New("completion: executedAt required")
	errPrivateKey   = errors.New("completion: privateKey required")
	errNilReceipt   = errors.New("completion: receipt is nil")
	errNilPermit    = errors.New("completion: permit receipt is nil")
)

// receiptBody builds the unsigned body map exactly as the reference SDK does
// (createCompletionReceipt body literal): every scalar field is always present
// (defaulting to "" or 0), and citations are included only when non-empty.
// This is the precise object that gets canonicalized and signed.
func receiptBody(r *CompletionReceipt) map[string]interface{} {
	body := map[string]interface{}{
		"completionId":      r.CompletionID,
		"permitReceiptHash": r.PermitReceiptHash,
		"executionResult":   r.ExecutionResult,
		"resultSummary":     r.ResultSummary,
		"resultHash":        r.ResultHash,
		"executedAt":        r.ExecutedAt,
		"durationMs":        r.DurationMs,
		"signedAt":          r.SignedAt,
	}
	if len(r.Citations) > 0 {
		cites := make([]interface{}, 0, len(r.Citations))
		for _, c := range r.Citations {
			cites = append(cites, map[string]interface{}{
				"receipt_id":       c.ReceiptID,
				"cited_principal":  c.CitedPrincipal,
				"citation_content": c.CitationContent,
			})
		}
		body["citations"] = cites
	}
	return body
}

// CreateCompletionReceipt builds and signs a completion receipt. The signed
// bytes are jcs.Canonicalize(body), where body is the receipt without its
// signature field, matching createCompletionReceipt in the reference SDK byte
// for byte. The private key is the caller-supplied 32-byte seed hex; it is not
// retained, logged, or placed in any error string.
func CreateCompletionReceipt(opts CompletionReceiptOptions) (CompletionReceipt, error) {
	if opts.CompletionID == "" {
		return CompletionReceipt{}, errCompletionID
	}
	if opts.PermitReceiptHash == "" {
		return CompletionReceipt{}, errPermitHash
	}
	if _, ok := validResults[opts.ExecutionResult]; !ok {
		return CompletionReceipt{}, errBadResult
	}
	if opts.ExecutedAt == "" {
		return CompletionReceipt{}, errExecutedAt
	}
	if opts.PrivateKey == "" {
		return CompletionReceipt{}, errPrivateKey
	}

	r := CompletionReceipt{
		CompletionID:      opts.CompletionID,
		PermitReceiptHash: opts.PermitReceiptHash,
		ExecutionResult:   opts.ExecutionResult,
		ResultSummary:     opts.ResultSummary,
		ResultHash:        opts.ResultHash,
		ExecutedAt:        opts.ExecutedAt,
		DurationMs:        opts.DurationMs,
		SignedAt:          opts.SignedAt,
		Citations:         opts.Citations,
	}

	body := receiptBody(&r)
	sig, err := keys.SignArtifact(body, "signature", opts.PrivateKey)
	if err != nil {
		return CompletionReceipt{}, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyResult mirrors the { valid, errors } shape the reference SDK returns.
type VerifyResult struct {
	Valid  bool
	Errors []string
}

// VerifyCompletionReceipt checks a completion receipt against publicKeyHex,
// matching verifyCompletionReceipt in the reference SDK: it verifies the
// Ed25519 signature over the canonical unsigned body, checks the required
// fields, and validates the executionResult taxonomy.
//
// Citation handling: when the receipt carries citations, the reference SDK calls
// checkArtifactCitations, which performs structural checks (a receipt must be
// supplied for each citation, citation content and principal must match, and no
// receipt id may be cited twice) and then a full AttributionConsent signature/
// expiry verification. Per the package boundary, the AttributionConsent
// signature machinery lives in the attribution sibling package and is not
// reimplemented here. This function performs the structural citation checks
// against the supplied attribution receipts and surfaces the same error
// messages; it deliberately does not re-verify attribution-receipt signatures.
// Callers that need full AttributionConsent validation run the attribution
// package's verifier on the receipts first. See the package boundary notes.
func VerifyCompletionReceipt(receipt *CompletionReceipt, publicKeyHex string, attributionReceipts []AttributionReceipt) VerifyResult {
	var errs []string
	if receipt == nil {
		return VerifyResult{Valid: false, Errors: []string{errNilReceipt.Error()}}
	}

	body := receiptBody(receipt)
	if !verify.VerifyCanonicalSignature(body, "signature", receipt.Signature, publicKeyHex) {
		errs = append(errs, "Invalid completion receipt signature")
	}

	if receipt.CompletionID == "" {
		errs = append(errs, "Missing completionId")
	}
	if receipt.PermitReceiptHash == "" {
		errs = append(errs, "Missing permitReceiptHash")
	}
	if _, ok := validResults[receipt.ExecutionResult]; !ok {
		errs = append(errs, "Invalid executionResult: "+receipt.ExecutionResult)
	}

	if len(receipt.Citations) > 0 {
		if attributionReceipts == nil {
			errs = append(errs, "citations present but no receipts supplied")
		} else if reason := checkArtifactCitationsStructural(receipt.Citations, attributionReceipts); reason != "" {
			errs = append(errs, "AttributionConsent: "+reason)
		}
	}

	return VerifyResult{Valid: len(errs) == 0, Errors: errs}
}

// LinkResult mirrors the linkPermitAndCompletion return shape.
type LinkResult struct {
	Linked               bool
	PermitHash           string
	CompletionClaimsHash string
	Errors               []string
}

// LinkPermitAndCompletion cryptographically binds a permit receipt to a
// completion receipt. It hashes the canonicalized permit receipt (its signature
// field stripped first) and compares that hash to the permitReceiptHash the
// completion claims, matching linkPermitAndCompletion in the reference SDK. The
// permit receipt is supplied as a generic map so this primitive stays
// independent of any specific permit/decision struct.
func LinkPermitAndCompletion(permitReceipt map[string]interface{}, completionReceipt *CompletionReceipt) (LinkResult, error) {
	if permitReceipt == nil {
		return LinkResult{}, errNilPermit
	}
	if completionReceipt == nil {
		return LinkResult{}, errNilReceipt
	}

	rest := make(map[string]interface{}, len(permitReceipt))
	for k, v := range permitReceipt {
		if k == "signature" {
			continue
		}
		rest[k] = v
	}
	permitHash, err := jcs.CanonicalHash(rest)
	if err != nil {
		return LinkResult{}, err
	}

	completionClaimsHash := completionReceipt.PermitReceiptHash

	var errs []string
	if permitHash != completionClaimsHash {
		errs = append(errs, "Hash mismatch: permit receipt hashes to "+permitHash+", completion claims "+completionClaimsHash)
	}

	return LinkResult{
		Linked:               len(errs) == 0,
		PermitHash:           permitHash,
		CompletionClaimsHash: completionClaimsHash,
		Errors:               errs,
	}, nil
}

// AttributionReceipt carries only the fields the structural citation check
// needs (id, cited principal, citation content). It is a minimal local shape so
// the package does not depend on the attribution sibling. The full attribution
// receipt has additional signature and validity fields verified by the
// attribution package.
type AttributionReceipt struct {
	ID              string
	CitedPrincipal  string
	CitationContent string
}

// checkArtifactCitationsStructural mirrors the structural half of
// checkArtifactCitations in the reference SDK: each citation must reference a
// supplied receipt, the citation content and principal must match that receipt,
// and no receipt id may be cited more than once. It returns an empty string on
// success or the same human-readable failure reason the reference emits. It does
// not perform AttributionConsent signature or expiry verification (boundary).
func checkArtifactCitationsStructural(citations []ArtifactCitation, receipts []AttributionReceipt) string {
	byID := make(map[string]AttributionReceipt, len(receipts))
	for _, r := range receipts {
		byID[r.ID] = r
	}
	seen := make(map[string]struct{}, len(citations))
	for _, c := range citations {
		if _, dup := seen[c.ReceiptID]; dup {
			return "replay: receipt " + c.ReceiptID + " cited more than once in this artifact"
		}
		seen[c.ReceiptID] = struct{}{}

		r, ok := byID[c.ReceiptID]
		if !ok {
			return "no receipt provided for citation " + c.ReceiptID
		}
		if r.CitationContent != c.CitationContent {
			return "citation content mismatch for receipt " + c.ReceiptID
		}
		if r.CitedPrincipal != c.CitedPrincipal {
			return "cited principal mismatch for receipt " + c.ReceiptID
		}
	}
	return ""
}
