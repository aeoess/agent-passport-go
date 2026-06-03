// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package passport ports the APS passport protocol primitives from the
// reference TypeScript SDK (src/core/passport.ts and src/verification/verify.ts)
// to Go. It covers create, sign, countersign, and verify for agent passports,
// plus the signed-nonce challenge/response pair.
//
// Signed bytes match the reference exactly:
//
//   - The agent (self) signature covers canonical(passport): the full
//     AgentPassport object with no signature field present.
//   - The issuer countersignature covers canonical({passport, signature,
//     signedAt}): the SignedPassport minus its own issuerSignature.
//   - A challenge response signs the raw nonce string, not a canonical object.
//
// canonical() here is jcs.Canonicalize, which for the all-ASCII, no-null
// passport shape is byte-identical to the reference canonicalize() in
// src/core/canonical.ts. The cross-implementation test pins the real TS
// signature and canonical hash.
//
// Key custody: every signing entry point takes a caller-supplied private key
// hex (a 32-byte Ed25519 seed). This package holds no global mutable key
// state and never places key material in a log line or an error string.
package passport

import (
	"errors"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// RuntimeInfo mirrors RuntimeInfo in src/types/passport.ts.
type RuntimeInfo struct {
	Platform   string   `json:"platform"`
	Models     []string `json:"models"`
	ToolsCount int      `json:"toolsCount"`
	MemoryType string   `json:"memoryType"`
}

// ReputationScore mirrors ReputationScore in src/types/passport.ts. The
// optional penaltyDeductions field is a pointer so an unset score canonicalizes
// without it (the reference omits undefined keys).
type ReputationScore struct {
	Overall                 float64  `json:"overall"`
	CollaborationsCompleted int      `json:"collaborationsCompleted"`
	ProposalsSubmitted      int      `json:"proposalsSubmitted"`
	ProposalsApproved       int      `json:"proposalsApproved"`
	TokensContributed       float64  `json:"tokensContributed"`
	TasksCompleted          int      `json:"tasksCompleted"`
	PenaltyDeductions       *float64 `json:"penaltyDeductions,omitempty"`
	LastUpdated             string   `json:"lastUpdated"`
}

// AgentPassport mirrors AgentPassport in src/types/passport.ts. Only the fields
// the reference createPassport sets are modeled here. The Delegations and
// Metadata fields are intentionally generic so the issuer signature covers the
// exact same bytes the reference would for any embedded delegation shape.
type AgentPassport struct {
	Version      string                   `json:"version"`
	AgentID      string                   `json:"agentId"`
	AgentName    string                   `json:"agentName"`
	OwnerAlias   string                   `json:"ownerAlias"`
	PublicKey    string                   `json:"publicKey"`
	Mission      string                   `json:"mission"`
	Capabilities []string                 `json:"capabilities"`
	Runtime      RuntimeInfo              `json:"runtime"`
	CreatedAt    string                   `json:"createdAt"`
	ExpiresAt    string                   `json:"expiresAt"`
	NotBefore    string                   `json:"notBefore,omitempty"`
	VoteWeight   int                      `json:"voteWeight"`
	Reputation   ReputationScore          `json:"reputation"`
	Delegations  []map[string]interface{} `json:"delegations"`
	Metadata     map[string]interface{}   `json:"metadata"`
}

// IssuerSignature mirrors IssuerSignature in src/types/passport.ts.
type IssuerSignature struct {
	IssuerID        string `json:"issuerId"`
	IssuerPublicKey string `json:"issuerPublicKey"`
	Signature       string `json:"signature"`
	SignedAt        string `json:"signedAt"`
}

// SignedPassport mirrors SignedPassport in src/types/passport.ts. Only the
// fields the reference signPassport/countersignPassport set are modeled.
type SignedPassport struct {
	Passport        AgentPassport    `json:"passport"`
	Signature       string           `json:"signature"`
	SignedAt        string           `json:"signedAt"`
	IssuerSignature *IssuerSignature `json:"issuerSignature,omitempty"`
}

// VerificationResult mirrors VerificationResult in src/types/passport.ts.
type VerificationResult struct {
	Valid    bool           `json:"valid"`
	Errors   []string       `json:"errors"`
	Warnings []string       `json:"warnings"`
	Passport *AgentPassport `json:"passport,omitempty"`
}

// CreatePassportInput is the deterministic input set for CreatePassport. Unlike
// the reference createPassport, which generates a random keypair and reads the
// wall clock, this primitive takes a caller-supplied key and explicit
// timestamps so the artifact is reproducible and key custody stays with the
// caller. voteWeight is computed the same way the reference does.
type CreatePassportInput struct {
	AgentID      string
	AgentName    string
	OwnerAlias   string
	PublicKey    string
	Mission      string
	Capabilities []string
	Runtime      RuntimeInfo
	CreatedAt    string
	ExpiresAt    string
	NotBefore    string                   // optional; omitted when empty
	Reputation   ReputationScore          // caller supplies deterministic timestamps
	Delegations  []map[string]interface{} // nil becomes an empty slice
	Metadata     map[string]interface{}   // nil becomes an empty object
}

// capabilityWeights mirrors the table in src/core/passport.ts.
var capabilityWeights = map[string]float64{
	"code_execution":       0.5,
	"system_control":       0.5,
	"web_search":           0.2,
	"email_management":     0.3,
	"file_management":      0.3,
	"git_operations":       0.3,
	"browser_automation":   0.2,
	"voice_transcription":  0.1,
	"social_media_posting": 0.1,
}

// CalculateVoteWeight mirrors calculateVoteWeight in src/core/passport.ts:
// base 1, plus a per-capability bonus (0.1 default), rounded, floored at 1.
func CalculateVoteWeight(capabilities []string) int {
	bonus := 0.0
	for _, cap := range capabilities {
		if w, ok := capabilityWeights[cap]; ok {
			bonus += w
		} else {
			bonus += 0.1
		}
	}
	// Math.round in JS rounds half away from zero for positive values, which
	// for the non-negative weights here is the same as round-half-up.
	weight := int(roundHalfUp(1 + bonus))
	if weight < 1 {
		return 1
	}
	return weight
}

// roundHalfUp matches JavaScript Math.round for non-negative inputs.
func roundHalfUp(f float64) float64 {
	// Math.round(x) === Math.floor(x + 0.5) for the finite positive range used
	// by vote weights.
	intPart := float64(int64(f + 0.5))
	return intPart
}

// CreatePassport builds an AgentPassport from deterministic inputs and signs it
// with the caller's private key, returning the SignedPassport. voteWeight is
// derived from capabilities exactly as the reference does. signedAt must be
// supplied because the reference stamps it from the wall clock; pin it for
// reproducible artifacts. The private key never leaves this call.
func CreatePassport(in CreatePassportInput, privateKeyHex, signedAt string) (SignedPassport, error) {
	delegations := in.Delegations
	if delegations == nil {
		delegations = []map[string]interface{}{}
	}
	metadata := in.Metadata
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	p := AgentPassport{
		Version:      "1.0.0",
		AgentID:      in.AgentID,
		AgentName:    in.AgentName,
		OwnerAlias:   in.OwnerAlias,
		PublicKey:    in.PublicKey,
		Mission:      in.Mission,
		Capabilities: in.Capabilities,
		Runtime:      in.Runtime,
		CreatedAt:    in.CreatedAt,
		ExpiresAt:    in.ExpiresAt,
		NotBefore:    in.NotBefore,
		VoteWeight:   CalculateVoteWeight(in.Capabilities),
		Reputation:   in.Reputation,
		Delegations:  delegations,
		Metadata:     metadata,
	}
	return SignPassport(p, privateKeyHex, signedAt)
}

// SignPassport signs canonical(passport) with the caller's private key and
// wraps it in a SignedPassport. This is the exact preimage the reference
// signPassport uses (signedAt is not part of the agent signature). signedAt is
// recorded on the envelope; the reference stamps it from the wall clock, so
// callers pin it for reproducibility.
func SignPassport(passport AgentPassport, privateKeyHex, signedAt string) (SignedPassport, error) {
	obj, err := passportMap(passport)
	if err != nil {
		return SignedPassport{}, err
	}
	canonical, err := jcs.Canonicalize(obj)
	if err != nil {
		return SignedPassport{}, err
	}
	sig, err := keys.Sign(canonical, privateKeyHex)
	if err != nil {
		return SignedPassport{}, err
	}
	return SignedPassport{
		Passport:  passport,
		Signature: sig,
		SignedAt:  signedAt,
	}, nil
}

// CountersignPassport adds an issuer countersignature, the certificate-authority
// operation. The issuer signs canonical({passport, signature, signedAt}), the
// exact preimage the reference countersignPassport uses. issuerSignedAt is
// recorded on the IssuerSignature; the reference stamps it from the wall clock.
// The issuer public key is derived from the supplied issuer private key.
func CountersignPassport(signed SignedPassport, issuerPrivateKeyHex, issuerID, issuerSignedAt string) (SignedPassport, error) {
	if issuerID == "" {
		issuerID = "aeoess"
	}
	payload, err := issuerPayloadMap(signed)
	if err != nil {
		return SignedPassport{}, err
	}
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return SignedPassport{}, err
	}
	issuerPub, err := keys.PublicKeyFromPrivate(issuerPrivateKeyHex)
	if err != nil {
		return SignedPassport{}, err
	}
	issuerSig, err := keys.Sign(canonical, issuerPrivateKeyHex)
	if err != nil {
		return SignedPassport{}, err
	}
	out := signed
	out.IssuerSignature = &IssuerSignature{
		IssuerID:        issuerID,
		IssuerPublicKey: issuerPub,
		Signature:       issuerSig,
		SignedAt:        issuerSignedAt,
	}
	return out, nil
}

// VerifyIssuerSignature mirrors verifyIssuerSignature in src/core/passport.ts:
// the passport must carry an issuer signature whose issuerPublicKey equals the
// expected key, and that signature must verify over canonical({passport,
// signature, signedAt}).
func VerifyIssuerSignature(signed SignedPassport, issuerPublicKey string) bool {
	if signed.IssuerSignature == nil {
		return false
	}
	if signed.IssuerSignature.IssuerPublicKey != issuerPublicKey {
		return false
	}
	payload, err := issuerPayloadMap(signed)
	if err != nil {
		return false
	}
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		return false
	}
	return keys.Verify(canonical, signed.IssuerSignature.Signature, issuerPublicKey)
}

// VerifyPassport mirrors verifyPassport in src/verification/verify.ts. It checks
// the agent signature over canonical(passport), optional issuer countersignature
// against trustedIssuers, the expiry boundary, and presence of required fields.
// now is the verifier clock as an ISO 8601 string; an empty string skips the
// expiry and notBefore checks (callers without a deterministic clock omit it).
// This is the verify-first surface, so it never touches a private key.
func VerifyPassport(signed SignedPassport, trustedIssuers []string, now string) VerificationResult {
	errs := []string{}
	warnings := []string{}

	if signed.Signature == "" {
		return VerificationResult{Valid: false, Errors: []string{"Missing passport or signature"}, Warnings: warnings}
	}
	p := signed.Passport

	obj, err := passportMap(p)
	if err != nil {
		return VerificationResult{Valid: false, Errors: []string{"Cannot canonicalize passport"}, Warnings: warnings}
	}
	canonical, err := jcs.Canonicalize(obj)
	if err != nil {
		return VerificationResult{Valid: false, Errors: []string{"Cannot canonicalize passport"}, Warnings: warnings}
	}
	if !keys.Verify(canonical, signed.Signature, p.PublicKey) {
		errs = append(errs, "Invalid signature - passport may have been tampered with")
	}

	if len(trustedIssuers) > 0 {
		if signed.IssuerSignature == nil || signed.IssuerSignature.Signature == "" || signed.IssuerSignature.IssuerPublicKey == "" {
			errs = append(errs, "No issuer countersignature - passport is self-signed")
		} else if !contains(trustedIssuers, signed.IssuerSignature.IssuerPublicKey) {
			head := signed.IssuerSignature.IssuerPublicKey
			if len(head) > 16 {
				head = head[:16]
			}
			errs = append(errs, "Issuer "+head+"... not in trusted issuers list")
		} else {
			payload, perr := issuerPayloadMap(signed)
			if perr != nil {
				errs = append(errs, "Invalid issuer countersignature")
			} else {
				ic, cerr := jcs.Canonicalize(payload)
				if cerr != nil || !keys.Verify(ic, signed.IssuerSignature.Signature, signed.IssuerSignature.IssuerPublicKey) {
					errs = append(errs, "Invalid issuer countersignature")
				}
			}
		}
	} else {
		warnings = append(warnings, "No trustedIssuers provided - self-signed passports are accepted")
	}

	// Expiry check. Reference uses isExpired (expiresAt < now). We compare ISO
	// strings via time parsing when a clock is supplied.
	if now != "" {
		if expired, ok := isExpired(p.ExpiresAt, now); ok && expired {
			errs = append(errs, "Passport expired at "+p.ExpiresAt)
		}
		if p.NotBefore != "" {
			if before, ok := isBefore(now, p.NotBefore); ok && before {
				errs = append(errs, "Passport not valid before "+p.NotBefore)
			}
		}
	}

	if p.Version == "" {
		warnings = append(warnings, "No version field")
	}
	if p.AgentID == "" {
		errs = append(errs, "Missing agentId")
	}
	if p.PublicKey == "" {
		errs = append(errs, "Missing publicKey")
	}
	if len(p.Capabilities) == 0 {
		warnings = append(warnings, "No capabilities declared")
	}

	res := VerificationResult{
		Valid:    len(errs) == 0,
		Errors:   errs,
		Warnings: warnings,
	}
	if res.Valid {
		pp := p
		res.Passport = &pp
	}
	return res
}

// CanonicalBytes returns the exact signed-bytes preimage for the agent
// signature: jcs.Canonicalize of the AgentPassport. This is the pure-compute
// primitive a caller hashes or signs; it is byte-identical to the reference
// canonicalize(passport).
func CanonicalBytes(p AgentPassport) (string, error) {
	obj, err := passportMap(p)
	if err != nil {
		return "", err
	}
	return jcs.Canonicalize(obj)
}

// IssuerCanonicalBytes returns the signed-bytes preimage for the issuer
// countersignature: jcs.Canonicalize({passport, signature, signedAt}).
func IssuerCanonicalBytes(signed SignedPassport) (string, error) {
	payload, err := issuerPayloadMap(signed)
	if err != nil {
		return "", err
	}
	return jcs.Canonicalize(payload)
}

// passportMap converts an AgentPassport to the exact field set the reference
// canonicalizes. Optional fields are omitted when unset so the canonical bytes
// match the reference, which drops undefined keys.
func passportMap(p AgentPassport) (map[string]interface{}, error) {
	if p.Capabilities == nil {
		return nil, errors.New("passport: capabilities must not be nil")
	}
	rep := map[string]interface{}{
		"overall":                 p.Reputation.Overall,
		"collaborationsCompleted": p.Reputation.CollaborationsCompleted,
		"proposalsSubmitted":      p.Reputation.ProposalsSubmitted,
		"proposalsApproved":       p.Reputation.ProposalsApproved,
		"tokensContributed":       p.Reputation.TokensContributed,
		"tasksCompleted":          p.Reputation.TasksCompleted,
		"lastUpdated":             p.Reputation.LastUpdated,
	}
	if p.Reputation.PenaltyDeductions != nil {
		rep["penaltyDeductions"] = *p.Reputation.PenaltyDeductions
	}

	caps := make([]interface{}, len(p.Capabilities))
	for i, c := range p.Capabilities {
		caps[i] = c
	}
	models := make([]interface{}, len(p.Runtime.Models))
	for i, m := range p.Runtime.Models {
		models[i] = m
	}
	delegations := make([]interface{}, len(p.Delegations))
	for i, d := range p.Delegations {
		delegations[i] = d
	}
	metadata := map[string]interface{}{}
	for k, v := range p.Metadata {
		metadata[k] = v
	}

	obj := map[string]interface{}{
		"version":      p.Version,
		"agentId":      p.AgentID,
		"agentName":    p.AgentName,
		"ownerAlias":   p.OwnerAlias,
		"publicKey":    p.PublicKey,
		"mission":      p.Mission,
		"capabilities": caps,
		"runtime": map[string]interface{}{
			"platform":   p.Runtime.Platform,
			"models":     models,
			"toolsCount": p.Runtime.ToolsCount,
			"memoryType": p.Runtime.MemoryType,
		},
		"createdAt":   p.CreatedAt,
		"expiresAt":   p.ExpiresAt,
		"voteWeight":  p.VoteWeight,
		"reputation":  rep,
		"delegations": delegations,
		"metadata":    metadata,
	}
	if p.NotBefore != "" {
		obj["notBefore"] = p.NotBefore
	}
	return obj, nil
}

// issuerPayloadMap builds canonical({passport, signature, signedAt}), the exact
// preimage countersignPassport and verifyIssuerSignature sign over.
func issuerPayloadMap(signed SignedPassport) (map[string]interface{}, error) {
	pm, err := passportMap(signed.Passport)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"passport":  pm,
		"signature": signed.Signature,
		"signedAt":  signed.SignedAt,
	}, nil
}

func contains(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}
