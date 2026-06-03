// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package intoto wraps the AEOESS decision-receipt predicate in an in-toto
// Statement v1 envelope, byte/hex-identical to the APS reference SDK
// src/decisionReceipt.ts.
//
// A Decision Receipt v0.1 is emitted as a DSSE-style signed Statement:
//
//	{ payloadType, payload: <JCS-canonical Statement string>,
//	  signatures: [{ keyid, sig }] }
//
// The payload is jcs.Canonicalize(IntotoStatement); the signature is an
// Ed25519 signature over exactly those payload bytes (no field stripping). A
// verifier canonicalizes the parsed Statement, checks it equals the payload,
// then verifies the signature over the payload bytes.
//
// Scope: pure protocol primitives only - create (EmitDecisionReceipt), parse
// (ParseDecisionReceiptStatement), and pure compute (ComputeDelegationChainRoot).
// No network, no mutable state, no gateway dependency, no analytics.
//
// Key-custody rules, non-negotiable:
//   - The signer private key is passed in by the caller. The package keeps no
//     global mutable key state.
//   - Key material is never logged and never placed in an error string.
//
// Artifacts (intent, receipt, delegation chain) are accepted as generic decoded
// JSON values (typically map[string]interface{} / []interface{}). This keeps
// the JCS canonical bytes byte-identical to whatever the reference SDK
// serializes, which is what the cross-impl digests depend on.
package intoto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// DecisionReceiptPredicateType is the canonical predicate identifier for the
// in-toto Decision Receipt v0.1. Matches DECISION_RECEIPT_PREDICATE_TYPE in the
// reference SDK and the parallel Python emission in hermes-aps-delegation.
const DecisionReceiptPredicateType = "https://veritasacta.com/attestation/decision-receipt/v0.1"

// IntotoStatementV1 is the in-toto Statement envelope type
// (INTOTO_STATEMENT_V1 in the reference SDK).
const IntotoStatementV1 = "https://in-toto.io/Statement/v1"

// IntotoPayloadType is the DSSE payloadType for in-toto Statements
// (INTOTO_PAYLOAD_TYPE in the reference SDK).
const IntotoPayloadType = "application/vnd.in-toto+json"

// DefaultAPSVersion is the apsVersion stamped into the predicate metadata when
// EmitInput.APSVersion is empty. Matches the reference SDK default.
const DefaultAPSVersion = "2.3.0-alpha"

var (
	errNilIntent   = errors.New("intoto: intent is required")
	errBadIntent   = errors.New("intoto: intent must expose action.type and intentId as strings")
	errEmptySigKey = errors.New("intoto: signerKeyId is required")
)

// EmitInput is the input contract for EmitDecisionReceipt. It mirrors the
// reference SDK EmitDecisionReceiptInput.
//
// Intent, Receipt, and DelegationChain are accepted as generic decoded JSON
// values so their JCS canonical bytes match the reference SDK exactly. Pass the
// same map[string]interface{} / []interface{} shapes the SDK would produce.
type EmitInput struct {
	// Intent is the agent's signed request (the full ActionIntent object). Its
	// JCS digest becomes both the subject digest and predicate.intentDigest.
	Intent interface{}
	// Receipt is the acting agent's signed ActionReceipt. Its JCS digest
	// becomes predicate.receiptDigest.
	Receipt interface{}
	// DelegationChain is the ordered root-to-leaf delegation chain that
	// authorized the action (typically a []interface{} of delegation objects).
	// delegationChainRoot = SHA-256(JCS(chain)); delegationDepth = len(chain).
	DelegationChain []interface{}
	// EpistemicClaims are the typed epistemic labels for the four claim classes.
	EpistemicClaims EpistemicClaims
	// Verdict is the policy decision: "permit", "deny", or "narrow".
	Verdict string
	// Reason is the human-readable decision explanation.
	Reason string
	// PolicyID is the policy identifier (e.g. "floor-validator-v1").
	PolicyID string
	// FloorVersion is the floor version used; it feeds the policyDigest preimage
	// { version: FloorVersion, policyId: PolicyID }.
	FloorVersion string
	// IssuerID is the issuer DID or stable identifier for the signing party.
	IssuerID string
	// IssuedAt is the ISO 8601 issuance timestamp. The reference SDK uses
	// new Date().toISOString(), which renders millisecond precision (a trailing
	// .000Z for whole seconds). Supply the exact string you want signed; this
	// package never reads a wall clock.
	IssuedAt string
	// ActionRef is the optional content-addressed request identity copied into
	// metadata.actionRef. The reference SDK always includes the actionRef key in
	// metadata, emitting JSON null when the intent carried no actionRef, so this
	// package always writes the key (null when empty) to stay byte-identical.
	ActionRef string
	// APSVersion is the APS version string. Empty means DefaultAPSVersion.
	APSVersion string
	// SignerPrivateKey is the Ed25519 private key (32-byte seed) as hex.
	// Caller-supplied; never retained, logged, or echoed in errors.
	SignerPrivateKey string
	// SignerKeyID is the stable identifier for the signing key (the DSSE keyid).
	SignerKeyID string
}

// EpistemicClaims carries the typed epistemic labels for the four claim classes
// a v2.3 decision receipt asserts. Field tags fix the JSON key names; the JCS
// layer sorts keys, so on-the-wire order is deterministic regardless of struct
// order.
type EpistemicClaims struct {
	PolicyEvaluated   string `json:"policy_evaluated"`
	AuthorityConsumed string `json:"authority_consumed"`
	ScopeWithinBounds string `json:"scope_within_bounds"`
	EffectOccurred    string `json:"effect_occurred"`
}

// DSSESignature is a single DSSE signature entry.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Digest is the in-toto { sha256: <hex> } resource-descriptor digest shape.
type Digest struct {
	SHA256 string `json:"sha256"`
}

// DecisionReceiptEnvelope is the DSSE-style signed envelope returned by
// EmitDecisionReceipt. Payload is the JCS-canonical JSON of the in-toto
// Statement; the signature covers exactly those bytes.
type DecisionReceiptEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
	// Digest is a convenience field (not part of DSSE): SHA-256 of the payload
	// bytes, exposed under the JSON key "_digest" to match the reference SDK.
	Digest Digest `json:"_digest"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// digestOf returns { sha256: SHA-256(JCS(obj)) }, matching the SDK digestOf.
func digestOf(obj interface{}) (Digest, error) {
	canon, err := jcs.Canonicalize(obj)
	if err != nil {
		return Digest{}, err
	}
	return Digest{SHA256: sha256Hex([]byte(canon))}, nil
}

// ComputeDelegationChainRoot returns the v2.3 bilateral delegation chain root:
// SHA-256 of the JCS canonicalization of the chain array. Deterministic across
// re-emissions and byte-identical to the reference SDK computeDelegationChainRoot
// and the Python hermes-aps-delegation emitter.
func ComputeDelegationChainRoot(chain []interface{}) (string, error) {
	canon, err := jcs.Canonicalize(chain)
	if err != nil {
		return "", err
	}
	return sha256Hex([]byte(canon)), nil
}

// intentField extracts a top-level string field from a map-shaped intent. It is
// used only to build the human-readable subject name; the cryptographic intent
// digest always canonicalizes the full intent object.
func intentField(intent interface{}, key string) (string, bool) {
	m, ok := intent.(map[string]interface{})
	if !ok {
		return "", false
	}
	v, ok := m[key].(string)
	return v, ok
}

func intentActionType(intent interface{}) (string, bool) {
	m, ok := intent.(map[string]interface{})
	if !ok {
		return "", false
	}
	action, ok := m["action"].(map[string]interface{})
	if !ok {
		return "", false
	}
	t, ok := action["type"].(string)
	return t, ok
}

// BuildStatement assembles the in-toto Statement value (as the generic map the
// JCS layer canonicalizes) without signing. Exposed so verifiers and tests can
// reproduce the exact preimage. The returned value canonicalizes byte-identical
// to the reference SDK IntotoStatement.
func BuildStatement(in EmitInput) (map[string]interface{}, error) {
	if in.Intent == nil {
		return nil, errNilIntent
	}
	actionType, ok1 := intentActionType(in.Intent)
	intentID, ok2 := intentField(in.Intent, "intentId")
	if !ok1 || !ok2 {
		return nil, errBadIntent
	}

	apsVersion := in.APSVersion
	if apsVersion == "" {
		apsVersion = DefaultAPSVersion
	}

	intentDigest, err := digestOf(in.Intent)
	if err != nil {
		return nil, err
	}
	receiptDigest, err := digestOf(in.Receipt)
	if err != nil {
		return nil, err
	}
	// policyDigest preimage matches the SDK: { version, policyId }.
	policyDigest, err := digestOf(map[string]interface{}{
		"version":  in.FloorVersion,
		"policyId": in.PolicyID,
	})
	if err != nil {
		return nil, err
	}
	chainRoot, err := ComputeDelegationChainRoot(in.DelegationChain)
	if err != nil {
		return nil, err
	}

	// metadata.actionRef is always present. The SDK writes the key from
	// intent.actionRef, which canonicalizes to null when undefined; mirror that
	// by emitting a nil value (JCS null) when ActionRef is empty.
	var actionRefVal interface{}
	if in.ActionRef != "" {
		actionRefVal = in.ActionRef
	} else {
		actionRefVal = nil
	}

	predicate := map[string]interface{}{
		"decision":            in.Verdict,
		"reason":              in.Reason,
		"policyId":            in.PolicyID,
		"policyDigest":        map[string]interface{}{"sha256": policyDigest.SHA256},
		"delegationChainRoot": map[string]interface{}{"sha256": chainRoot},
		"delegationDepth":     len(in.DelegationChain),
		"epistemicClaims": map[string]interface{}{
			"policy_evaluated":    in.EpistemicClaims.PolicyEvaluated,
			"authority_consumed":  in.EpistemicClaims.AuthorityConsumed,
			"scope_within_bounds": in.EpistemicClaims.ScopeWithinBounds,
			"effect_occurred":     in.EpistemicClaims.EffectOccurred,
		},
		"issuerId":      in.IssuerID,
		"issuedAt":      in.IssuedAt,
		"intentDigest":  map[string]interface{}{"sha256": intentDigest.SHA256},
		"receiptDigest": map[string]interface{}{"sha256": receiptDigest.SHA256},
		"metadata": map[string]interface{}{
			"framework":   "aps",
			"receiptKind": "decision_receipt",
			"apsVersion":  apsVersion,
			"actionRef":   actionRefVal,
		},
	}

	subject := []interface{}{
		map[string]interface{}{
			"name":   "aps-action:" + actionType + ":" + intentID,
			"digest": map[string]interface{}{"sha256": intentDigest.SHA256},
		},
	}

	statement := map[string]interface{}{
		"_type":         IntotoStatementV1,
		"predicateType": DecisionReceiptPredicateType,
		"subject":       subject,
		"predicate":     predicate,
	}
	return statement, nil
}

// EmitDecisionReceipt emits an in-toto Decision Receipt v0.1 envelope.
//
// Pure function. Given an intent/receipt/decision triple and the delegation
// chain that authorized it, it produces a DSSE-style signed Statement whose
// predicate carries delegationChainRoot, delegationDepth, and the typed
// epistemicClaims. The payload string is jcs.Canonicalize(statement); the
// signature is Ed25519 over exactly those payload bytes.
func EmitDecisionReceipt(in EmitInput) (DecisionReceiptEnvelope, error) {
	if in.SignerKeyID == "" {
		return DecisionReceiptEnvelope{}, errEmptySigKey
	}
	statement, err := BuildStatement(in)
	if err != nil {
		return DecisionReceiptEnvelope{}, err
	}
	payload, err := jcs.Canonicalize(statement)
	if err != nil {
		return DecisionReceiptEnvelope{}, err
	}
	// Sign the canonical payload bytes directly (no field stripping), matching
	// sign(payload, signerPrivateKey) in the reference SDK.
	sig, err := keys.Sign(payload, in.SignerPrivateKey)
	if err != nil {
		return DecisionReceiptEnvelope{}, err
	}
	return DecisionReceiptEnvelope{
		PayloadType: IntotoPayloadType,
		Payload:     payload,
		Signatures:  []DSSESignature{{KeyID: in.SignerKeyID, Sig: sig}},
		Digest:      Digest{SHA256: sha256Hex([]byte(payload))},
	}, nil
}
