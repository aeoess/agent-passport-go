// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package types holds the APS protocol artifact shapes the verify core reads.
//
// JSON field names and tags are byte-faithful to the APS reference SDK
// TypeScript types (src/types and src/core). Optional fields use omitempty and
// pointer types where the reference type marks them optional, so a struct
// round-trips to the same JSON shape the reference SDK produces.
package types

// Passport is an APS agent passport. Identity bound to one principal.
// Mirrors AgentPassport in src/types/passport.ts.
type Passport struct {
	PassportID  string `json:"passportId,omitempty"`
	AgentID     string `json:"agentId"`
	PrincipalID string `json:"principalId,omitempty"`
	PublicKey   string `json:"publicKey"` // hex-encoded Ed25519 public key
	Grade       *int   `json:"grade,omitempty"`
	IssuedAt    string `json:"issuedAt,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// Delegation is a scoped grant of authority. Mirrors Delegation in
// src/core/delegation.ts. The signed bytes are canonicalizeJCS over the
// delegation with the signature field removed.
type Delegation struct {
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

// ActionSpec is the action block of an ActionIntent. Mirrors the inline
// action object in ActionIntent (src/types/policy.ts).
type ActionSpec struct {
	Type          string     `json:"type"`
	Target        string     `json:"target,omitempty"`
	ScopeRequired string     `json:"scopeRequired"`
	Spend         *SpendSpec `json:"spend,omitempty"`
}

// SpendSpec is the optional spend block on an action.
type SpendSpec struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// ActionIntent is a request an agent wants to perform. Mirrors ActionIntent in
// src/types/policy.ts. action_ref is computed from agentId, action.type,
// action.scopeRequired, and a second-precision timestamp.
type ActionIntent struct {
	IntentID     string     `json:"intentId,omitempty"`
	AgentID      string     `json:"agentId"`
	DelegationID string     `json:"delegationId,omitempty"`
	Action       ActionSpec `json:"action"`
	Context      string     `json:"context,omitempty"`
	ActionRef    string     `json:"actionRef,omitempty"`
	CreatedAt    string     `json:"createdAt"`
	Signature    string     `json:"signature,omitempty"`
}

// PolicyReceipt is a signed record of an evaluated decision. The verify core
// checks the signature over the canonical body and the hash references back to
// the authorizing delegation and decision.
type PolicyReceipt struct {
	ReceiptID      string `json:"receiptId,omitempty"`
	AgentID        string `json:"agentId,omitempty"`
	DelegationID   string `json:"delegationId,omitempty"`
	ActionRef      string `json:"actionRef,omitempty"`
	CompoundDigest string `json:"compoundDigest,omitempty"`
	DecisionType   string `json:"decisionType,omitempty"`
	CaptureMode    string `json:"captureMode,omitempty"`
	SelfAttested   *bool  `json:"selfAttested,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Signature      string `json:"signature,omitempty"`
}
