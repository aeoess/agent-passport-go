// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package commerce ports the Layer 7 agentic-commerce PRIMITIVES from the APS
// reference SDK (src/core/commerce.ts): the pure gate predicates, the commerce
// receipt signing and verification primitive, the commerce delegation factory,
// and the delegation-chain extractor.
//
// Scope is verify-first plus the two create primitives. This package holds NO
// global mutable state, computes NO analytics, and runs NO orchestration. The
// 6-gate orchestrator (commercePreflight), the ACP fetch wrappers, and the
// spend-summary analytics (getSpendSummary) live in the product gateway, not in
// the protocol SDK, and are intentionally absent here.
//
// Byte-faithfulness: every signed artifact uses the same preimage as the
// reference SDK, which is jcs.Canonicalize(artifact with its signature field
// removed). Signatures are Ed25519 over those canonical UTF-8 bytes, so a Go
// artifact signature equals the TypeScript signature byte for byte for the same
// deterministic inputs.
//
// Key-custody: private keys are caller-supplied. The package keeps no key state
// and never places key material in a log line or an error string.
package commerce

import (
	"fmt"
	"math"
	"strings"

	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

// CommerceScopes are the canonical commerce scopes, mirroring COMMERCE_SCOPES
// in src/core/commerce.ts.
var CommerceScopes = []string{
	"commerce:checkout",
	"commerce:browse",
	"commerce:purchase",
	"commerce:cancel",
}

// Money is an ACP money amount in the smallest currency unit. Mirrors ACPMoney
// in src/types/commerce.ts.
type Money struct {
	Amount   float64 `json:"amount"`   // smallest currency unit (cents)
	Currency string  `json:"currency"` // ISO 4217 (e.g. "usd")
}

// CommerceDelegation is a spend-scoped commerce grant. Mirrors CommerceDelegation
// in src/types/commerce.ts. This is the unsigned config object the reference SDK
// passes through its gate predicates; the signed wire artifact is the typed
// Delegation produced by CreateCommerceDelegation.
type CommerceDelegation struct {
	AgentID                string   `json:"agentId"`
	DelegationID           string   `json:"delegationId"`
	Scope                  []string `json:"scope"`
	SpendLimit             float64  `json:"spendLimit"`
	SpentAmount            float64  `json:"spentAmount"`
	Currency               string   `json:"currency"`
	ApprovedMerchants      []string `json:"approvedMerchants,omitempty"`
	RequireHumanApproval   *bool    `json:"requireHumanApproval,omitempty"`
	HumanApprovalThreshold *float64 `json:"humanApprovalThreshold,omitempty"`
}

// PreflightCheck is the result of a single gate predicate. Mirrors
// CommercePreflightCheck in src/types/commerce.ts. Each predicate is pure:
// same inputs produce the same output, with no I/O and no mutation.
type PreflightCheck struct {
	Check  string `json:"check"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// SignedPassport is the minimal signed-passport shape the passport gate reads.
// It mirrors the SignedPassport envelope in src/types/passport.ts: a passport
// body, its detached Ed25519 signature, and the optional bound-wallet list.
//
// The passport body is held as a generic map so the signed preimage is exactly
// jcs.Canonicalize(passport) regardless of which optional passport fields a
// caller populates. That matches signPassport in src/core/passport.ts, which
// signs canonicalize(passport).
type SignedPassport struct {
	Passport  map[string]interface{} `json:"passport"`
	Signature string                 `json:"signature"`
}

// BoundWallet is a signed binding between a passport and an external wallet
// address. Mirrors BoundWallet in src/v2/wallet-binding/types.ts. The
// binding_signature is Ed25519 over jcs.Canonicalize of the four-field binding
// payload, signed by the passport private key.
type BoundWallet struct {
	Chain            string `json:"chain"`
	Address          string `json:"address"`
	BoundAt          string `json:"bound_at"`
	BindingSignature string `json:"binding_signature"`
}

// WalletRef names a wallet to check against a passport binding.
type WalletRef struct {
	Chain   string
	Address string
}

// HasCommerceScope reports whether the delegation scope authorizes the required
// commerce scope. Mirrors hasCommerceScope in src/core/commerce.ts, which
// delegates to scopeAuthorizes (any granted scope covers the required scope).
func HasCommerceScope(delegation CommerceDelegation, required string) bool {
	return scopeAuthorizes(delegation.Scope, required)
}

// scopeAuthorizes reports whether any scope in the slice covers required.
// Mirrors scopeAuthorizes in src/core/delegation.ts; coverage uses the shared
// verify.ScopeCovers rule (exact, "*", prefix, and trailing ":*").
func scopeAuthorizes(scope []string, required string) bool {
	for _, s := range scope {
		if verify.ScopeCovers(s, required) {
			return true
		}
	}
	return false
}

// ── Gate Predicates ──
// Each predicate is pure. The product gateway composes these into its 6-gate
// preflight pipeline; this SDK exposes only the predicates.

// CheckPassportGate verifies the passport signature over its canonical body and
// returns a passport_valid check. Mirrors checkPassportGate in
// src/core/commerce.ts. The signed preimage is jcs.Canonicalize(passport),
// verified with verify.VerifyEd25519 against passport.publicKey.
func CheckPassportGate(signedPassport SignedPassport) PreflightCheck {
	agentID, _ := signedPassport.Passport["agentId"].(string)
	pubKey, _ := signedPassport.Passport["publicKey"].(string)

	valid := verifyPassportSignature(signedPassport, pubKey)

	detail := "Passport failed: invalid signature"
	if valid {
		detail = "Passport verified for " + agentID
	}
	return PreflightCheck{
		Check:  "passport_valid",
		Passed: valid,
		Detail: detail,
	}
}

// verifyPassportSignature checks the Ed25519 signature over the canonical
// passport body. This is the cryptographic core of verifyPassport
// (src/verification/verify.ts) without the optional issuer-countersignature and
// clock-skew paths, which the gateway layers on. Returns false on any decode or
// canonicalize failure rather than surfacing the error, matching the predicate
// contract that a gate never throws.
func verifyPassportSignature(sp SignedPassport, pubKey string) bool {
	if sp.Passport == nil || sp.Signature == "" || pubKey == "" {
		return false
	}
	canonical, err := jcsCanonicalize(sp.Passport)
	if err != nil {
		return false
	}
	return verify.VerifyEd25519([]byte(canonical), sp.Signature, pubKey)
}

// CheckScopeGate reports whether the agent holds commerce:checkout scope.
// Mirrors checkScopeGate in src/core/commerce.ts.
func CheckScopeGate(delegation CommerceDelegation) PreflightCheck {
	ok := HasCommerceScope(delegation, "commerce:checkout")
	detail := "Agent lacks commerce:checkout scope. Has: [" + joinScopes(delegation.Scope) + "]"
	if ok {
		detail = "Agent has commerce:checkout scope via delegation " + delegation.DelegationID
	}
	return PreflightCheck{
		Check:  "delegation_scope",
		Passed: ok,
		Detail: detail,
	}
}

// CheckSpendGate reports whether the estimated total fits within the delegation
// remaining budget (spendLimit minus spentAmount). Mirrors checkSpendGate in
// src/core/commerce.ts. Pure arithmetic; mutates nothing.
func CheckSpendGate(delegation CommerceDelegation, estimatedTotal Money) PreflightCheck {
	// Currency must match before comparing amounts: the SDK does NO conversion, so a EUR purchase
	// must not be charged against a USD budget. Compare case-insensitively (ISO 4217); a declared
	// mismatch denies. No constraint when a currency is absent on either side.
	if estimatedTotal.Currency != "" && delegation.Currency != "" &&
		!strings.EqualFold(estimatedTotal.Currency, delegation.Currency) {
		return PreflightCheck{
			Check:  "spend_limit",
			Passed: false,
			Detail: "Currency mismatch: purchase in " + estimatedTotal.Currency + " cannot be charged against a " + delegation.Currency + " budget",
		}
	}
	remaining := delegation.SpendLimit - delegation.SpentAmount
	ok := estimatedTotal.Amount <= remaining
	detail := "Purchase " + fmtNum(estimatedTotal.Amount) +
		" exceeds remaining budget of " + fmtNum(remaining) +
		" (limit: " + fmtNum(delegation.SpendLimit) +
		", spent: " + fmtNum(delegation.SpentAmount) + ")"
	if ok {
		detail = "Purchase " + fmtNum(estimatedTotal.Amount) +
			" within budget (" + fmtNum(remaining) + " remaining of " +
			fmtNum(delegation.SpendLimit) + ")"
	}
	return PreflightCheck{
		Check:  "spend_limit",
		Passed: ok,
		Detail: detail,
	}
}

// RecordSpend records a spend against a commerce delegation and returns a NEW
// CommerceDelegation with SpentAmount incremented. It is the stateless write
// primitive that pairs with CheckSpendGate: check before a purchase, record
// after it settles, and persist the returned value yourself. The SDK is
// by-value and stateless; it does not persist spend between calls, and
// cumulative enforcement across purchases is the caller's or the gateway's
// responsibility. It refuses a negative or non-finite amount, and a spend that
// would push SpentAmount past SpendLimit (so it doubles as a safe
// check-and-record). Mirrors recordSpend in src/core/commerce.ts.
// CommerceDelegation is unsigned, so this is signature-safe; the signed core
// Delegation does not carry a running spentAmount.
func RecordSpend(delegation CommerceDelegation, amount float64) (CommerceDelegation, error) {
	if math.IsNaN(amount) || math.IsInf(amount, 0) || amount < 0 {
		return delegation, fmt.Errorf("RecordSpend: amount must be a non-negative finite number, got %v", amount)
	}
	newSpent := delegation.SpentAmount + amount
	if newSpent > delegation.SpendLimit {
		return delegation, fmt.Errorf("RecordSpend: spend %v would exceed the spend limit (%v > %v, already spent %v)",
			amount, newSpent, delegation.SpendLimit, delegation.SpentAmount)
	}
	out := delegation
	out.SpentAmount = newSpent
	return out, nil
}

// CheckHumanApprovalThreshold returns a non-empty reason string when the
// estimated total requires human confirmation, or "" when it does not. Mirrors
// checkHumanApprovalThreshold in src/core/commerce.ts (which returns string |
// null). When the delegation does not require approval or has no threshold set,
// no approval is needed.
func CheckHumanApprovalThreshold(delegation CommerceDelegation, estimatedTotal Money) string {
	if delegation.RequireHumanApproval == nil || !*delegation.RequireHumanApproval {
		return ""
	}
	if delegation.HumanApprovalThreshold == nil {
		return ""
	}
	if estimatedTotal.Amount <= *delegation.HumanApprovalThreshold {
		return ""
	}
	return "Purchase of " + fmtNum(estimatedTotal.Amount) +
		" exceeds human approval threshold of " + fmtNum(*delegation.HumanApprovalThreshold) +
		". Human confirmation required."
}

// CheckMerchantGate reports whether the merchant is on the delegation approved
// list, or returns ok=false when no gate applies. Mirrors checkMerchantGate in
// src/core/commerce.ts, which returns null when there is no allowlist. Go has
// no null struct, so the boolean second return reports whether a check applies:
// false means "no merchant gate configured" (the TS null case).
func CheckMerchantGate(delegation CommerceDelegation, merchantName string) (PreflightCheck, bool) {
	if len(delegation.ApprovedMerchants) == 0 {
		return PreflightCheck{}, false
	}
	ok := contains(delegation.ApprovedMerchants, merchantName)
	detail := "Merchant \"" + merchantName + "\" is NOT on approved list: [" +
		joinScopes(delegation.ApprovedMerchants) + "]"
	if ok {
		detail = "Merchant \"" + merchantName + "\" is on approved list"
	}
	return PreflightCheck{
		Check:  "merchant_approved",
		Passed: ok,
		Detail: detail,
	}, true
}

// CheckWalletGate verifies that walletRef is bound to the passport. Mirrors
// checkWalletGate in src/core/commerce.ts, which delegates to verifyBoundWallet
// (src/v2/wallet-binding/bind.ts). A binding is valid when the passport carries
// a matching bound wallet whose binding_signature verifies under the passport
// public key over jcs.Canonicalize({passport_id, chain, address, bound_at}).
func CheckWalletGate(signedPassport SignedPassport, wallets []BoundWallet, walletRef WalletRef) PreflightCheck {
	agentID, _ := signedPassport.Passport["agentId"].(string)
	bound := verifyBoundWallet(signedPassport, wallets, walletRef)
	detail := "WALLET_NOT_BOUND: " + walletRef.Chain + ":" + walletRef.Address +
		" is not bound to passport " + agentID
	if bound {
		detail = "Wallet " + walletRef.Chain + ":" + walletRef.Address +
			" is bound to passport " + agentID
	}
	return PreflightCheck{
		Check:  "wallet_bound",
		Passed: bound,
		Detail: detail,
	}
}

// verifyBoundWallet is the verify primitive behind the wallet gate, ported from
// verifyBoundWallet in src/v2/wallet-binding/bind.ts. It finds the matching
// bound wallet, rebuilds the canonical binding payload, and checks the binding
// signature against the passport public key.
func verifyBoundWallet(sp SignedPassport, wallets []BoundWallet, ref WalletRef) bool {
	if len(wallets) == 0 {
		return false
	}
	agentID, _ := sp.Passport["agentId"].(string)
	pubKey, _ := sp.Passport["publicKey"].(string)
	if agentID == "" || pubKey == "" {
		return false
	}
	for _, w := range wallets {
		if w.Chain != ref.Chain || w.Address != ref.Address {
			continue
		}
		payload, err := jcsCanonicalize(map[string]interface{}{
			"passport_id": agentID,
			"chain":       w.Chain,
			"address":     w.Address,
			"bound_at":    w.BoundAt,
		})
		if err != nil {
			return false
		}
		return verify.VerifyEd25519([]byte(payload), w.BindingSignature, pubKey)
	}
	return false
}

// ── Commerce Delegation Factory ──

// CreateCommerceDelegationOptions configures CreateCommerceDelegation.
type CreateCommerceDelegationOptions struct {
	// DelegatedBy is the granting principal public key (the signer).
	DelegatedBy string
	// DelegatedTo is the agent receiving the grant.
	DelegatedTo string
	// DelegationID is the stable identifier for the grant.
	DelegationID string
	// SpendLimit is the maximum spend in the smallest currency unit.
	SpendLimit float64
	// Currency defaults to "usd" when empty.
	Currency string
	// AdditionalScopes are appended after the two default commerce scopes.
	AdditionalScopes []string
	// ExpiresAt and NotBefore are explicit ISO 8601 timestamps. Callers supply
	// them so the artifact is deterministic; there is no wall-clock source here.
	ExpiresAt string
	NotBefore string
	CreatedAt string
	// MaxDepth and CurrentDepth default to 1 and 0 when nil, matching the
	// reference delegation factory.
	MaxDepth     *int
	CurrentDepth *int
}

// CreateCommerceDelegation builds a signed, typed APS Delegation carrying the
// commerce scope set and signs it with the caller's private key.
//
// Per the package boundary this constructs the typed types.Delegation INLINE
// and signs via keys.SignArtifact; it does NOT import the sibling delegation
// package. The scope is ["commerce:checkout", "commerce:browse", ...additional],
// matching the scope the reference createCommerceDelegation sets
// (src/core/commerce.ts).
//
// The signed preimage is jcs.Canonicalize(delegation with the signature field
// removed), identical to createDelegation in src/core/delegation.ts over the
// same field set. privateKeyHex is the 32-byte Ed25519 seed in hex; it is never
// logged or echoed in an error.
func CreateCommerceDelegation(opts CreateCommerceDelegationOptions, privateKeyHex string) (types.Delegation, error) {
	currency := opts.Currency
	if currency == "" {
		currency = "usd"
	}
	scope := append([]string{"commerce:checkout", "commerce:browse"}, opts.AdditionalScopes...)

	maxDepth := 1
	if opts.MaxDepth != nil {
		maxDepth = *opts.MaxDepth
	}
	currentDepth := 0
	if opts.CurrentDepth != nil {
		currentDepth = *opts.CurrentDepth
	}
	spendLimit := opts.SpendLimit

	del := types.Delegation{
		DelegationID:   opts.DelegationID,
		DelegatedBy:    opts.DelegatedBy,
		DelegatedTo:    opts.DelegatedTo,
		Scope:          scope,
		SpendLimit:     &spendLimit,
		SpendLimitUnit: currency,
		MaxDepth:       &maxDepth,
		CurrentDepth:   &currentDepth,
		ExpiresAt:      opts.ExpiresAt,
		NotBefore:      opts.NotBefore,
		CreatedAt:      opts.CreatedAt,
	}

	// Build the generic map that the typed struct marshals to so the signed
	// preimage matches jcs.Canonicalize(delegation minus signature) exactly.
	body, err := structToMap(del)
	if err != nil {
		return types.Delegation{}, err
	}
	delete(body, "signature")

	sig, err := keys.SignArtifact(body, "signature", privateKeyHex)
	if err != nil {
		return types.Delegation{}, err
	}
	del.Signature = sig
	return del, nil
}

// ── Helpers ──

// ExtractDelegationChain returns the principal chain rooted at the passport
// public key, following each delegation back to its delegatedBy. Mirrors
// extractDelegationChain in src/core/commerce.ts. The first entry is the
// passport public key; subsequent entries are the distinct delegatedBy
// principals in order, with duplicates skipped.
func ExtractDelegationChain(sp SignedPassport, delegations []types.Delegation) []string {
	pubKey, _ := sp.Passport["publicKey"].(string)
	chain := []string{pubKey}
	for _, d := range delegations {
		if d.DelegatedBy != "" && !contains(chain, d.DelegatedBy) {
			chain = append(chain, d.DelegatedBy)
		}
	}
	return chain
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func joinScopes(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
