// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package delegation is the delegation issuing surface: create and sub-delegate
// scoped authority, and verify a delegation signature. Chain-narrowing and the
// scope matcher live in the verify package and are reused here, not forked.
//
// The signed-bytes preimage matches the reference SDK src/core/delegation.ts:
// the signature is over the canonical bytes of the delegation with its
// signature field removed. The reference signs with the legacy canonicalize();
// for a well-formed delegation (no null-valued keys, ASCII field names) that is
// byte-identical to jcs.Canonicalize, which this package uses. The cross-impl
// test pins the shared canonical bytes so any divergence fails loudly.
//
// Verify-first scope: the stateful revocation store (cascadeRevoke,
// getRevocation, clearStores, onRevocation) is NOT ported. Only the create and
// verify of a signed revocation record (see revocation.go) is in scope.
package delegation

import (
	"errors"
	"time"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/types"
	"github.com/aeoess/agent-passport-go/verify"
)

// CreateOptions are the inputs to CreateDelegation. The private key is supplied
// by the caller (no global key state). IDs and timestamps are explicit so
// issuance is deterministic and reproducible.
type CreateOptions struct {
	PrivateKey   string // delegator 32-byte seed hex
	DelegationID string
	DelegatedBy  string
	DelegatedTo  string
	Scope        []string
	SpendLimit   *float64
	// SpendLimitUnit labels SpendLimit. An empty unit alongside a SpendLimit
	// means the default unit "currency", matching the reference SDK.
	SpendLimitUnit string
	MaxDepth       int
	CurrentDepth   int
	ExpiresAt      string
	NotBefore      string
	CreatedAt      string
}

// canonicalMap builds the exact field set the reference SDK signs over. Optional
// fields are included only when present, matching the reference object shape.
func canonicalMap(d types.Delegation) map[string]interface{} {
	scope := make([]interface{}, len(d.Scope))
	for i, s := range d.Scope {
		scope[i] = s
	}
	m := map[string]interface{}{
		"delegationId": d.DelegationID,
		"delegatedTo":  d.DelegatedTo,
		"delegatedBy":  d.DelegatedBy,
		"scope":        scope,
	}
	// Optional timestamps are omitted when empty, matching the struct's
	// `omitempty` json tags. Including "expiresAt":"" here (the prior behavior)
	// signed a key the wire JSON drops, so a Go-issued delegation with an empty
	// optional timestamp did not round-trip: a verifier canonicalizing the
	// received (key-omitted) object computed different bytes.
	if d.ExpiresAt != "" {
		m["expiresAt"] = d.ExpiresAt
	}
	if d.NotBefore != "" {
		m["notBefore"] = d.NotBefore
	}
	if d.CreatedAt != "" {
		m["createdAt"] = d.CreatedAt
	}
	if d.SpendLimit != nil {
		m["spendLimit"] = *d.SpendLimit
	}
	if d.SpendLimitUnit != "" {
		m["spendLimitUnit"] = d.SpendLimitUnit
	}
	if d.MaxDepth != nil {
		m["maxDepth"] = float64(*d.MaxDepth)
	}
	if d.CurrentDepth != nil {
		m["currentDepth"] = float64(*d.CurrentDepth)
	}
	return m
}

// CreateDelegation builds a signed delegation. The delegator signs the canonical
// bytes of the delegation (signature field excluded).
func CreateDelegation(opts CreateOptions) (types.Delegation, error) {
	if opts.DelegatedBy == "" || opts.DelegatedTo == "" {
		return types.Delegation{}, errors.New("delegation: delegatedBy and delegatedTo are required")
	}
	maxD, curD := opts.MaxDepth, opts.CurrentDepth
	// A delegation must be self-consistent at issue. currentDepth is a position
	// in a chain, so it is never negative: a negative position buys extra hops
	// under any ceiling, which is how an eight-link chain fitted inside
	// maxDepth 2. And a delegation may not be minted already outside its own
	// ceiling; CreateDelegation(currentDepth: 5, maxDepth: 1) used to succeed.
	if curD < 0 {
		return types.Delegation{}, errors.New("delegation: currentDepth may not be negative")
	}
	if maxD < 0 {
		return types.Delegation{}, errors.New("delegation: maxDepth may not be negative")
	}
	if curD > maxD {
		return types.Delegation{}, errors.New("delegation: currentDepth exceeds maxDepth")
	}
	d := types.Delegation{
		DelegationID:   opts.DelegationID,
		DelegatedBy:    opts.DelegatedBy,
		DelegatedTo:    opts.DelegatedTo,
		Scope:          opts.Scope,
		SpendLimit:     opts.SpendLimit,
		SpendLimitUnit: opts.SpendLimitUnit,
		MaxDepth:       &maxD,
		CurrentDepth:   &curD,
		ExpiresAt:      opts.ExpiresAt,
		NotBefore:      opts.NotBefore,
		CreatedAt:      opts.CreatedAt,
	}
	sig, err := keys.SignArtifact(canonicalMap(d), "signature", opts.PrivateKey)
	if err != nil {
		return types.Delegation{}, err
	}
	d.Signature = sig
	return d, nil
}

// SubDelegateOptions narrows a parent delegation to a child. The child scope
// must be covered by the parent scope, the depth must stay within bounds, and
// the child is signed by the parent's delegatee key.
type SubDelegateOptions struct {
	Parent       types.Delegation
	PrivateKey   string // the parent's delegatee key (the new delegator)
	DelegationID string
	DelegatedTo  string
	Scope        []string
	SpendLimit   *float64
	// SpendLimitUnit labels SpendLimit. Leave it empty to inherit the parent's
	// unit; stating a different one is a conversion, which the narrowing layer
	// refuses.
	SpendLimitUnit string
	ExpiresAt      string
	NotBefore      string
	CreatedAt      string
	// Now is the evaluation time for the parent's validity window, RFC3339. Leave
	// it empty to use the real clock. Tests set it so issuance is deterministic.
	Now string
}

// statedSpendUnit is the unit a delegation asserts. A bare SpendLimit with no
// explicit SpendLimitUnit asserts the default unit "currency", matching the
// reference SDK (src/core/delegation.ts). An empty result means the delegation
// binds no spend dimension at all.
func statedSpendUnit(d types.Delegation) string {
	if d.SpendLimitUnit != "" {
		return d.SpendLimitUnit
	}
	if d.SpendLimit != nil {
		return "currency"
	}
	return ""
}

// SubDelegate validates monotonic narrowing against the parent, then issues the
// signed child. Narrowing uses verify.ScopeCovers and the bounds carried by the
// parent, matching the reference subDelegate refusal semantics.
//
// Every bound the caller omits is MATERIALIZED from the parent rather than left
// absent. A bounded ancestor facet must not become unconstrained because a
// sub-delegation call omitted the field, and the minter must never produce a
// chain this repo's own verifier refuses. The child therefore carries the
// parent's spend limit and unit, the parent's expiry (or the earlier of the two),
// and the parent's notBefore (or the later of the two).
func SubDelegate(opts SubDelegateOptions) (types.Delegation, error) {
	parent := opts.Parent
	now := time.Now().UTC()
	if opts.Now != "" {
		t, ok := verify.ParseTimestamp(opts.Now)
		if !ok {
			return types.Delegation{}, errors.New("delegation: Now is not a valid timestamp")
		}
		now = t
	}
	// Verify the parent before minting a child: signature AND validity window. Previously
	// SubDelegate trusted any parent struct, so a forged or invalid parent signature could mint an
	// authority-bearing child (parity with the Python sub_delegate parent check), and it consulted
	// no clock at all, so an expired or not-yet-valid parent could still mint.
	if err := VerifyDelegationAt(parent, now); err != nil {
		return types.Delegation{}, errors.New("delegation: cannot sub-delegate from an invalid parent: " + err.Error())
	}
	parentDepth := 0
	if parent.CurrentDepth != nil {
		parentDepth = *parent.CurrentDepth
	}
	if parentDepth < 0 {
		return types.Delegation{}, errors.New("delegation: parent currentDepth may not be negative")
	}
	newDepth := parentDepth + 1
	if parent.MaxDepth != nil && newDepth > *parent.MaxDepth {
		return types.Delegation{}, errors.New("delegation: depth limit exceeded")
	}
	for _, s := range opts.Scope {
		covered := false
		for _, ps := range parent.Scope {
			if verify.ScopeCovers(ps, s) {
				covered = true
				break
			}
		}
		if !covered {
			return types.Delegation{}, errors.New("delegation: scope violation, child scope not covered by parent")
		}
	}

	// Spend unit. Once the parent binds a unit, the child may not change it; a
	// declared currency conversion belongs at the payment-rails layer, not here.
	// A child may still introduce a unit on an otherwise unconstrained parent,
	// which is narrowing rather than conversion.
	parentUnit := statedSpendUnit(parent)
	childUnit := opts.SpendLimitUnit
	if childUnit == "" {
		childUnit = parentUnit
	}
	if parentUnit != "" && childUnit != parentUnit {
		return types.Delegation{}, errors.New("delegation: spend unit change, child must carry the parent spendLimitUnit unchanged")
	}
	// Spend ceiling. The cap and the inheritance apply only when parent and child
	// share a bounded budget in the same unit.
	sharesParentBudget := parentUnit != "" && childUnit == parentUnit && parent.SpendLimit != nil
	if sharesParentBudget && opts.SpendLimit != nil && *opts.SpendLimit > *parent.SpendLimit {
		return types.Delegation{}, errors.New("delegation: spend limit exceeds parent")
	}
	childLimit := opts.SpendLimit
	if childLimit == nil && sharesParentBudget {
		inherited := *parent.SpendLimit
		childLimit = &inherited
	}

	// Temporal narrowing. The child expiry is the earlier of the requested one
	// and the parent's; omitting it inherits the parent's rather than minting a
	// child with no expiry under a parent that has one.
	childExpiresAt := opts.ExpiresAt
	if parent.ExpiresAt != "" {
		pe, ok := verify.ParseTimestamp(parent.ExpiresAt)
		if !ok {
			return types.Delegation{}, errors.New("delegation: parent expiresAt is non-empty but invalid")
		}
		if childExpiresAt == "" {
			childExpiresAt = parent.ExpiresAt
		} else {
			ce, ok := verify.ParseTimestamp(childExpiresAt)
			if !ok {
				return types.Delegation{}, errors.New("delegation: expiresAt is non-empty but invalid")
			}
			if ce.After(pe) {
				childExpiresAt = parent.ExpiresAt
			}
		}
	} else if childExpiresAt != "" {
		if _, ok := verify.ParseTimestamp(childExpiresAt); !ok {
			return types.Delegation{}, errors.New("delegation: expiresAt is non-empty but invalid")
		}
	}
	// The child activation floor is the later of the requested one and the
	// parent's; omitting it inherits the parent's.
	childNotBefore := opts.NotBefore
	if parent.NotBefore != "" {
		pn, ok := verify.ParseTimestamp(parent.NotBefore)
		if !ok {
			return types.Delegation{}, errors.New("delegation: parent notBefore is non-empty but invalid")
		}
		if childNotBefore == "" {
			childNotBefore = parent.NotBefore
		} else {
			cn, ok := verify.ParseTimestamp(childNotBefore)
			if !ok {
				return types.Delegation{}, errors.New("delegation: notBefore is non-empty but invalid")
			}
			if cn.Before(pn) {
				childNotBefore = parent.NotBefore
			}
		}
	} else if childNotBefore != "" {
		if _, ok := verify.ParseTimestamp(childNotBefore); !ok {
			return types.Delegation{}, errors.New("delegation: notBefore is non-empty but invalid")
		}
	}

	// The child inherits the parent's depth ceiling EXACTLY. When the parent
	// states none, the child states none: an absent ceiling stays absent rather
	// than becoming a fabricated 1. Defaulting to 1 invented a bound nobody
	// stated, and it was the verifier's own refusal: a parent at currentDepth 1
	// with no maxDepth minted a child at currentDepth 2 carrying maxDepth 1,
	// which VerifyDelegationChain then refused as "depth limit exceeded". A
	// minter must never write a bound the verifier will reject.
	var childMaxDepth *int
	if parent.MaxDepth != nil {
		inherited := *parent.MaxDepth
		childMaxDepth = &inherited
	}
	child := types.Delegation{
		DelegationID: opts.DelegationID,
		DelegatedBy:  parent.DelegatedTo,
		DelegatedTo:  opts.DelegatedTo,
		Scope:        opts.Scope,
		SpendLimit:   childLimit,
		// Carry the RESOLVED spend unit forward so a sub-delegation cannot silently drop or change
		// it (an invocations budget must not become a currency budget across a hop).
		SpendLimitUnit: childUnit,
		MaxDepth:       childMaxDepth,
		CurrentDepth:   &newDepth,
		ExpiresAt:      childExpiresAt,
		NotBefore:      childNotBefore,
		CreatedAt:      opts.CreatedAt,
	}
	sig, err := keys.SignArtifact(canonicalMap(child), "signature", opts.PrivateKey)
	if err != nil {
		return types.Delegation{}, err
	}
	child.Signature = sig
	return child, nil
}

// Delegation validity failures returned by VerifyDelegationAt. Stable
// categories, matching the Rust DelegationError variants.
var (
	ErrInvalidSignature = errors.New("delegation: invalid signature")
	ErrInvalidExpiry    = errors.New("delegation: expiresAt is missing or unparseable")
	ErrExpired          = errors.New("delegation: expired")
	ErrInvalidNotBefore = errors.New("delegation: notBefore is unparseable")
	ErrNotYetValid      = errors.New("delegation: not yet valid")
	ErrDepthExceeded    = errors.New("delegation: currentDepth exceeds maxDepth")
)

// VerifyDelegationSignature checks ONLY that a typed delegation's signature is
// authentic against its delegatedBy key. It consults no clock and makes no
// validity claim: an expired or not-yet-valid delegation still has an authentic
// signature. Callers deciding whether a delegation may be USED want
// VerifyDelegationAt or VerifyDelegation instead.
func VerifyDelegationSignature(d types.Delegation) bool {
	if d.Signature == "" {
		return false
	}
	canon, err := jcs.Canonicalize(canonicalMap(d))
	if err != nil {
		return false
	}
	return keys.Verify(canon, d.Signature, d.DelegatedBy)
}

// VerifyDelegationAt is the deterministic core: it checks a delegation at an
// explicit evaluation time and returns nil when the delegation is authentic and
// live, or the first violation otherwise.
//
// expiresAt is part of the signed bytes and is REQUIRED. A missing or
// unparseable expiry fails closed as expired rather than meaning "never
// expires", matching the reference SDK (new Date(undefined) is NaN, which the
// reference reports as an invalid expiresAt) and the Rust verifier.
func VerifyDelegationAt(d types.Delegation, now time.Time) error {
	if !VerifyDelegationSignature(d) {
		return ErrInvalidSignature
	}
	expiry, ok := verify.ParseTimestamp(d.ExpiresAt)
	if !ok {
		return ErrInvalidExpiry
	}
	// Boundary semantics match the reference: expired only when strictly earlier
	// than the evaluation time, not yet valid only when strictly later. Equality
	// on either boundary is live.
	if expiry.Before(now) {
		return ErrExpired
	}
	if d.NotBefore != "" {
		notBefore, ok := verify.ParseTimestamp(d.NotBefore)
		if !ok {
			return ErrInvalidNotBefore
		}
		if notBefore.After(now) {
			return ErrNotYetValid
		}
	}
	if d.MaxDepth != nil && d.CurrentDepth != nil && *d.CurrentDepth > *d.MaxDepth {
		return ErrDepthExceeded
	}
	return nil
}

// VerifyDelegation reports whether a typed delegation is authentic AND live
// right now. It is VerifyDelegationAt against the real clock.
//
// Before, this was a signature-only check with no clock, so a delegation that
// expired in 2020 and one whose notBefore is in 2099 both verified true even
// though expiresAt and notBefore are part of the signed bytes. Callers that
// genuinely want the signature alone (a clock-free lineage check, for example)
// should call VerifyDelegationSignature, which says so in its name.
func VerifyDelegation(d types.Delegation) bool {
	return VerifyDelegationAt(d, time.Now().UTC()) == nil
}

// VerifyDelegationRaw verifies a delegation supplied as a generic JSON map (for
// example one produced by another implementation). It strips the signature
// field, canonicalizes the rest, and verifies against the delegatedBy key.
func VerifyDelegationRaw(obj map[string]interface{}) bool {
	sig, _ := obj["signature"].(string)
	delegatedBy, _ := obj["delegatedBy"].(string)
	if sig == "" || delegatedBy == "" {
		return false
	}
	rest := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k == "signature" {
			continue
		}
		rest[k] = v
	}
	canon, err := jcs.Canonicalize(rest)
	if err != nil {
		return false
	}
	return keys.Verify(canon, sig, delegatedBy)
}
