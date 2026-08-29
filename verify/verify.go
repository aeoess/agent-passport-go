// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package verify implements APS verification: Ed25519 signature checks over
// canonical bytes, delegation-chain monotonic-narrowing validation, and
// receipt verification. Verify-first scope: this package checks artifacts, it
// does not mint or sign them.
package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/types"
)

// Closed taxonomy of chain-refusal codes, matching CTEF v0.3.2 §A and the
// shared composition fixtures (aps-conformance-suite a2a-1496-negative-paths).
const (
	CodeInvalidScope  = "INVALID_CLAIM_SCOPE"
	CodeDepthExceeded = "DELEGATION_DEPTH_EXCEEDED"
	CodeInvalidSig    = "INVALID_SIGNATURE"
	CodeValidityExp   = "VALIDITY_EXPIRED"

	// Authorization-only codes. They can only be returned by
	// VerifyChainAuthorization, never by the structural validator, so a
	// structural pass can never be read as an authorization pass.

	// CodeUntrustedRoot: the chain root's delegator is not in the caller's
	// trusted set. A chain that is internally well signed is not thereby
	// authorized; without this, an attacker who mints their own root and signs
	// every hop from it produces a structurally perfect chain.
	CodeUntrustedRoot = "UNTRUSTED_ROOT"
	// CodeRevoked: the resolver reported a link revoked at the evaluation time.
	CodeRevoked = "DELEGATION_REVOKED"
	// CodeRevocationIndeterminate: no revocation context was supplied, so
	// authorization cannot be decided. This is NOT a positive authorization and
	// NOT a refusal on the merits: the caller must supply a resolver or treat
	// the answer as unknown. Legacy chain links carry no revocation member and
	// none is added here, because they are signed wire objects.
	CodeRevocationIndeterminate = "REVOCATION_INDETERMINATE"
)

// VerifyEd25519 verifies a raw Ed25519 signature (64-byte hex) over message
// under a raw 32-byte public key (hex). The reference SDK and the conformance
// runners sign over the UTF-8 canonical bytes.
//
// The public key and the signature's R must both be admissible: the canonical
// encoding of a point that is not of small order. See ed25519_admissibility.go
// for why crypto/ed25519 alone is not enough.
func VerifyEd25519(message []byte, sigHex, pubHex string) bool {
	if len(pubHex) != 64 {
		return false
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !admissiblePoint(pub) || !admissiblePoint(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

// VerifyCanonicalSignature strips the named signature field from obj,
// canonicalizes the remainder with JCS, and verifies sigHex against pubHex over
// those canonical bytes. This is the standard "signature over
// canonicalizeJCS(body minus signature)" check.
func VerifyCanonicalSignature(obj map[string]interface{}, sigField, sigHex, pubHex string) bool {
	rest := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k == sigField {
			continue
		}
		rest[k] = v
	}
	canon, err := jcs.Canonicalize(rest)
	if err != nil {
		return false
	}
	return VerifyEd25519([]byte(canon), sigHex, pubHex)
}

// ScopeCovers reports whether a granted scope covers a required scope, matching
// scopeCovers in the reference SDK (src/core/delegation.ts): exact match, the
// "*" wildcard, prefix match, and trailing ":*" segment wildcards.
func ScopeCovers(granted, required string) bool {
	if granted == required {
		return true
	}
	if granted == "*" {
		return true
	}
	if strings.HasPrefix(required, granted+":") {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		prefix := granted[:len(granted)-2]
		if required == prefix || strings.HasPrefix(required, prefix+":") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Composition negative-path chain validation (a2a-1496 fixtures).
// ---------------------------------------------------------------------------

// ChainInput is the composition negative-path chain shape: root-first chain of
// links, an optional max_depth, and an optional clock.
type ChainInput struct {
	Chain    []map[string]interface{} `json:"chain"`
	MaxDepth *int                     `json:"max_depth"`
	Now      string                   `json:"now"`
}

// ValidateChain is the former name of ValidateChainStructure.
//
// Deprecated: the name reads as a verdict on the whole chain, but it proves
// STRUCTURE only: linkage, validity windows, per-link signatures, and scope
// narrowing. It has no trust root and no revocation context, so a chain an
// attacker minted from their own root passes it. Call ValidateChainStructure
// when you want that proof, or VerifyChainAuthorization when you want an
// authorization decision. Kept as an alias so existing callers keep compiling
// and keep their exact behaviour.
func ValidateChain(in ChainInput) string {
	return ValidateChainStructure(in)
}

// ValidateChainStructure walks a delegation chain and returns the first refusal
// code, or "" if the chain is structurally sound. Check order matches the
// reference validator: depth, then per link root->leaf: validity, signature,
// scope narrowing.
//
// "Structurally sound" is not "authorized". This function answers only whether
// the links hang together and each one is signed by the key it names as its
// delegator. It does not know which roots the caller trusts and cannot consult
// revocation. Use VerifyChainAuthorization for a decision.
func ValidateChainStructure(in ChainInput) string {
	// A present-but-empty chain (len 0) is not a valid delegation and must be
	// refused identically to a nil chain: fail-closed. Guarding only nil left an
	// asymmetric fail-open where an explicit empty array returned "" (valid).
	if len(in.Chain) == 0 {
		return CodeInvalidSig
	}
	if in.MaxDepth != nil && len(in.Chain) > *in.MaxDepth {
		return CodeDepthExceeded
	}
	nowMs, ok := parseMillis(in.Now)
	if !ok {
		return CodeValidityExp
	}
	for i, link := range in.Chain {
		notAfter := nestedString(link, "validityWindow", "not_after")
		// A link with no not_after must be treated as invalid, not as never-expiring. parseMillis("")
		// returns (now, true) so an empty not_after would otherwise pass the expiry gate (fail-open).
		if notAfter == "" {
			return CodeValidityExp
		}
		naMs, naOK := parseMillis(notAfter)
		if !naOK || naMs < nowMs {
			return CodeValidityExp
		}
		sig, _ := link["signature"].(string)
		delegator, _ := link["delegator"].(string)
		if !VerifyCanonicalSignature(link, "signature", sig, delegator) {
			return CodeInvalidSig
		}
		if i > 0 {
			// Chain continuity: each link must be issued by the previous link's
			// delegatee, so a link cannot be authenticated by an arbitrary key
			// it names as its own delegator. Without this, a chain of
			// independently self-signed links (each signed by whatever key it
			// names) passes every other gate. An unauthorized issuer is an
			// invalid signature in the chain sense. (The typed
			// ValidateDelegationChain below enforces the same
			// delegatedBy==delegatedTo invariant.)
			prevDelegatee, _ := in.Chain[i-1]["delegatee"].(string)
			if prevDelegatee == "" || delegator == "" || delegator != prevDelegatee {
				return CodeInvalidSig
			}
			if scopeExpands(in.Chain[i-1], link) {
				return CodeInvalidScope
			}
		}
	}
	return ""
}

// scopeExpands reports whether child.scope.action_categories contains any value
// absent from parent.scope.action_categories (a widening, which is refused).
func scopeExpands(parent, child map[string]interface{}) bool {
	pcats := categorySet(parent)
	for _, c := range categoryList(child) {
		if _, ok := pcats[c]; !ok {
			return true
		}
	}
	return false
}

func categoryList(link map[string]interface{}) []string {
	scope, _ := link["scope"].(map[string]interface{})
	if scope == nil {
		return nil
	}
	raw, _ := scope["action_categories"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func categorySet(link map[string]interface{}) map[string]struct{} {
	set := map[string]struct{}{}
	for _, c := range categoryList(link) {
		set[c] = struct{}{}
	}
	return set
}

func nestedString(m map[string]interface{}, k1, k2 string) string {
	inner, _ := m[k1].(map[string]interface{})
	if inner == nil {
		return ""
	}
	s, _ := inner[k2].(string)
	return s
}

// ParseTimestamp parses an APS timestamp in the forms the reference SDK emits.
// It is the single source of truth for which timestamp spellings this
// implementation accepts, shared with the delegation package so the issuing and
// verifying sides never drift apart on what a valid instant looks like. An empty
// or unparseable value is not a timestamp: ok is false.
func ParseTimestamp(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	for _, l := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(l, ts); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseMillis(ts string) (int64, bool) {
	if ts == "" {
		return time.Now().UTC().UnixMilli(), true
	}
	t, ok := ParseTimestamp(ts)
	if !ok {
		return 0, false
	}
	return t.UnixMilli(), true
}

// ---------------------------------------------------------------------------
// Composition chain AUTHORIZATION (structure plus trust root and revocation).
// ---------------------------------------------------------------------------

// RevocationResolver answers whether a chain link is revoked at the evaluation
// time. It returns known=false when it cannot answer, which is not the same as
// answering "not revoked".
//
// Revocation state is NOT carried on the link. Legacy chain links are signed
// wire objects and adding a member to them would change the bytes the delegator
// signed, so the state arrives from outside, through this resolver.
type RevocationResolver func(link map[string]interface{}) (revoked bool, known bool)

// AuthorizationOptions is the external verification context an authorization
// decision needs and a signed artifact cannot carry.
type AuthorizationOptions struct {
	// TrustedRoots are the delegator keys the caller is willing to root a chain
	// at. An empty set authorizes nothing.
	TrustedRoots []string
	// Revocation resolves revocation state. A nil resolver means the caller
	// supplied no revocation context, and authorization comes back
	// indeterminate rather than positive.
	Revocation RevocationResolver
}

// ChainAuthorization is the proof token a successful authorization returns. It
// is deliberately a distinct type from the string code ValidateChainStructure
// returns, so a structural pass cannot be substituted for an authorization pass
// by accident.
type ChainAuthorization struct {
	// Hops is the number of links the authorization covered.
	Hops int
	// RevocationChecked reports whether revocation state was established for
	// every link. VerifyChainAuthorization only ever returns a token with this
	// set, because it refuses to succeed without a resolver that can answer.
	// It is part of the token rather than a footnote in the docs so a caller
	// reading a token from elsewhere can tell what it establishes, and it
	// mirrors the Rust ChainAuthorization field of the same meaning.
	RevocationChecked bool
}

// VerifyChainAuthorization decides whether a chain authorizes anything. On top
// of ValidateChainStructure it requires the root delegator to be explicitly
// trusted and every link to be resolvable as not revoked. It returns the
// authorization and "" on success, or the zero value and the first refusal code.
//
// A nil Revocation resolver yields CodeRevocationIndeterminate. That is the
// honest answer for a stateless verifier with no revocation context: the
// alternative, treating "cannot check" as "not revoked", is exactly the
// fail-open this separation exists to prevent.
func VerifyChainAuthorization(in ChainInput, opts AuthorizationOptions) (ChainAuthorization, string) {
	if len(in.Chain) == 0 {
		return ChainAuthorization{}, CodeInvalidSig
	}
	rootDelegator, _ := in.Chain[0]["delegator"].(string)
	trusted := false
	for _, r := range opts.TrustedRoots {
		if r != "" && r == rootDelegator {
			trusted = true
			break
		}
	}
	if rootDelegator == "" || !trusted {
		return ChainAuthorization{}, CodeUntrustedRoot
	}
	if code := ValidateChainStructure(in); code != "" {
		return ChainAuthorization{}, code
	}
	if opts.Revocation == nil {
		return ChainAuthorization{}, CodeRevocationIndeterminate
	}
	for _, link := range in.Chain {
		revoked, known := opts.Revocation(link)
		if !known {
			return ChainAuthorization{}, CodeRevocationIndeterminate
		}
		if revoked {
			return ChainAuthorization{}, CodeRevoked
		}
	}
	return ChainAuthorization{Hops: len(in.Chain), RevocationChecked: true}, ""
}

// ---------------------------------------------------------------------------
// Typed SDK-shape delegation-chain narrowing.
// ---------------------------------------------------------------------------

// effectiveBound is the authority ceiling a chain carries from its root down to
// the link being checked. It is derived only from the artifacts in the chain: it
// is a CEILING, never a remaining balance. Remaining balances belong to the
// ledger and a stateless verifier does not reconstruct them.
//
// The rule it implements: a bounded ancestor facet never becomes unconstrained
// because a descendant omitted the field. The effective spend ceiling is the
// MINIMUM spendLimit over the bounded ancestors, and the effective unit is the
// one carried from the NEAREST bounded ancestor. maxDepth narrows the same way.
// An omitted facet inherits; it never means infinity.
type effectiveBound struct {
	spendLimit  *float64
	spendUnit   string
	maxDepth    *int
	notBefore   string
	notBeforeMs int64
}

// statedSpendUnit is the unit a link asserts. A bare spendLimit with no explicit
// spendLimitUnit asserts the default unit "currency", matching the reference SDK
// (src/core/delegation.ts: parentUnit = spendLimitUnit ?? (spendLimit !== undefined
// ? 'currency' : undefined)). Without that default, a currency budget could be
// relabelled as invocations one hop down.
func statedSpendUnit(d types.Delegation) string {
	if d.SpendLimitUnit != "" {
		return d.SpendLimitUnit
	}
	if d.SpendLimit != nil {
		return "currency"
	}
	return ""
}

// narrow folds one link's stated bounds into the effective ceiling and returns
// the first violation. A stated bound may only tighten what it inherited; an
// omitted bound inherits the ancestor bound unchanged.
func (b *effectiveBound) narrow(d types.Delegation) error {
	// Spend unit. Once an ancestor has bound the unit, a descendant that states
	// a DIFFERENT unit is refused. Stating a spend limit without a unit states
	// the default unit "currency", so a USD-bound authority cannot erase the
	// unit by omitting spendLimitUnit and reappear as an unlabelled budget.
	stated := statedSpendUnit(d)
	if b.spendUnit != "" {
		if stated != "" && stated != b.spendUnit {
			return errors.New("spend unit change: child must carry the inherited spendLimitUnit unchanged")
		}
	} else if stated != "" {
		// No ancestor bound the unit yet: this link introduces one, which is
		// narrowing rather than conversion.
		b.spendUnit = stated
	}
	// Spend ceiling: the minimum over the bounded ancestors.
	if d.SpendLimit != nil {
		if b.spendLimit != nil && *d.SpendLimit > *b.spendLimit {
			return errors.New("spend limit widening: child exceeds the effective inherited ceiling")
		}
		if b.spendLimit == nil || *d.SpendLimit < *b.spendLimit {
			v := *d.SpendLimit
			b.spendLimit = &v
		}
	}
	// Depth ceiling: the minimum over the bounded ancestors. A descendant may
	// not restate a larger maxDepth to raise an ancestor bound, and omitting
	// maxDepth inherits rather than lifting it.
	if d.MaxDepth != nil {
		if b.maxDepth != nil && *d.MaxDepth > *b.maxDepth {
			return errors.New("depth limit widening: child maxDepth exceeds the effective inherited maxDepth")
		}
		if b.maxDepth == nil || *d.MaxDepth < *b.maxDepth {
			v := *d.MaxDepth
			b.maxDepth = &v
		}
	}
	// Activation floor: the MAXIMUM notBefore over the bounded ancestors. A
	// descendant may not become active earlier than its ancestor, and omitting
	// notBefore inherits the ancestor floor rather than meaning "active since
	// the beginning of time".
	if d.NotBefore != "" {
		ms, ok := parseMillis(d.NotBefore)
		if !ok {
			return errors.New("notBefore unparseable: non-empty but invalid")
		}
		if b.notBefore != "" && ms < b.notBeforeMs {
			return errors.New("activation widening: child notBefore precedes the effective inherited notBefore")
		}
		b.notBefore, b.notBeforeMs = d.NotBefore, ms
	}
	return nil
}

// VerifyDelegationChain checks a typed APS delegation chain (root first) for
// monotonic narrowing: chain linkage, depth bounds, scope subset under
// ScopeCovers, non-increasing spend limit, and non-widening expiry. It returns
// nil for a valid chain or the first violation. Signatures and revocation are
// checked separately (this is the narrowing invariant only).
//
// Every optional bound is evaluated against the EFFECTIVE ceiling carried from
// the root (see effectiveBound), not against the immediate parent alone. Under a
// pairwise reading, a three-hop chain that omits the bound in the middle hop
// launders it back to unbounded: 100 -> absent -> 1,000,000 passed both pairwise
// steps. Two hops cannot distinguish the two readings; three can.
func VerifyDelegationChain(chain []types.Delegation) error {
	// A present-but-empty chain is not a valid delegation and must fail closed,
	// exactly as ValidateChainStructure refuses one (APG-01) and as the Rust and
	// Python chain verifiers do. Returning nil here read "nothing to narrow" as
	// "narrowing satisfied".
	if len(chain) == 0 {
		return errors.New("chain is empty")
	}
	// Seed the effective ceiling from the root. Whether the root's own
	// currentDepth sits inside its own maxDepth is a per-link question, not a
	// narrowing question: delegation.VerifyDelegationAt reports that one.
	var bound effectiveBound
	if err := bound.narrow(chain[0]); err != nil {
		return err
	}
	for i := 1; i < len(chain); i++ {
		parent, child := chain[i-1], chain[i]
		if child.DelegatedBy != parent.DelegatedTo {
			return errors.New("chain linkage broken: child.delegatedBy != parent.delegatedTo")
		}
		if err := bound.narrow(child); err != nil {
			return err
		}
		// Depth must increase by exactly one per hop AND stay within the effective maxDepth.
		// Checking only child.currentDepth <= parent.maxDepth let a long chain claim a flat depth
		// and bypass the bound; require strict monotonic increment so depth tracks the real hop count.
		parentDepth := 0
		if parent.CurrentDepth != nil {
			parentDepth = *parent.CurrentDepth
		}
		childDepth := 0
		if child.CurrentDepth != nil {
			childDepth = *child.CurrentDepth
		}
		if childDepth != parentDepth+1 {
			return errors.New("depth not monotonic: child.currentDepth must be parent.currentDepth + 1")
		}
		if bound.maxDepth != nil && childDepth > *bound.maxDepth {
			return errors.New("depth limit exceeded")
		}
		for _, s := range child.Scope {
			covered := false
			for _, ps := range parent.Scope {
				if ScopeCovers(ps, s) {
					covered = true
					break
				}
			}
			if !covered {
				return errors.New("scope widening: child scope not covered by parent")
			}
		}
		// Temporal narrowing: a child may not outlive its parent. A missing child expiry must not
		// bypass the check when the parent has one. A non-empty but UNPARSEABLE expiry on either
		// side must fail closed (invalidate the chain), never be silently skipped: gating the
		// outlives comparison on both sides parsing let a garbage child expiry slip through and
		// outlive its parent. Expiry stays a pairwise rule because rejecting the omission makes
		// pairwise containment transitively equal to the effective minimum.
		var pe int64
		var haveParentExpiry bool
		if parent.ExpiresAt != "" {
			p, ok := parseMillis(parent.ExpiresAt)
			if !ok {
				return errors.New("expiry unparseable: parent expiresAt is non-empty but invalid")
			}
			pe, haveParentExpiry = p, true
		}
		var ce int64
		var haveChildExpiry bool
		if child.ExpiresAt != "" {
			c, ok := parseMillis(child.ExpiresAt)
			if !ok {
				return errors.New("expiry unparseable: child expiresAt is non-empty but invalid")
			}
			ce, haveChildExpiry = c, true
		}
		if haveParentExpiry {
			if !haveChildExpiry {
				return errors.New("expiry widening: child has no expiry but parent does")
			}
			if ce > pe {
				return errors.New("expiry widening: child outlives parent")
			}
		}
	}
	return nil
}
