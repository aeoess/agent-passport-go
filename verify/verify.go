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

// ValidateChain walks a delegation chain and returns the first refusal code, or
// "" if the chain is valid. Check order matches the reference validator:
// depth, then per link root->leaf: validity, signature, scope narrowing.
func ValidateChain(in ChainInput) string {
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

func parseMillis(ts string) (int64, bool) {
	if ts == "" {
		return time.Now().UTC().UnixMilli(), true
	}
	for _, l := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(l, ts); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Typed SDK-shape delegation-chain narrowing.
// ---------------------------------------------------------------------------

// VerifyDelegationChain checks a typed APS delegation chain (root first) for
// monotonic narrowing: chain linkage, depth bounds, scope subset under
// ScopeCovers, non-increasing spend limit, and non-widening expiry. It returns
// nil for a valid chain or the first violation. Signatures and revocation are
// checked separately (this is the narrowing invariant only).
func VerifyDelegationChain(chain []types.Delegation) error {
	for i := 1; i < len(chain); i++ {
		parent, child := chain[i-1], chain[i]
		if child.DelegatedBy != parent.DelegatedTo {
			return errors.New("chain linkage broken: child.delegatedBy != parent.delegatedTo")
		}
		// Depth must increase by exactly one per hop AND stay within the parent's maxDepth.
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
		if parent.MaxDepth != nil && childDepth > *parent.MaxDepth {
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
		if parent.SpendLimit != nil && child.SpendLimit != nil && *child.SpendLimit > *parent.SpendLimit {
			return errors.New("spend limit widening: child exceeds parent")
		}
		// Spend unit may not change across a hop. When the parent carries a unit and the child
		// carries a spend limit, the child must carry the SAME unit; dropping or changing it (e.g.
		// invocations -> currency, or invocations -> unit-less which downstream treats as currency)
		// is a narrowing violation that a numeric-only check misses.
		if parent.SpendLimitUnit != "" && child.SpendLimit != nil && child.SpendLimitUnit != parent.SpendLimitUnit {
			return errors.New("spend unit change: child must carry the parent spendLimitUnit unchanged")
		}
		// Temporal narrowing: a child may not outlive its parent. A missing child expiry must not
		// bypass the check when the parent has one. A non-empty but UNPARSEABLE expiry on either
		// side must fail closed (invalidate the chain), never be silently skipped: gating the
		// outlives comparison on both sides parsing let a garbage child expiry slip through and
		// outlive its parent.
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
