// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

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
	MaxDepth     int
	CurrentDepth int
	ExpiresAt    string
	NotBefore    string
	CreatedAt    string
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
		"expiresAt":    d.ExpiresAt,
		"notBefore":    d.NotBefore,
		"createdAt":    d.CreatedAt,
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
	d := types.Delegation{
		DelegationID: opts.DelegationID,
		DelegatedBy:  opts.DelegatedBy,
		DelegatedTo:  opts.DelegatedTo,
		Scope:        opts.Scope,
		SpendLimit:   opts.SpendLimit,
		MaxDepth:     &maxD,
		CurrentDepth: &curD,
		ExpiresAt:    opts.ExpiresAt,
		NotBefore:    opts.NotBefore,
		CreatedAt:    opts.CreatedAt,
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
	ExpiresAt    string
	NotBefore    string
	CreatedAt    string
}

// SubDelegate validates monotonic narrowing against the parent, then issues the
// signed child. Narrowing uses verify.ScopeCovers and the depth bound from the
// parent, matching the reference subDelegate refusal semantics.
func SubDelegate(opts SubDelegateOptions) (types.Delegation, error) {
	parent := opts.Parent
	parentDepth := 0
	if parent.CurrentDepth != nil {
		parentDepth = *parent.CurrentDepth
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
	if parent.SpendLimit != nil && opts.SpendLimit != nil && *opts.SpendLimit > *parent.SpendLimit {
		return types.Delegation{}, errors.New("delegation: spend limit exceeds parent")
	}
	maxD := 1
	if parent.MaxDepth != nil {
		maxD = *parent.MaxDepth
	}
	child := types.Delegation{
		DelegationID: opts.DelegationID,
		DelegatedBy:  parent.DelegatedTo,
		DelegatedTo:  opts.DelegatedTo,
		Scope:        opts.Scope,
		SpendLimit:   opts.SpendLimit,
		MaxDepth:     &maxD,
		CurrentDepth: &newDepth,
		ExpiresAt:    opts.ExpiresAt,
		NotBefore:    opts.NotBefore,
		CreatedAt:    opts.CreatedAt,
	}
	sig, err := keys.SignArtifact(canonicalMap(child), "signature", opts.PrivateKey)
	if err != nil {
		return types.Delegation{}, err
	}
	child.Signature = sig
	return child, nil
}

// VerifyDelegation checks a typed delegation's signature against its delegatedBy
// key. It touches no private key.
func VerifyDelegation(d types.Delegation) bool {
	if d.Signature == "" {
		return false
	}
	canon, err := jcs.Canonicalize(canonicalMap(d))
	if err != nil {
		return false
	}
	return keys.Verify(canon, d.Signature, d.DelegatedBy)
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
