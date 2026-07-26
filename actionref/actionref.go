// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package actionref computes the content-addressed request identity action_ref,
// hex-identical to the APS reference SDK computeActionRef (src/core/action-ref.ts)
// per draft-pidlisnyi-aps-01 §4.1.
//
// action_ref = SHA-256( canonicalizeJCS({ agentId, actionType, scopeRequired,
// timestamp }) ), where timestamp is normalized to second-precision UTC ISO
// 8601. Two receipts with the same action_ref describe the same request.
package actionref

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/aeoess/agent-passport-go/jcs"
)

// NormalizeTimestamp parses an ISO 8601 timestamp and returns it as
// second-precision UTC with a trailing Z, matching the reference SDK
// normalizeTimestamp (new Date(ts).toISOString() with the millisecond suffix
// stripped).
func NormalizeTimestamp(ts string) (string, error) {
	t, err := parseTime(ts)
	if err != nil {
		return "", err
	}
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z07:00"), nil
}

func parseTime(ts string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z0700",
		"2006-01-02T15:04:05Z0700",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, ts); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("actionref: invalid timestamp \"" + ts + "\"")
}

// ErrDuplicateScopeRequired reports a scopeRequired array holding two elements
// that are equal after NFC normalization. Section 4.1 defines scope_required as
// a duplicate-free array, so a duplicated array has no canonical form and is
// rejected rather than deduplicated: an equality key must not map distinct
// inputs onto one value silently. Callers branch with errors.Is.
var ErrDuplicateScopeRequired = errors.New("actionref: duplicate_scope_required")

// CanonicalizeScopes returns the spec-canonical form of a scopeRequired array
// per draft-pidlisnyi-aps-03 section 4.1: each scope string is normalized to
// Unicode Normalization Form C, duplicates are rejected, then the array is
// sorted by Unicode code point. The input slice is never mutated; the result is
// a fresh copy.
//
// sort.Strings compares UTF-8 bytes, and for valid UTF-8 the byte order equals
// Unicode code-point order, so a byte sort after NFC normalization is exactly
// the code-point sort the spec requires. This intentionally differs from the
// UTF-16 code-unit order used for JCS object-key sorting in the jcs package:
// the scopeRequired array sort is a pre-canonicalization step defined by the
// spec, not part of RFC 8785 itself.
//
// Duplicates are detected AFTER normalization, so two spellings that collide
// only under NFC (U+00E9 and "e" + U+0301) reject as well. Valid arrays are
// byte-unchanged: only duplicated input changes behavior, from a silent
// identity to ErrDuplicateScopeRequired.
func CanonicalizeScopes(scopeRequired []string) ([]string, error) {
	scopes := make([]string, len(scopeRequired))
	for i, s := range scopeRequired {
		scopes[i] = norm.NFC.String(s)
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if _, dup := seen[s]; dup {
			return nil, fmt.Errorf(
				"%w: scope_required contains duplicate elements after NFC normalization: %q",
				ErrDuplicateScopeRequired, s)
		}
		seen[s] = struct{}{}
	}
	sort.Strings(scopes)
	return scopes, nil
}

// ComputeActionRefScopes returns the lowercase-hex SHA-256 action_ref for an
// intent whose scopeRequired is an array of scope strings, the shape defined
// by draft-pidlisnyi-aps-03 section 4.1. Each scope is NFC-normalized and the
// array is sorted by code point (CanonicalizeScopes) before hashing, so two
// callers supplying the same scopes in different order or in different Unicode
// normalization forms produce the same action_ref. The caller's slice is not
// mutated. createdAt is normalized to second precision before hashing.
//
// Returns ErrDuplicateScopeRequired (wrapped) when scopeRequired holds two
// elements equal after NFC normalization. The return happens inside
// canonicalization, before the digest is computed, so a duplicated array can
// never present as an identity mismatch downstream: there is no action_ref to
// compare in the first place.
func ComputeActionRefScopes(agentID, actionType string, scopeRequired []string, createdAt string) (string, error) {
	ts, err := NormalizeTimestamp(createdAt)
	if err != nil {
		return "", err
	}
	scopes, err := CanonicalizeScopes(scopeRequired)
	if err != nil {
		return "", err
	}
	scopeVals := make([]interface{}, len(scopes))
	for i, s := range scopes {
		scopeVals[i] = s
	}
	preimage := map[string]interface{}{
		"agentId":       agentID,
		"actionType":    actionType,
		"scopeRequired": scopeVals,
		"timestamp":     ts,
	}
	return jcs.CanonicalHash(preimage)
}

// ComputeActionRef returns the lowercase-hex SHA-256 action_ref for the given
// intent fields. scopeRequired is the single delegation scope the action needs
// (ActionIntent.action.scopeRequired) and is carried in the preimage as a
// plain JSON string; this preserves the pinned cross-implementation hash for
// existing single-scope callers. The scope is NFC-normalized before hashing
// (an identity operation for ASCII scopes, so existing expected values are
// unchanged). For the section 4.1 array shape use ComputeActionRefScopes.
// createdAt is normalized to second precision before hashing.
func ComputeActionRef(agentID, actionType, scopeRequired, createdAt string) (string, error) {
	ts, err := NormalizeTimestamp(createdAt)
	if err != nil {
		return "", err
	}
	preimage := map[string]interface{}{
		"agentId":       agentID,
		"actionType":    actionType,
		"scopeRequired": norm.NFC.String(scopeRequired),
		"timestamp":     ts,
	}
	return jcs.CanonicalHash(preimage)
}

// Match reports whether two action_ref values describe the same request.
func Match(a, b string) bool {
	return a != "" && a == b
}
