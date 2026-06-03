// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package values

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aeoess/agent-passport-go/verify"
)

// ---------------------------------------------------------------------------
// Canonical map builders.
//
// The signed preimage is jcs.Canonicalize(artifact minus signature). To match
// the reference byte for byte we hand the canonicalizer the SAME field set the
// reference object carries: required fields always, optional fields only when
// non-empty (the reference legacy canonicalize() strips null/undefined, so an
// absent optional field must simply not appear in the map). Field ORDER does
// not matter because JCS sorts keys; field PRESENCE does.
// ---------------------------------------------------------------------------

// attestationToMap builds the map for an attestation. The signature field is
// included here and stripped by SignArtifact/VerifyCanonicalSignature; every
// other field is always present in the reference shape.
func attestationToMap(a FloorAttestation) map[string]interface{} {
	exts := make([]interface{}, len(a.Extensions))
	for i, e := range a.Extensions {
		exts[i] = e
	}
	return map[string]interface{}{
		"attestationId": a.AttestationID,
		"agentId":       a.AgentID,
		"publicKey":     a.PublicKey,
		"floorVersion":  a.FloorVersion,
		"extensions":    exts,
		"attestedAt":    a.AttestedAt,
		"expiresAt":     a.ExpiresAt,
		"commitment":    a.Commitment,
		"signature":     a.Signature,
	}
}

// reportToMap builds the map for a compliance report.
func reportToMap(r ComplianceReport) map[string]interface{} {
	checks := make([]interface{}, len(r.Checks))
	for i, c := range r.Checks {
		checks[i] = checkToMap(c)
	}
	return map[string]interface{}{
		"reportId":          r.ReportID,
		"agentId":           r.AgentID,
		"floorVersion":      r.FloorVersion,
		"period":            map[string]interface{}{"from": r.Period.From, "to": r.Period.To},
		"receiptsAnalyzed":  r.ReceiptsAnalyzed,
		"checks":            checks,
		"overallCompliance": r.OverallCompliance,
		"generatedAt":       r.GeneratedAt,
		"signature":         r.Signature,
	}
}

// checkToMap builds the map for a single compliance check. enforcementMode and
// evidence are emitted only when set, matching the reference object: the base
// always carries enforcementMode (so it is present whenever non-empty), while
// evidence appears only on the checks that set it.
func checkToMap(c ComplianceCheck) map[string]interface{} {
	m := map[string]interface{}{
		"principleId":   c.PrincipleID,
		"principleName": c.PrincipleName,
		"status":        c.Status,
		"detail":        c.Detail,
	}
	if c.EnforcementMode != "" {
		m["enforcementMode"] = string(c.EnforcementMode)
	}
	if c.Evidence != "" {
		m["evidence"] = c.Evidence
	}
	return m
}

// ---------------------------------------------------------------------------
// Floor JSON parsing.
// ---------------------------------------------------------------------------

// parseFloorJSON decodes the canonical JSON floor. It requires a top-level
// "floor" array, matching the reference loadFloor JSON branch.
func parseFloorJSON(input string) (ValuesFloor, error) {
	var probe struct {
		Floor json.RawMessage `json:"floor"`
	}
	if err := json.Unmarshal([]byte(input), &probe); err != nil {
		return ValuesFloor{}, errBadFloor
	}
	if len(probe.Floor) == 0 || probe.Floor[0] != '[' {
		return ValuesFloor{}, errBadFloor
	}
	var floor ValuesFloor
	if err := json.Unmarshal([]byte(input), &floor); err != nil {
		return ValuesFloor{}, errBadFloor
	}
	return floor, nil
}

// ---------------------------------------------------------------------------
// Small utilities.
// ---------------------------------------------------------------------------

// scopeAuthorizes reports whether any granted scope covers the required scope,
// reusing the Phase-0 ScopeCovers. Mirrors scopeAuthorizes in the reference SDK
// (src/core/delegation.ts).
func scopeAuthorizes(delegationScope []string, required string) bool {
	for _, s := range delegationScope {
		if verify.ScopeCovers(s, required) {
			return true
		}
	}
	return false
}

// periodBounds returns [min, max] of receipt timestamps. With no receipts it
// falls back to the caller-supplied bounds, matching the reference which uses
// the sorted-timestamp ends and otherwise new Date().toISOString().
func periodBounds(receipts []ActionReceipt, fallbackFrom, fallbackTo string) (string, string) {
	if len(receipts) == 0 {
		return fallbackFrom, fallbackTo
	}
	ts := make([]string, 0, len(receipts))
	for _, r := range receipts {
		ts = append(ts, r.Timestamp)
	}
	sort.Strings(ts)
	return ts[0], ts[len(ts)-1]
}

// itoa is JavaScript-style integer-to-string for the detail strings.
func itoa(n int) string { return strconv.Itoa(n) }

// roundTo3 rounds to three decimals the way Math.round(x*1000)/1000 does.
func roundTo3(x float64) float64 {
	return float64(int64(x*1000+copySign(0.5, x))) / 1000
}

func copySign(mag, sign float64) float64 {
	if sign < 0 {
		return -mag
	}
	return mag
}

// majorVersion returns the segment before the first dot, matching
// version.split('.')[0].
func majorVersion(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// sortedKeys returns the keys of a set in ascending order. The reference uses
// Set iteration order (insertion), but the only call site embeds them in a
// violation detail string; sorting keeps the output deterministic across runs.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nonNilStrings normalizes a nil slice to an empty slice so JSON encodes [] not
// null, matching the reference arrays which are always present.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// timeLess reports whether RFC 3339 timestamp a is strictly before b. Both must
// parse; on any parse failure it returns false (do not flag expiry on garbage).
func timeLess(a, b string) bool {
	ta, okA := parseTime(a)
	tb, okB := parseTime(b)
	if !okA || !okB {
		return false
	}
	return ta.Before(tb)
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
