// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

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
	"time"

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

// ComputeActionRef returns the lowercase-hex SHA-256 action_ref for the given
// intent fields. scopeRequired is the single delegation scope the action needs
// (ActionIntent.action.scopeRequired). createdAt is normalized to second
// precision before hashing.
func ComputeActionRef(agentID, actionType, scopeRequired, createdAt string) (string, error) {
	ts, err := NormalizeTimestamp(createdAt)
	if err != nil {
		return "", err
	}
	preimage := map[string]interface{}{
		"agentId":       agentID,
		"actionType":    actionType,
		"scopeRequired": scopeRequired,
		"timestamp":     ts,
	}
	return jcs.CanonicalHash(preimage)
}

// Match reports whether two action_ref values describe the same request.
func Match(a, b string) bool {
	return a != "" && a == b
}
