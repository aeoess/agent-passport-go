// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package intoto

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/verify"
)

var errEmptyPayload = errors.New("intoto: envelope payload is empty")

// ParseDecisionReceiptStatement parses a DecisionReceiptEnvelope payload back
// into its in-toto Statement value. Round-trip property, matching the reference
// SDK: jcs.Canonicalize(ParseDecisionReceiptStatement(env)) == env.Payload.
//
// Numbers are decoded as json.Number so a re-canonicalization reproduces the
// original integer/number rendering byte-for-byte.
func ParseDecisionReceiptStatement(env DecisionReceiptEnvelope) (map[string]interface{}, error) {
	if env.Payload == "" {
		return nil, errEmptyPayload
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(env.Payload)))
	dec.UseNumber()
	var stmt map[string]interface{}
	if err := dec.Decode(&stmt); err != nil {
		return nil, err
	}
	return stmt, nil
}

// VerifyEnvelope checks a DecisionReceiptEnvelope two ways:
//  1. the parsed payload re-canonicalizes to exactly env.Payload (the verifier
//     does not trust the supplied payload string blindly), and
//  2. the DSSE signature at the given index is a valid Ed25519 signature over
//     the payload bytes under pubHex.
//
// It returns true only when both hold. pubHex is the raw 32-byte Ed25519 public
// key as hex (the signer's verification key). sigIndex selects which signature
// entry to check.
func VerifyEnvelope(env DecisionReceiptEnvelope, pubHex string, sigIndex int) bool {
	if sigIndex < 0 || sigIndex >= len(env.Signatures) {
		return false
	}
	stmt, err := ParseDecisionReceiptStatement(env)
	if err != nil {
		return false
	}
	canon, err := jcs.Canonicalize(stmt)
	if err != nil {
		return false
	}
	if canon != env.Payload {
		return false
	}
	return verify.VerifyEd25519([]byte(env.Payload), env.Signatures[sigIndex].Sig, pubHex)
}
