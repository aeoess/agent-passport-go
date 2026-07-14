// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Signing-boundary regression: a lone-surrogate escape in a raw DSSE payload
// must fail closed at the verify boundary. Before the raw-JSON fix, encoding/json
// substituted U+FFFD and the verifier canonicalized and hashed the altered value.
package intoto

import (
	"errors"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

const loneSurrogatePayload = `{"_type":"https://in-toto.io/Statement/v1","predicate":{"note":"\uD800"}}`

func TestParseRejectsLoneSurrogatePayload(t *testing.T) {
	env := DecisionReceiptEnvelope{PayloadType: IntotoPayloadType, Payload: loneSurrogatePayload}
	_, err := ParseDecisionReceiptStatement(env)
	if !errors.Is(err, jcs.ErrLoneSurrogate) {
		t.Fatalf("ParseDecisionReceiptStatement want ErrLoneSurrogate, got %v", err)
	}
}

func TestVerifyEnvelopeFailsClosedOnLoneSurrogate(t *testing.T) {
	// A crafted envelope whose payload carries a lone surrogate: verification must
	// return false (fail closed), with no panic, no retry, and no fallback.
	env := DecisionReceiptEnvelope{
		PayloadType: IntotoPayloadType,
		Payload:     loneSurrogatePayload,
		Signatures:  []DSSESignature{{KeyID: "k", Sig: "00"}},
		Digest:      Digest{SHA256: "deadbeef"},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyEnvelope panicked on adversarial input: %v", r)
		}
	}()
	if VerifyEnvelope(env, "00", 0) {
		t.Fatal("VerifyEnvelope accepted a lone-surrogate payload (must fail closed)")
	}
}
