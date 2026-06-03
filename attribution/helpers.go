// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package attribution

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"

	"github.com/aeoess/agent-passport-go/verify"
)

// verifyEd25519Hex delegates to the Phase-0 verify core so there is one source
// of truth for Ed25519 verification.
func verifyEd25519Hex(message []byte, sigHex, pubHex string) bool {
	return verify.VerifyEd25519(message, sigHex, pubHex)
}

// toGeneric projects a typed value to the generic JSON shape (map, slice,
// scalar) that jcs.Canonicalize consumes, using a JSON round-trip with
// UseNumber so numeric fidelity survives. This is the same generic form the
// reference SDK canonicalizes (it works on plain JS objects). Numbers decode as
// json.Number, which the jcs ECMAScript number serializer formats identically
// to JSON.stringify (integers without a trailing ".0", -0 as "0").
func toGeneric(v interface{}) interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out interface{}
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

// unsignedReport returns the report as a generic map with the signature key
// removed, so the canonical preimage matches the reference object-rest
// destructuring { signature, ...unsigned }. The JSON round-trip yields exactly
// the field set the reference object carries (omitempty fields that are empty
// are absent on both sides, which the null-stripping canonicalize also drops).
func unsignedReport(report AttributionReport) map[string]interface{} {
	g, ok := toGeneric(report).(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	delete(g, "signature")
	return g
}

// roundTo3 mirrors the reference Math.round(x * 1000) / 1000.
func roundTo3(x float64) float64 {
	return math.Round(x*1000) / 1000
}

func absf(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}
