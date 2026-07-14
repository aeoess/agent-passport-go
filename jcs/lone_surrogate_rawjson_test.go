// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// v2: the raw-JSON ingestion path. Go's encoding/json replaces a lone surrogate
// escape with U+FFFD during Unmarshal, so a post-parse byte scan sees nothing
// and would accept-and-hash a substituted value. ValidateJSONText / CanonicalizeJSON
// reject the raw text before decoding. Also: the general invalid-UTF-8 check on
// programmatic strings, and the cross-language error contract.
package jcs

import (
	"errors"
	"strings"
	"testing"
)

// --- raw-JSON layer: reject lone-surrogate escapes before the lossy decode ---

func TestRawJSONRejectsLoneSurrogate(t *testing.T) {
	cases := map[string]string{
		"value":         `{"x":"\uD800"}`,
		"lone-low":      `{"x":"\uDC00"}`,
		"member-name":   `{"\uD800":"x"}`,
		"nested":        `{"a":{"b":"\uD800"}}`,
		"array-element": `{"a":["\uD800"]}`,
		"mid-string":    `{"x":"a\uD800b"}`,
	}
	for name, raw := range cases {
		if err := ValidateJSONText([]byte(raw)); !errors.Is(err, ErrLoneSurrogate) {
			t.Errorf("%s: ValidateJSONText want ErrLoneSurrogate, got %v", name, err)
		}
		if _, err := CanonicalizeJSON([]byte(raw)); !errors.Is(err, ErrLoneSurrogate) {
			t.Errorf("%s: CanonicalizeJSON want ErrLoneSurrogate, got %v", name, err)
		}
	}
}

func TestRawJSONAcceptsGenuineReplacementChar(t *testing.T) {
	// A real U+FFFD in the input is a valid scalar and MUST be accepted. Do not
	// reject all U+FFFD as a shortcut.
	raw := "{\"x\":\"�\"}"
	got, err := CanonicalizeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("genuine U+FFFD rejected: %v", err)
	}
	if got != "{\"x\":\"�\"}" {
		t.Fatalf("U+FFFD canonical changed: got %q", got)
	}
}

func TestRawJSONEscapedBackslashNotFlagged(t *testing.T) {
	// {"x":"\\uD800"} is an escaped backslash then the literal text uD800, a valid
	// six-character string. It must NOT be flagged as a surrogate escape.
	raw := `{"x":"\\uD800"}`
	if err := ValidateJSONText([]byte(raw)); err != nil {
		t.Fatalf("escaped-backslash false positive: %v", err)
	}
}

func TestRawJSONEscapedValidPairAccepted(t *testing.T) {
	raw := `{"x":"😀"}` // escaped surrogate pair for U+1F600
	got, err := CanonicalizeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("valid escaped pair rejected: %v", err)
	}
	if got != "{\"x\":\"\U0001F600\"}" {
		t.Fatalf("escaped pair canonical wrong: got %q", got)
	}
}

func TestRawJSONValidPairFollowedByLoneLow(t *testing.T) {
	// A valid pair immediately followed by a lone low surrogate (the off-by-one
	// case): must still reject.
	raw := `{"x":"😀\uDC00"}`
	if err := ValidateJSONText([]byte(raw)); !errors.Is(err, ErrLoneSurrogate) {
		t.Fatalf("want ErrLoneSurrogate, got %v", err)
	}
}

// --- programmatic layer: general invalid UTF-8, not only the surrogate pattern ---

func TestRejectGeneralInvalidUTF8(t *testing.T) {
	bad := string([]byte{0xff, 0xfe}) // not valid UTF-8, not a surrogate pattern
	_, err := Canonicalize(map[string]interface{}{"v": bad})
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("want ErrInvalidUTF8, got %v", err)
	}
}

// --- error contract: catchable by errors.Is AND errors.As, stable category ---

func TestErrorContract(t *testing.T) {
	_, err := Canonicalize(map[string]interface{}{"v": loneHigh})
	if err == nil {
		t.Fatal("expected error")
	}
	// Existing fail-closed paths use `if err != nil`; that already handles it.
	if !errors.Is(err, ErrLoneSurrogate) {
		t.Errorf("errors.Is(ErrLoneSurrogate) failed")
	}
	var ce *CanonicalizationError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As(*CanonicalizationError) failed")
	}
	if ce.Category != "invalid_unicode" || ce.Reason != "lone_surrogate" {
		t.Errorf("category/reason = %q/%q, want invalid_unicode/lone_surrogate", ce.Category, ce.Reason)
	}
	// The offending bytes must NOT appear in the message (payloads may be sensitive).
	if strings.Contains(err.Error(), loneHigh) || strings.ContainsRune(err.Error(), 0xFFFD) {
		t.Errorf("error message leaked the offending string: %q", err.Error())
	}
}

func TestValidInputsUnchangedByRawLayer(t *testing.T) {
	// Regression: valid raw JSON canonicalizes identically through CanonicalizeJSON
	// and through decode+Canonicalize.
	raw := `{"b":1,"a":"x","n":[1,2,3],"z":null}`
	viaRaw, err := CanonicalizeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if viaRaw != `{"a":"x","b":1,"n":[1,2,3],"z":null}` {
		t.Fatalf("valid canonical wrong: %q", viaRaw)
	}
}
