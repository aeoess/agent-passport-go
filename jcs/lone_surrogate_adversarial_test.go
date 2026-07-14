// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Pinned adversarial cases for the raw-JSON surrogate-escape scanner
// (ValidateJSONText). The scanner is string-aware and escape-aware; these cases
// lock in its behavior so a future refactor cannot silently regress it. Each
// input is raw JSON text (a Go raw string literal, so \uXXXX is literal text).
package jcs

import (
	"errors"
	"testing"
)

func TestScannerAdversarialCases(t *testing.T) {
	reject := []struct{ name, raw string }{
		{"space-separated-non-adjacent", `{"v":"\uD800 \uDC00"}`},
		{"newline-separated-non-adjacent", `{"v":"\uD800\n\uDC00"}`},
		{"lone-low-first", `{"v":"\uDC00"}`},
		{"low-then-high", `{"v":"\uDC00\uD800"}`},
		{"high-then-literal-low", `{"v":"\uD800\\uDC00"}`},
		{"lone-in-key", `{"\uD800":"x"}`},
		{"lowercase-hex", `{"v":"\ud800"}`},
		{"literal-backslash-then-lone", `{"v":"\\\uD800"}`},
	}
	for _, c := range reject {
		if err := ValidateJSONText([]byte(c.raw)); !errors.Is(err, ErrLoneSurrogate) {
			t.Errorf("%s: want ErrLoneSurrogate, got %v", c.name, err)
		}
	}

	accept := []struct{ name, raw string }{
		{"valid-adjacent-pair", `{"v":"😀"}`},
		{"escaped-backslash-literal", `{"v":"\\uD800"}`},
		{"double-backslash-literal", `{"v":"\\\\uD800"}`},
	}
	for _, c := range accept {
		if err := ValidateJSONText([]byte(c.raw)); err != nil {
			t.Errorf("%s: want accept, got %v", c.name, err)
		}
	}
}
