// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// RFC 8785: Canonicalize must reject lone/unpaired UTF-16 surrogates. A lone
// surrogate is not a valid Unicode scalar and has no UTF-8 encoding, so the
// input is invalid and must be rejected, not replaced with U+FFFD. A valid
// non-BMP scalar (a well-formed surrogate pair in UTF-16) must still
// canonicalize to its raw UTF-8 bytes.
package jcs

import (
	"errors"
	"testing"
)

var (
	loneHigh = string([]byte{0xED, 0xA0, 0x80}) // WTF-8 encoding of U+D800
	loneLow  = string([]byte{0xED, 0xBF, 0xBF}) // WTF-8 encoding of U+DFFF
	emoji    = "\U0001F600"                     // valid non-BMP scalar U+1F600
)

func TestRejectLoneHighSurrogate(t *testing.T) {
	if _, err := Canonicalize(map[string]interface{}{"v": loneHigh}); !errors.Is(err, ErrLoneSurrogate) {
		t.Fatalf("want ErrLoneSurrogate, got %v", err)
	}
}

func TestRejectLoneLowSurrogate(t *testing.T) {
	if _, err := Canonicalize(map[string]interface{}{"v": loneLow}); !errors.Is(err, ErrLoneSurrogate) {
		t.Fatalf("want ErrLoneSurrogate, got %v", err)
	}
}

func TestRejectLoneSurrogateAfterValidPair(t *testing.T) {
	// A valid non-BMP scalar followed by a lone surrogate: detection must not be
	// fooled by the earlier valid character.
	if _, err := Canonicalize(map[string]interface{}{"v": emoji + loneHigh}); !errors.Is(err, ErrLoneSurrogate) {
		t.Fatalf("want ErrLoneSurrogate, got %v", err)
	}
}

func TestRejectLoneSurrogateInKey(t *testing.T) {
	if _, err := Canonicalize(map[string]interface{}{loneHigh: "x"}); !errors.Is(err, ErrLoneSurrogate) {
		t.Fatalf("want ErrLoneSurrogate, got %v", err)
	}
}

func TestValidNonBMPUnchanged(t *testing.T) {
	got, err := Canonicalize(map[string]interface{}{"v": emoji})
	if err != nil {
		t.Fatalf("valid non-BMP rejected: %v", err)
	}
	want := "{\"v\":\"\U0001F600\"}"
	if got != want {
		t.Fatalf("non-BMP canonical changed:\n got %q\nwant %q", got, want)
	}
	// Raw 4-byte UTF-8 of U+1F600, unchanged by this fix.
	if []byte(got)[6] != 0xF0 {
		t.Fatalf("expected raw UTF-8 emoji bytes, got % x", []byte(got))
	}
}

func TestValidHangulD7FFNotFlagged(t *testing.T) {
	// U+D7FF (ED 9F BF) is a valid scalar just below the surrogate range and must
	// NOT be flagged (the detector keys on the 0xA0..0xBF second byte).
	if _, err := Canonicalize(map[string]interface{}{"v": "\uD7FF"}); err != nil {
		t.Fatalf("valid U+D7FF rejected: %v", err)
	}
}
