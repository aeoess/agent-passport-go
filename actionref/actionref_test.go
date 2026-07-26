// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package actionref

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestNormalizeTimestamp(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-06-02T12:00:00.000Z", "2026-06-02T12:00:00Z"},
		{"2026-06-02T12:00:00Z", "2026-06-02T12:00:00Z"},
		{"2026-06-02T12:00:00.123Z", "2026-06-02T12:00:00Z"},  // sub-second truncated
		{"2026-06-02T14:00:00+02:00", "2026-06-02T12:00:00Z"}, // offset converted to UTC
		{"2026-06-02T12:00:00.999999Z", "2026-06-02T12:00:00Z"},
	}
	for _, c := range cases {
		got, err := NormalizeTimestamp(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeTimestamp(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := NormalizeTimestamp("not-a-timestamp"); err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

// TestActionRefCrossImpl pins the value cross-checked at build time against the
// reference TypeScript computeActionRef (src/core/action-ref.ts). Both
// implementations produced this exact hex for the same intent; see the Phase 3
// build report. This guards against any future drift in either the JCS path or
// the timestamp normalization.
func TestActionRefCrossImpl(t *testing.T) {
	const want = "575878c62491d45459394dac7093b04316cdd3ecbe2718c0698192698153ddf6"
	got, err := ComputeActionRef("ag_test_001", "code_execution", "compute:exec", "2026-06-02T12:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("ComputeActionRef = %s, want %s (TS reference)", got, want)
	}
}

// TestActionRefStableUnderTimestampPrecision confirms two requests in the same
// second produce the same action_ref regardless of sub-second precision, which
// is the whole point of second-precision normalization.
func TestActionRefStableUnderTimestampPrecision(t *testing.T) {
	a, err := ComputeActionRef("ag_x", "web_search", "data:read", "2026-06-02T12:00:00.001Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeActionRef("ag_x", "web_search", "data:read", "2026-06-02T12:00:00.999Z")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("action_ref differs within the same second: %s vs %s", a, b)
	}
	if !Match(a, b) {
		t.Error("Match should report true for identical action_ref")
	}
}

// TestActionRefScopesOrderInsensitive mirrors T1 case (a): unsorted multi-scope
// ASCII input produces the same ref as sorted input.
func TestActionRefScopesOrderInsensitive(t *testing.T) {
	a, err := ComputeActionRefScopes("ag_x", "commerce_preflight", []string{"commerce:write", "commerce:read"}, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeActionRefScopes("ag_x", "commerce_preflight", []string{"commerce:read", "commerce:write"}, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("scope order changed action_ref: %s vs %s", a, b)
	}
}

// TestActionRefScopesNFCEquivalence mirrors T1 case (b): NFD and NFC forms of
// the same scope produce equal refs. "cafe" plus U+0301 combining acute is the
// NFD form of the precomposed U+00E9 form.
func TestActionRefScopesNFCEquivalence(t *testing.T) {
	nfd := "cafe\u0301:read"
	nfc := "caf\u00e9:read"
	a, err := ComputeActionRefScopes("ag_x", "web_search", []string{nfd}, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeActionRefScopes("ag_x", "web_search", []string{nfc}, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("NFD and NFC forms produced different refs: %s vs %s", a, b)
	}
	// The single-string legacy form gets the same NFC treatment.
	c, err := ComputeActionRef("ag_x", "web_search", nfd, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ComputeActionRef("ag_x", "web_search", nfc, "2026-06-02T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if c != d {
		t.Errorf("legacy form: NFD and NFC produced different refs: %s vs %s", c, d)
	}
}

// TestActionRefScopesCodePointOrder mirrors T1 case (c): a scope containing an
// astral-plane character (U+10000) sorts AFTER a scope in the U+E000..U+FFFF
// range under code-point order. A UTF-16 code-unit sort would misorder these,
// because U+10000 encodes as a surrogate pair starting at 0xD800, which is
// below 0xE000. sort.Strings on UTF-8 bytes gives the code-point order the
// spec requires.
func TestActionRefScopesCodePointOrder(t *testing.T) {
	astral := "\U00010000:x"
	bmpHigh := "\ue000:x"
	got, err := CanonicalizeScopes([]string{astral, bmpHigh})
	if err != nil {
		t.Fatalf("CanonicalizeScopes: %v", err)
	}
	if got[0] != bmpHigh || got[1] != astral {
		t.Errorf("code-point order violated: got %q first, want %q first", got[0], bmpHigh)
	}
}

// TestCanonicalizeScopesDoesNotMutateCaller pins the copied-slice requirement.
func TestCanonicalizeScopesDoesNotMutateCaller(t *testing.T) {
	in := []string{"b:scope", "a:scope"}
	if _, err := CanonicalizeScopes(in); err != nil {
		t.Fatalf("CanonicalizeScopes: %v", err)
	}
	if in[0] != "b:scope" || in[1] != "a:scope" {
		t.Errorf("caller slice mutated: %v", in)
	}
}

// Section 4.1 defines scope_required as a duplicate-free array. A duplicated
// array has no canonical form, so it is rejected rather than deduplicated: a
// silent dedupe would map ["a","a"] and ["a"] onto one identity with no error,
// and would change the identity previously computed for the duplicated input.
func TestCanonicalizeScopesRejectsRawDuplicate(t *testing.T) {
	_, err := CanonicalizeScopes([]string{"a", "a"})
	if !errors.Is(err, ErrDuplicateScopeRequired) {
		t.Fatalf("want ErrDuplicateScopeRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "duplicate_scope_required") {
		t.Errorf("error string must name duplicate_scope_required: %q", err.Error())
	}
	// rejection, not dedupe: the single-element form still canonicalizes
	got, err := CanonicalizeScopes([]string{"a"})
	if err != nil || len(got) != 1 {
		t.Errorf("single element must still canonicalize: %v %v", got, err)
	}
	// and the same rejection surfaces through the identity entry point
	if _, err := ComputeActionRefScopes("a", "t", []string{"a", "a"},
		"2026-07-10T00:00:00Z"); !errors.Is(err, ErrDuplicateScopeRequired) {
		t.Errorf("ComputeActionRefScopes must reject duplicates: %v", err)
	}
}

func TestCanonicalizeScopesRejectsNFCCollidingDuplicate(t *testing.T) {
	precomposed := "\u00e9" // U+00E9
	decomposed := "e\u0301" // e followed by U+0301 combining acute
	if precomposed == decomposed {
		t.Fatal("test inputs must differ before normalization")
	}
	if norm.NFC.String(precomposed) != norm.NFC.String(decomposed) {
		t.Fatal("test inputs must collide under NFC")
	}
	_, err := CanonicalizeScopes([]string{precomposed, decomposed})
	if !errors.Is(err, ErrDuplicateScopeRequired) {
		t.Fatalf("want ErrDuplicateScopeRequired, got %v", err)
	}
}

// TestValidVectorsByteUnchanged pins that the duplicate rejection leaves every
// shared cross-language vector byte-identical, asserted against the recorded
// action_ref values rather than recomputed ones.
func TestValidVectorsByteUnchanged(t *testing.T) {
	_, vectors := loadVectors(t)
	for _, v := range vectors {
		got, err := ComputeActionRefScopes(v.Input.AgentID, v.Input.ActionType, v.Input.ScopeRequired, v.Input.Timestamp)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got != v.ActionRef {
			t.Errorf("%s: action_ref = %s, want %s", v.Name, got, v.ActionRef)
		}
	}
}
