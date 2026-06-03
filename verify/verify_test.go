// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package verify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/types"
)

func decode(t *testing.T, raw []byte) interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

// TestEd25519AgainstBilateralFixture verifies every bilateral-delegation vector
// signature against the canonical bytes our JCS produces. The signatures and
// pubkeys ship with the fixture; a valid verify proves both the JCS bytes and
// the Ed25519 path are correct end to end.
func TestEd25519AgainstBilateralFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/bilateral-canonicalize-fixture-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Vectors []struct {
			Name    string          `json:"name"`
			Input   json.RawMessage `json:"input"`
			SigHex  string          `json:"ed25519_signature_over_canonical_hex"`
			PubHex  string          `json:"ed25519_pubkey_hex"`
			ExpectV bool            `json:"expected_verification"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse: %v", err)
	}
	pass := 0
	for _, v := range fx.Vectors {
		canon, err := jcs.Canonicalize(decode(t, v.Input))
		if err != nil {
			t.Errorf("%s: canon: %v", v.Name, err)
			continue
		}
		ok := VerifyEd25519([]byte(canon), v.SigHex, v.PubHex)
		if ok != v.ExpectV {
			t.Errorf("%s: VerifyEd25519 = %v, want %v", v.Name, ok, v.ExpectV)
			continue
		}
		pass++
	}
	t.Logf("bilateral ed25519: %d/%d vectors verified as expected", pass, len(fx.Vectors))
	// Negative control: flipping a byte of the signature must fail.
	if len(fx.Vectors) > 0 {
		v := fx.Vectors[0]
		canon, _ := jcs.Canonicalize(decode(t, v.Input))
		bad := "00" + v.SigHex[2:]
		if VerifyEd25519([]byte(canon), bad, v.PubHex) {
			t.Error("tampered signature verified true (must be false)")
		}
	}
}

// TestCompositionNegativePaths runs the shared a2a-1496 negative-path fixtures
// and asserts ValidateChain returns the exact pinned error code for each.
func TestCompositionNegativePaths(t *testing.T) {
	files, err := filepath.Glob("testdata/composition/*.fixture.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no composition fixtures: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var fx struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			ExpectedErrorCode string          `json:"expected_error_code"`
		}
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		var in ChainInput
		dec := json.NewDecoder(bytes.NewReader(fx.Input))
		dec.UseNumber()
		if err := dec.Decode(&in); err != nil {
			t.Fatalf("decode chain %s: %v", f, err)
		}
		got := ValidateChain(in)
		if got != fx.ExpectedErrorCode {
			t.Errorf("%s [%s]: ValidateChain = %q, want %q", filepath.Base(f), fx.Name, got, fx.ExpectedErrorCode)
		} else {
			t.Logf("%s: refused with %s (as pinned)", fx.Name, got)
		}
	}
}

// TestValidChainAccepts proves the validator accepts a good link, not just
// rejects bad ones. The root link of the scope-expansion fixture has a valid
// signature and validity window; a one-link chain over it must pass.
func TestValidChainAccepts(t *testing.T) {
	raw, err := os.ReadFile("testdata/composition/01-scope-expansion.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Input struct {
			Chain []json.RawMessage `json:"chain"`
			Now   string            `json:"now"`
		} `json:"input"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(fx.Input.Chain[0]))
	dec.UseNumber()
	var root map[string]interface{}
	if err := dec.Decode(&root); err != nil {
		t.Fatal(err)
	}
	big := 10
	got := ValidateChain(ChainInput{Chain: []map[string]interface{}{root}, MaxDepth: &big, Now: fx.Input.Now})
	if got != "" {
		t.Errorf("valid root-only chain refused with %q, want accept", got)
	}
}

func TestScopeCovers(t *testing.T) {
	cases := []struct {
		granted, required string
		want              bool
	}{
		{"data:read", "data:read", true},
		{"*", "anything:here", true},
		{"data", "data:read", true},          // prefix
		{"refund:order:*", "refund:order:abc", true},
		{"refund:order:*", "refund:order", true},
		{"data:read", "data:write", false},
		{"refund:order:*", "refund:invoice:abc", false},
		{"data:read", "data", false},
	}
	for _, c := range cases {
		if got := ScopeCovers(c.granted, c.required); got != c.want {
			t.Errorf("ScopeCovers(%q,%q)=%v want %v", c.granted, c.required, got, c.want)
		}
	}
}

func TestVerifyDelegationChainTyped(t *testing.T) {
	d := func(n int) *int { return &n }
	f := func(v float64) *float64 { return &v }
	parent := types.Delegation{
		DelegationID: "del_root", DelegatedBy: "did:aps:p", DelegatedTo: "did:aps:a",
		Scope: []string{"data:*"}, MaxDepth: d(3), CurrentDepth: d(0), SpendLimit: f(500),
		ExpiresAt: "2026-12-31T00:00:00Z",
	}
	// Valid narrowing child.
	good := types.Delegation{
		DelegationID: "del_child", DelegatedBy: "did:aps:a", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, MaxDepth: d(3), CurrentDepth: d(1), SpendLimit: f(200),
		ExpiresAt: "2026-06-30T00:00:00Z",
	}
	if err := VerifyDelegationChain([]types.Delegation{parent, good}); err != nil {
		t.Errorf("valid chain rejected: %v", err)
	}
	// Scope widening.
	wide := good
	wide.Scope = []string{"commerce:checkout"}
	if err := VerifyDelegationChain([]types.Delegation{parent, wide}); err == nil {
		t.Error("scope-widening child accepted (must reject)")
	}
	// Spend widening.
	spend := good
	spend.SpendLimit = f(900)
	if err := VerifyDelegationChain([]types.Delegation{parent, spend}); err == nil {
		t.Error("spend-widening child accepted (must reject)")
	}
	// Depth exceed.
	deep := good
	deep.CurrentDepth = d(4)
	if err := VerifyDelegationChain([]types.Delegation{parent, deep}); err == nil {
		t.Error("depth-exceeding child accepted (must reject)")
	}
	// Broken linkage.
	orphan := good
	orphan.DelegatedBy = "did:aps:someone-else"
	if err := VerifyDelegationChain([]types.Delegation{parent, orphan}); err == nil {
		t.Error("broken-linkage child accepted (must reject)")
	}
}
