// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Cross-language agreement matrix. Go, Rust and Python run this identical table
// of narrowing vectors and must return the same verdict for every cell. The
// three-hop spend rows distinguish a pairwise reading of the bounds from the
// effective-ceiling reading; the two-hop rows are the neighbour guard that must
// not move. The Rust twin is tests/xlang_matrix.rs and the Python twin is
// tests/test_xlang_matrix.py.

package verify

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aeoess/agent-passport-go/types"
)

func mk(by, to string, depth int, extra map[string]interface{}) types.Delegation {
	d := depth
	m := map[string]interface{}{
		"delegationId": by + "->" + to, "delegatedBy": by, "delegatedTo": to,
		"scope": []string{"data:read"}, "currentDepth": d,
	}
	for k, v := range extra {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	var out types.Delegation
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func verdict(chain []types.Delegation) string {
	if err := VerifyDelegationChain(chain); err != nil {
		return "REJECT"
	}
	return "ACCEPT"
}

func TestXLangMatrix(t *testing.T) {
	e := func(kv ...interface{}) map[string]interface{} {
		m := map[string]interface{}{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	d5 := func(extra map[string]interface{}) map[string]interface{} {
		extra["maxDepth"] = 5
		return extra
	}
	three := func(a, b, c map[string]interface{}) []types.Delegation {
		return []types.Delegation{mk("root", "a", 0, a), mk("a", "b", 1, b), mk("b", "c", 2, c)}
	}
	two := func(a, b map[string]interface{}) []types.Delegation {
		return []types.Delegation{mk("root", "a", 0, a), mk("a", "b", 1, b)}
	}
	rows := []struct {
		name  string
		chain []types.Delegation
	}{
		{"spend/100->absent->1000000", three(d5(e("spendLimit", 100)), d5(e()), d5(e("spendLimit", 1000000)))},
		{"spend/100->absent->50", three(d5(e("spendLimit", 100)), d5(e()), d5(e("spendLimit", 50)))},
		{"spend/100->100->100", three(d5(e("spendLimit", 100)), d5(e("spendLimit", 100)), d5(e("spendLimit", 100)))},
		{"spend/100->50->50", three(d5(e("spendLimit", 100)), d5(e("spendLimit", 50)), d5(e("spendLimit", 50)))},
		{"spend/100->101->101", three(d5(e("spendLimit", 100)), d5(e("spendLimit", 101)), d5(e("spendLimit", 101)))},
		{"spend2/100->100", two(d5(e("spendLimit", 100)), d5(e("spendLimit", 100)))},
		{"spend2/100->50", two(d5(e("spendLimit", 100)), d5(e("spendLimit", 50)))},
		{"spend2/100->101", two(d5(e("spendLimit", 100)), d5(e("spendLimit", 101)))},
		{"unit/USD->absent->JPY50", three(d5(e("spendLimit", 100, "spendLimitUnit", "USD")), d5(e()), d5(e("spendLimit", 50, "spendLimitUnit", "JPY")))},
		{"unit/USD->absent->unitless50", three(d5(e("spendLimit", 100, "spendLimitUnit", "USD")), d5(e()), d5(e("spendLimit", 50)))},
		{"unit/USD->absent->absent", three(d5(e("spendLimit", 100, "spendLimitUnit", "USD")), d5(e()), d5(e()))},
		{"unit/USD->absent->USD50", three(d5(e("spendLimit", 100, "spendLimitUnit", "USD")), d5(e()), d5(e("spendLimit", 50, "spendLimitUnit", "USD")))},
		{"unit/USD->absent->USD101", three(d5(e("spendLimit", 100, "spendLimitUnit", "USD")), d5(e()), d5(e("spendLimit", 101, "spendLimitUnit", "USD")))},
		{"depth/max1->absent->depth2", three(e("maxDepth", 1), e(), e())},
		{"depth/max1->99->depth2", three(e("maxDepth", 1), e("maxDepth", 99), e("maxDepth", 99))},
		{"depth/max2->absent->depth2", three(e("maxDepth", 2), e(), e())},
		{"depth/flat", two(d5(e()), d5(e("currentDepth", 0)))},
		{"depth/increment", two(d5(e()), d5(e()))},
		{"nbf/2026-06->absent->2020", three(d5(e("notBefore", "2026-06-01T00:00:00Z")), d5(e()), d5(e("notBefore", "2020-01-01T00:00:00Z")))},
		{"nbf/2026-06->absent->absent", three(d5(e("notBefore", "2026-06-01T00:00:00Z")), d5(e()), d5(e()))},
		{"nbf/2026-06->absent->2026-07", three(d5(e("notBefore", "2026-06-01T00:00:00Z")), d5(e()), d5(e("notBefore", "2026-07-01T00:00:00Z")))},
		{"exp/2030->absent", two(d5(e("expiresAt", "2030-01-01T00:00:00Z")), d5(e()))},
		{"exp/2030->2099", two(d5(e("expiresAt", "2030-01-01T00:00:00Z")), d5(e("expiresAt", "2099-01-01T00:00:00Z")))},
		{"exp/2030->2029", two(d5(e("expiresAt", "2030-01-01T00:00:00Z")), d5(e("expiresAt", "2029-01-01T00:00:00Z")))},
		{"scope/read->absent->wildcard", []types.Delegation{mk("root", "a", 0, d5(e("scope", []string{"data:read"}))), mk("a", "b", 1, d5(e("scope", []string{}))), mk("b", "c", 2, d5(e("scope", []string{"data:*"})))}},
		{"scope/read->absent->absent", []types.Delegation{mk("root", "a", 0, d5(e("scope", []string{"data:read"}))), mk("a", "b", 1, d5(e("scope", []string{}))), mk("b", "c", 2, d5(e("scope", []string{})))}},
		{"empty-chain", []types.Delegation{}},
	}
	// The pinned cross-language verdict for every cell. Go, Rust and Python
	// run the identical table (verify/xlang_matrix_test.go,
	// tests/xlang_matrix.rs, tests/test_xlang_matrix.py) and must agree on
	// every one, so a divergence fails here rather than in production.
	want := map[string]string{
		"spend/100->absent->1000000":   "REJECT",
		"spend/100->absent->50":        "ACCEPT",
		"spend/100->100->100":          "ACCEPT",
		"spend/100->50->50":            "ACCEPT",
		"spend/100->101->101":          "REJECT",
		"spend2/100->100":              "ACCEPT",
		"spend2/100->50":               "ACCEPT",
		"spend2/100->101":              "REJECT",
		"unit/USD->absent->JPY50":      "REJECT",
		"unit/USD->absent->unitless50": "REJECT",
		"unit/USD->absent->absent":     "ACCEPT",
		"unit/USD->absent->USD50":      "ACCEPT",
		"unit/USD->absent->USD101":     "REJECT",
		"depth/max1->absent->depth2":   "REJECT",
		"depth/max1->99->depth2":       "REJECT",
		"depth/max2->absent->depth2":   "ACCEPT",
		"depth/flat":                   "REJECT",
		"depth/increment":              "ACCEPT",
		"nbf/2026-06->absent->2020":    "REJECT",
		"nbf/2026-06->absent->absent":  "ACCEPT",
		"nbf/2026-06->absent->2026-07": "ACCEPT",
		"exp/2030->absent":             "REJECT",
		"exp/2030->2099":               "REJECT",
		"exp/2030->2029":               "ACCEPT",
		"scope/read->absent->wildcard": "REJECT",
		"scope/read->absent->absent":   "ACCEPT",
		"empty-chain":                  "REJECT",
		"malformed/spendLimit-string":  "REJECT",
	}
	for _, r := range rows {
		got := verdict(r.chain)
		fmt.Printf("CELL %s = %s\n", r.name, got)
		if w, ok := want[r.name]; !ok {
			t.Errorf("%s: no pinned verdict", r.name)
		} else if got != w {
			t.Errorf("%s: got %s, want %s", r.name, got, w)
		}
	}
	// Malformed ceiling: Go refuses at decode time (*float64), which is the
	// same refusal the other two report at verify time.
	var probe types.Delegation
	err := json.Unmarshal([]byte(`{"delegationId":"x","delegatedBy":"root","delegatedTo":"a","scope":["data:read"],"spendLimit":"999"}`), &probe)
	if err != nil {
		fmt.Printf("CELL malformed/spendLimit-string = REJECT\n")
		if want["malformed/spendLimit-string"] != "REJECT" {
			t.Error("malformed ceiling must be refused")
		}
	} else {
		fmt.Printf("CELL malformed/spendLimit-string = ACCEPT\n")
		t.Error("a string spendLimit must not decode into a typed Delegation")
	}
}
