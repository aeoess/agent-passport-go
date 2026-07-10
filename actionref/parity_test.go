// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package actionref

import (
	"encoding/json"
	"os"
	"testing"
)

// sprintVectorsPath is where the TS side (sprint task T1) publishes its
// canonical action_ref vectors. When that file exists this test runs against
// it, asserting byte-identical hex across implementations. Until then it runs
// against the Go-side vectors in testdata, which pin the same spec cases
// (draft-pidlisnyi-aps-03 section 4.1) as regression anchors.
const sprintVectorsPath = "/Users/tima/aeoess-private/sprint-vwe/vectors-actionref.json"

type canonicalVector struct {
	Name  string `json:"name"`
	Input struct {
		AgentID       string   `json:"agentId"`
		ActionType    string   `json:"actionType"`
		ScopeRequired []string `json:"scopeRequired"`
		Timestamp     string   `json:"timestamp"`
	} `json:"input"`
	CanonicalScopeOrder []string `json:"canonical_scope_order"`
	ActionRef           string   `json:"action_ref"`
}

func loadVectors(t *testing.T) (string, []canonicalVector) {
	t.Helper()
	path := sprintVectorsPath
	data, err := os.ReadFile(path)
	if err != nil {
		path = "testdata/actionref-canonical-vectors.json"
		data, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("no vector file available: %v", err)
		}
	}
	var vecs []canonicalVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(vecs) == 0 {
		t.Fatalf("vector file %s is empty", path)
	}
	return path, vecs
}

// TestActionRefCanonicalVectors asserts byte-identical action_ref hex for
// every vector, and that CanonicalizeScopes reproduces the recorded canonical
// scope order.
func TestActionRefCanonicalVectors(t *testing.T) {
	path, vecs := loadVectors(t)
	t.Logf("vectors from %s (%d entries)", path, len(vecs))
	for _, v := range vecs {
		got, err := ComputeActionRefScopes(v.Input.AgentID, v.Input.ActionType, v.Input.ScopeRequired, v.Input.Timestamp)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if got != v.ActionRef {
			t.Errorf("%s: action_ref = %s, want %s", v.Name, got, v.ActionRef)
		}
		canon := CanonicalizeScopes(v.Input.ScopeRequired)
		if len(canon) != len(v.CanonicalScopeOrder) {
			t.Errorf("%s: canonical order length %d, want %d", v.Name, len(canon), len(v.CanonicalScopeOrder))
			continue
		}
		for i := range canon {
			if canon[i] != v.CanonicalScopeOrder[i] {
				t.Errorf("%s: canonical order[%d] = %q, want %q", v.Name, i, canon[i], v.CanonicalScopeOrder[i])
			}
		}
	}
}
