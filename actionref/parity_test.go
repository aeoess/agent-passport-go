// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package actionref

import (
	"encoding/json"
	"os"
	"testing"
)

// The TS side (sprint task T1) publishes canonical action_ref vectors in an
// external workspace, not in this repo. Point APS_SPRINT_VECTORS at that file to
// run the cross-implementation parity assertions (byte-identical hex, canonical
// scope order) for the spec cases in draft-pidlisnyi-aps-03 section 4.1. When
// APS_SPRINT_VECTORS is unset or its file is unavailable, the parity test skips:
// the vectors are external, so there is nothing to compare against.

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
	path := os.Getenv("APS_SPRINT_VECTORS")
	if path == "" {
		t.Skip("APS_SPRINT_VECTORS not set; sprint parity vectors are external")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("APS_SPRINT_VECTORS points at an unavailable file (%v); sprint parity vectors are external", err)
	}
	var vecs []canonicalVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		var wrapped struct {
			Vectors []canonicalVector `json:"vectors"`
		}
		if werr := json.Unmarshal(data, &wrapped); werr != nil {
			t.Fatalf("parse %s: %v (wrapper: %v)", path, err, werr)
		}
		vecs = wrapped.Vectors
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
		canon, err := CanonicalizeScopes(v.Input.ScopeRequired)
		if err != nil {
			t.Errorf("%s: CanonicalizeScopes: %v", v.Name, err)
			continue
		}
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
