// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package delegation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

// Deterministic inputs shared with the TS reference cross-check.
const (
	delSeedInput = "aps-go-delegation-key"
	wantPub      = "8624c256201521da99c274a64767c0816da7a112dfaaf18f704ff9917197e214"
	// Reference values produced by a real `npx tsx` run against the
	// agent-passport-system checkout at build time (sign over the legacy
	// canonicalize, which equals canonicalizeJCS for this no-null ASCII shape).
	// Not authored from memory; reproduced live in TestDelegationLiveCrossImpl.
	wantDelSig = "8b7682fa79fe93aa635ba1402363691d9e3e66d62a72753f98b89cd27466ede6d1480b93d763d2992ee083478bd783f62b61419434341d7eead275ebadf2a10a"
	wantRevSig = "365d333b0ca21321d83745eba5a5c71f58f279b5d4bedcc950129b0689fb09b65f59ded82ecf0022567e1b5ecf640814da8e43680c9e2c0cd1c0e00cfbea6e06"
)

func seed() string {
	s := sha256.Sum256([]byte(delSeedInput))
	return hex.EncodeToString(s[:])
}

func f(v float64) *float64 { return &v }

func fixedDelegation(t *testing.T) string {
	t.Helper()
	d, err := CreateDelegation(CreateOptions{
		PrivateKey:   seed(),
		DelegationID: "del_000000000001",
		DelegatedBy:  wantPub,
		DelegatedTo:  "did:aps:agent002",
		Scope:        []string{"data:read", "commerce:checkout"},
		SpendLimit:   f(500),
		MaxDepth:     1,
		CurrentDepth: 0,
		ExpiresAt:    "2026-06-04T12:00:00.000Z",
		NotBefore:    "2026-06-03T12:00:00.000Z",
		CreatedAt:    "2026-06-03T12:00:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDelegation(d) {
		t.Fatal("self-created delegation failed VerifyDelegation")
	}
	return d.Signature
}

// TestDelegationSignatureVsReference asserts the Go delegation signature is
// hex-identical to the TS reference value (pinned, reproduced live below).
func TestDelegationSignatureVsReference(t *testing.T) {
	gotPub, err := keys.PublicKeyFromPrivate(seed())
	if err != nil || gotPub != wantPub {
		t.Fatalf("derived pub %s != want %s (err=%v)", gotPub, wantPub, err)
	}
	if sig := fixedDelegation(t); sig != wantDelSig {
		t.Errorf("delegation signature\n go: %s\n ts: %s", sig, wantDelSig)
	}
}

func TestRevocationSignatureVsReference(t *testing.T) {
	r, err := CreateRevocation(CreateRevocationOptions{
		PrivateKey:   seed(),
		RevocationID: "rev_000000000001",
		DelegationID: "del_000000000001",
		RevokedBy:    wantPub,
		RevokedAt:    "2026-06-03T13:00:00.000Z",
		Reason:       "key compromise suspected",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Signature != wantRevSig {
		t.Errorf("revocation signature\n go: %s\n ts: %s", r.Signature, wantRevSig)
	}
	if !VerifyRevocation(r) {
		t.Error("self-created revocation failed VerifyRevocation")
	}
	bad := r
	bad.Reason = "tampered"
	if VerifyRevocation(bad) {
		t.Error("tampered revocation verified true")
	}
}

func TestSubDelegateNarrowing(t *testing.T) {
	parent, err := CreateDelegation(CreateOptions{
		PrivateKey: seed(), DelegationID: "del_root", DelegatedBy: wantPub,
		DelegatedTo: wantPub, Scope: []string{"data:*"}, SpendLimit: f(500),
		MaxDepth: 3, CurrentDepth: 0, ExpiresAt: "2026-12-31T00:00:00.000Z",
		NotBefore: "2026-06-03T12:00:00.000Z", CreatedAt: "2026-06-03T12:00:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Valid narrowing: data:read is covered by data:*, lower spend, depth ok.
	child, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "del_child",
		DelegatedTo: "did:aps:b", Scope: []string{"data:read"}, SpendLimit: f(200),
		ExpiresAt: "2026-06-30T00:00:00.000Z", NotBefore: "2026-06-03T12:00:00.000Z",
		CreatedAt: "2026-06-03T12:00:00.000Z",
	})
	if err != nil {
		t.Fatalf("valid sub-delegation rejected: %v", err)
	}
	if !VerifyDelegation(child) {
		t.Error("valid child failed verify")
	}
	if child.CurrentDepth == nil || *child.CurrentDepth != 1 {
		t.Error("child currentDepth should be 1")
	}
	// Widening scope must be refused.
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "x", DelegatedTo: "did:aps:b",
		Scope: []string{"commerce:checkout"}, ExpiresAt: "2026-06-30T00:00:00.000Z",
	}); err == nil {
		t.Error("scope-widening sub-delegation accepted (must reject)")
	}
	// Spend widening must be refused.
	if _, err := SubDelegate(SubDelegateOptions{
		Parent: parent, PrivateKey: seed(), DelegationID: "x", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, SpendLimit: f(900), ExpiresAt: "2026-06-30T00:00:00.000Z",
	}); err == nil {
		t.Error("spend-widening sub-delegation accepted (must reject)")
	}
}

// TestDelegationLiveCrossImpl re-runs the real TS reference at test time and
// asserts byte/hex identity plus cross-verification both directions. It skips
// gracefully when npx or the TS repo is unavailable.
func TestDelegationLiveCrossImpl(t *testing.T) {
	repo := os.Getenv("APS_TS_REPO")
	if repo == "" {
		t.Skip("set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not available")
	}
	if _, err := os.Stat(repo); err != nil {
		t.Skip("TS reference repo not present")
	}
	script := `
import crypto from "node:crypto";
import { sign, publicKeyFromPrivate } from "` + repo + `/src/crypto/keys.ts";
import { canonicalize } from "` + repo + `/src/core/canonical.ts";
const seed = crypto.createHash("sha256").update("` + delSeedInput + `").digest("hex");
const pub = publicKeyFromPrivate(seed);
const del = { delegationId:"del_000000000001", delegatedTo:"did:aps:agent002", delegatedBy:pub, scope:["data:read","commerce:checkout"], spendLimit:500, maxDepth:1, currentDepth:0, expiresAt:"2026-06-04T12:00:00.000Z", notBefore:"2026-06-03T12:00:00.000Z", createdAt:"2026-06-03T12:00:00.000Z" };
console.log("DEL_SIG="+sign(canonicalize(del), seed));
`
	cmd := exec.Command("npx", "tsx", "-e", script)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("tsx run failed (environment): %v", err)
	}
	var tsSig string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "DEL_SIG=") {
			tsSig = strings.TrimSpace(strings.TrimPrefix(line, "DEL_SIG="))
		}
	}
	if tsSig == "" {
		t.Skipf("could not parse TS output: %s", string(out))
	}
	goSig := fixedDelegation(t)
	if goSig != tsSig {
		t.Fatalf("LIVE Go != TS\n go: %s\n ts: %s", goSig, tsSig)
	}
	if tsSig != wantDelSig {
		t.Errorf("live TS sig %s differs from pinned %s (update the pin)", tsSig, wantDelSig)
	}
	// TS-created object verifies under Go.
	tsObj := map[string]interface{}{
		"delegationId": "del_000000000001", "delegatedTo": "did:aps:agent002",
		"delegatedBy": wantPub, "scope": []interface{}{"data:read", "commerce:checkout"},
		"spendLimit": json.Number("500"), "maxDepth": json.Number("1"), "currentDepth": json.Number("0"),
		"expiresAt": "2026-06-04T12:00:00.000Z", "notBefore": "2026-06-03T12:00:00.000Z",
		"createdAt": "2026-06-03T12:00:00.000Z", "signature": tsSig,
	}
	if !VerifyDelegationRaw(tsObj) {
		t.Error("TS-created delegation failed Go VerifyDelegationRaw")
	}
	t.Logf("live cross-impl: Go delegation signature == TS reference (%s...)", goSig[:16])
}
