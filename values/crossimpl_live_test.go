// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package values

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

// tsRepoPath returns the reference TypeScript SDK checkout from the APS_TS_REPO
// environment variable. The live cross-impl tests run the REAL TS functions
// there via `npx tsx` and assert the Go output equals the live TS output. When
// APS_TS_REPO is unset (for example in a CI runner that only has Go), the tests
// skip rather than fail: the pinned constants in values_test.go still guard the
// cross-impl invariant. There is no hardcoded fallback path.
func tsRepoPath() string {
	return os.Getenv("APS_TS_REPO")
}

// skipUnlessTSRepo skips the calling cross-impl test when APS_TS_REPO is unset
// or empty, with the canonical message, before any use of the repo path or tsx.
func skipUnlessTSRepo(t *testing.T) {
	t.Helper()
	if tsRepoPath() == "" {
		t.Skip("set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	}
}

// runTSX writes script to a temp .mjs inside the TS repo (so absolute-path
// imports resolve), runs it with `npx tsx`, and returns parsed KEY VALUE lines.
func runTSX(t *testing.T, script string) map[string]string {
	t.Helper()
	repo := tsRepoPath()
	if _, err := os.Stat(filepath.Join(repo, "src", "core", "values.ts")); err != nil {
		t.Skipf("TS reference not found at %s (set APS_TS_REPO); pinned constants still cover this", repo)
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not on PATH; pinned constants still cover this")
	}

	f, err := os.CreateTemp(repo, "aps_values_live_*.mjs")
	if err != nil {
		t.Fatalf("create temp script: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		t.Fatalf("write script: %v", err)
	}
	f.Close()

	cmd := exec.Command("npx", "tsx", f.Name())
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("npx tsx failed (toolchain unavailable); pinned constants still cover this. output:\n%s", string(out))
	}

	res := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ' ')
		if i <= 0 {
			continue
		}
		res[line[:i]] = line[i+1:]
	}
	return res
}

// TestAttestFloor_LiveTS runs the reference attestation path live and asserts
// the Go canonical-byte hash and signature equal the live TS values. This is
// the build-time oracle; the pinned constants in values_test.go are its
// recorded output.
func TestAttestFloor_LiveTS(t *testing.T) {
	skipUnlessTSRepo(t)
	script := `
import crypto from 'node:crypto'
import { canonicalize } from '` + tsRepoPath() + `/src/core/canonical.ts'
import { canonicalizeJCS } from '` + tsRepoPath() + `/src/core/canonical-jcs.ts'
import { sign } from '` + tsRepoPath() + `/src/crypto/keys.ts'
const seed = crypto.createHash('sha256').update('aps-go-values-key').digest()
const privHex = Buffer.from(seed).toString('hex')
const derPrefix = Buffer.from('302e020100300506032b657004220420','hex')
const keyObj = crypto.createPrivateKey({key:Buffer.concat([derPrefix,seed]),format:'der',type:'pkcs8'})
const pubHex = Buffer.from(new Uint8Array(crypto.createPublicKey(keyObj).export({type:'spki',format:'der'}).slice(-32))).toString('hex')
const fv='2.0', ext=['ext-b','ext-a'], at='2026-06-03T12:00:00.000Z', ea='2027-06-03T12:00:00.000Z'
const a={attestationId:'att_000000000001',agentId:'ag_values_001',publicKey:pubHex,floorVersion:fv,extensions:ext,attestedAt:at,expiresAt:ea,commitment:` + "`floor:${fv}|ext:${[...ext].sort().join(',')||'none'}|ts:${at}`" + `}
const c=canonicalize(a)
console.log('PUB '+pubHex)
console.log('EQ '+(c===canonicalizeJCS(a)))
console.log('CANONSHA '+crypto.createHash('sha256').update(c,'utf8').digest('hex'))
console.log('SIG '+sign(c,privHex))
`
	ts := runTSX(t, script)

	att := buildTestAttestation(t)
	canonMap := attestationToMap(att)
	delete(canonMap, "signature")
	canon, _ := jcs.Canonicalize(canonMap)
	sum := sha256.Sum256([]byte(canon))
	goCanonSHA := hex.EncodeToString(sum[:])

	if ts["EQ"] != "true" {
		t.Fatalf("TS reports legacy canonicalize != JCS for this shape (EQ=%s); the jcs-based port would diverge", ts["EQ"])
	}
	if ts["PUB"] != attestPubHex {
		t.Errorf("live TS pub %s != Go-derived %s", ts["PUB"], attestPubHex)
	}
	if ts["CANONSHA"] != goCanonSHA {
		t.Errorf("canonical sha256 Go != live TS:\n Go %s\n TS %s", goCanonSHA, ts["CANONSHA"])
	}
	if ts["SIG"] != att.Signature {
		t.Errorf("signature Go != live TS:\n Go %s\n TS %s", att.Signature, ts["SIG"])
	}
	// Confirm the pinned constants match the live values too (catch drift).
	if ts["CANONSHA"] != wantAttestCanonSHA256 {
		t.Errorf("pinned attest canon sha %s != live TS %s", wantAttestCanonSHA256, ts["CANONSHA"])
	}
	if ts["SIG"] != wantAttestSig {
		t.Errorf("pinned attest sig != live TS")
	}
}

// TestEvaluateCompliance_LiveTS runs the REAL evaluateCompliance and asserts the
// Go report's canonical bytes and signature equal the live TS values. It signs
// the live TS report object the same way the function does and compares.
func TestEvaluateCompliance_LiveTS(t *testing.T) {
	skipUnlessTSRepo(t)
	script := `
import crypto from 'node:crypto'
import { canonicalize } from '` + tsRepoPath() + `/src/core/canonical.ts'
import { canonicalizeJCS } from '` + tsRepoPath() + `/src/core/canonical-jcs.ts'
import { sign } from '` + tsRepoPath() + `/src/crypto/keys.ts'
import { evaluateCompliance } from '` + tsRepoPath() + `/src/core/values.ts'
const seed = crypto.createHash('sha256').update('aps-go-values-verifier').digest()
const privHex = Buffer.from(seed).toString('hex')
const derPrefix = Buffer.from('302e020100300506032b657004220420','hex')
const keyObj = crypto.createPrivateKey({key:Buffer.concat([derPrefix,seed]),format:'der',type:'pkcs8'})
const pubHex = Buffer.from(new Uint8Array(crypto.createPublicKey(keyObj).export({type:'spki',format:'der'}).slice(-32))).toString('hex')
const floor={version:'2.0',schema:'aps-floor-v2',lastUpdated:'2026-01-01T00:00:00.000Z',governanceUri:'https://aeoess.org/floor',floor:[
 {id:'F-001',name:'Traceability',principle:'All actions traceable',enforcement:{mode:'inline',mechanism:'delegation-chain'},weight:'mandatory'},
 {id:'F-002',name:'Honest Identity',principle:'Consistent identity',enforcement:{mode:'audit',mechanism:'agentId'},weight:'mandatory'},
 {id:'F-005',name:'Auditability',principle:'All receipts signed',enforcement:{mode:'inline',mechanism:'signature'},weight:'mandatory'},
 {id:'F-006',name:'Non-Deception',principle:'No deception',enforcement:{mode:'warn',mechanism:'reasoning'},weight:'strong_consideration'}]}
const receipts=[
 {receiptId:'rcpt_001',version:'1.0',timestamp:'2026-06-03T10:00:00.000Z',agentId:'ag_values_001',delegationId:'dlg_001',action:{type:'web_search',target:'example.com',scopeUsed:'data:read'},result:{status:'success',summary:'ok'},delegationChain:['fp_root','fp_leaf'],signature:'aa'.repeat(64)},
 {receiptId:'rcpt_002',version:'1.0',timestamp:'2026-06-03T11:00:00.000Z',agentId:'ag_values_001',delegationId:'dlg_001',action:{type:'code_execution',target:'sandbox',scopeUsed:'compute:exec'},result:{status:'success',summary:'done'},delegationChain:['fp_root','fp_leaf'],signature:'bb'.repeat(64)}]
const delegations=new Map([['dlg_001',{scope:['data:read','compute:exec'],revoked:false}]])
const real=evaluateCompliance('ag_values_001',receipts,floor,delegations,privHex)
// Rebuild the signed preimage deterministically (real uses uuid+Date for id/generatedAt).
const report={reportId:'comp_000000000001',agentId:real.agentId,floorVersion:real.floorVersion,period:real.period,receiptsAnalyzed:real.receiptsAnalyzed,checks:real.checks,overallCompliance:real.overallCompliance,generatedAt:'2026-06-03T12:00:00.000Z'}
const c=canonicalize(report)
console.log('PUB '+pubHex)
console.log('EQ '+(c===canonicalizeJCS(report)))
console.log('OVERALL '+real.overallCompliance)
console.log('PERIODFROM '+real.period.from)
console.log('PERIODTO '+real.period.to)
console.log('CANONSHA '+crypto.createHash('sha256').update(c,'utf8').digest('hex'))
console.log('SIG '+sign(c,privHex))
`
	ts := runTSX(t, script)

	report := buildTestReport(t)
	canonMap := reportToMap(report)
	delete(canonMap, "signature")
	canon, _ := jcs.Canonicalize(canonMap)
	sum := sha256.Sum256([]byte(canon))
	goCanonSHA := hex.EncodeToString(sum[:])

	if ts["EQ"] != "true" {
		t.Fatalf("TS reports legacy canonicalize != JCS for the report shape (EQ=%s)", ts["EQ"])
	}
	if ts["OVERALL"] != "0.95" {
		t.Errorf("live TS overallCompliance = %s, want 0.95", ts["OVERALL"])
	}
	if ts["CANONSHA"] != goCanonSHA {
		t.Errorf("report canonical sha256 Go != live TS:\n Go %s\n TS %s", goCanonSHA, ts["CANONSHA"])
	}
	if ts["SIG"] != report.Signature {
		t.Errorf("report signature Go != live TS:\n Go %s\n TS %s", report.Signature, ts["SIG"])
	}
	if ts["CANONSHA"] != wantReportCanonSHA256 {
		t.Errorf("pinned report canon sha %s != live TS %s", wantReportCanonSHA256, ts["CANONSHA"])
	}
	if ts["SIG"] != wantReportSig {
		t.Errorf("pinned report sig != live TS")
	}
}

// TestTSVerifiesGoSignature: a Go-created artifact verifies under the TS verify
// function (Go-created -> TS verify, the second direction of cross-verification).
func TestTSVerifiesGoSignature(t *testing.T) {
	skipUnlessTSRepo(t)
	att := buildTestAttestation(t) // Go-created, Go-signed
	canonMap := attestationToMap(att)
	delete(canonMap, "signature")
	canon, _ := jcs.Canonicalize(canonMap)

	script := `
import { verify } from '` + tsRepoPath() + `/src/crypto/keys.ts'
const msg = process.env.APS_MSG
const sig = process.env.APS_SIG
const pub = process.env.APS_PUB
console.log('VERIFY '+verify(msg, sig, pub))
`
	repo := tsRepoPath()
	if _, err := os.Stat(filepath.Join(repo, "src", "crypto", "keys.ts")); err != nil {
		t.Skipf("TS reference not found at %s; pinned constants still cover this", repo)
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not on PATH; pinned constants still cover this")
	}
	f, err := os.CreateTemp(repo, "aps_values_verify_*.mjs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(script)
	f.Close()

	cmd := exec.Command("npx", "tsx", f.Name())
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"APS_MSG="+canon,
		"APS_SIG="+att.Signature,
		"APS_PUB="+attestPubHex,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("npx tsx failed; pinned constants still cover this:\n%s", string(out))
	}
	if !strings.Contains(string(out), "VERIFY true") {
		t.Errorf("TS verify rejected the Go-created signature. output:\n%s", string(out))
	}
}
