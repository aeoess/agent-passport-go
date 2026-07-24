package receiptcore

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/aeoess/agent-passport-go/keys"
)

const privateKey = "0000000000000000000000000000000000000000000000000000000000000000"

const katDecisionRef = "2157809a9a722314ae19dce7a242ea3b54a8948230fab2fab5d5dc15bd663dc2"
const katReceiptID = "89b0b77807e99845aab403f01bcdaa2f02949f6c9db84e1aca6c0a8449e4d023"
const katReceiptSig = "83deb713568bbdf0c85e1a6d46345530e84dbe86cdefe1cb608b0f14372c176a9e69e0033db11c4c44ff84be3de3bee5e212707eb84206f6c34455206d37f90b"
const katMerkleRoot = "03700eeba1b453086063612d3df73f711827735c3fe30cf8a8a2a6379a6f6d5f"
const katRecordID = "7d73684a65444088e841f2b30f0ecf139fbadbeab277d57d20d1a2ef5fe2a7b2"
const katRecordSig = "56a2116eb4e259a336c36a646e69322cf2e7850b7202f2093c5957e4e6a100cf4cae8048cb4647bbc557447bea531dd7e69c117e9298515cc767110cf0f7d809"
const katProofRoot = "dab9f2f5f3571345327f0144f2eafbb6e835ac5cbb48e9d789224e135ce16247"
const katProofLeft = "f3bdfcf031dea9da3129ae67bdf7f69caefc41660541d0acb015e1b49ae95470"

func hx(char string) string {
	out := ""
	for i := 0; i < 64; i++ {
		out += char
	}
	return out
}

func TestDecisionRefAndConstraintNormalization(t *testing.T) {
	_, first, err := BuildDecisionRefV1(hx("a"), map[string]interface{}{"scope": []interface{}{"read"}, "revoked": false}, map[string]interface{}{"id": "p1", "version": "1"}, map[string]interface{}{"tenant": "t1"}, map[string]interface{}{"verdict": "permit", "constraints": []interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if first != katDecisionRef {
		t.Fatalf("decision_ref KAT mismatch: %s", first)
	}
	_, reordered, err := BuildDecisionRefV1(hx("a"), map[string]interface{}{"revoked": false, "scope": []interface{}{"read"}}, map[string]interface{}{"version": "1", "id": "p1"}, map[string]interface{}{"tenant": "t1"}, map[string]interface{}{"constraints": []interface{}{}, "verdict": "permit"})
	if err != nil || first != reordered {
		t.Fatalf("decision ref order changed: %v", err)
	}
	effective := hx("b")
	validUntil := "2026-04-08T12:00:05.000Z"
	out, err := NormalizeCoreDecisionOutputV1(CoreDecisionOutputV1{Profile: "aps-core-decision-output-v1", Verdict: "narrow", EffectiveAuthorityRef: &effective, Constraints: []string{"é", "read", "e\u0301", "read"}, ValidUntil: &validUntil})
	if err != nil || len(out.Constraints) != 2 || out.Constraints[0] != "read" || out.Constraints[1] != "é" {
		t.Fatalf("bad constraints: %#v %v", out, err)
	}
}

func TestReceiptBindsIdentifierSignerAndContent(t *testing.T) {
	publicKey, err := keys.PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	decision := hx("c")
	receipt, err := CreateReceiptV1(ReceiptV1{
		Profile: "aps-receipt-v1", ReceiptType: "aps:action:v1", Issuer: "did:example:issuer", SubjectAgent: "did:example:agent",
		ActionRef: hx("a"), DelegationRef: hx("b"), DecisionRef: &decision, IssuedAt: "2026-07-18T12:00:00.000Z",
		EvidenceRefs: []EvidenceRefV1{{ArtifactType: "z", SHA256: hx("e")}, {ArtifactType: "a", SHA256: hx("d")}},
		Result:       map[string]interface{}{"status": "success", "detail": nil},
	}, []ReceiptSignerV1{{Signer: "did:example:issuer", KeyID: "key-1", PrivateKey: privateKey}})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ReceiptID != katReceiptID || receipt.Signatures[0].Value != katReceiptSig {
		t.Fatalf("receipt KAT mismatch: %s %s", receipt.ReceiptID, receipt.Signatures[0].Value)
	}
	verified := VerifyReceiptV1(receipt, func(_, _, _ string) (string, bool) { return publicKey, true })
	if !verified.Valid {
		t.Fatalf("receipt did not verify: %#v", verified)
	}
	receipt.Signatures[0].KeyID = "key-2"
	if VerifyReceiptV1(receipt, func(_, _, _ string) (string, bool) { return publicKey, true }).Valid {
		t.Fatal("relabeled key verified")
	}
}

func TestSupportingRecordAndBundleBindMemberAxes(t *testing.T) {
	publicKey, _ := keys.PublicKeyFromPrivate(privateKey)
	payloads := map[string]interface{}{"m1": map[string]interface{}{"value": nil}, "m2": map[string]interface{}{"value": int64(2)}}
	bundle, err := BuildEvidenceBundleBodyV2([]EvidenceBundleMemberInputV2{{MemberID: "m2", MemberType: "two", Payload: payloads["m2"]}, {MemberID: "m1", MemberType: "one", Payload: payloads["m1"]}})
	if err != nil || !VerifyEvidenceBundleBodyV2(bundle, payloads) {
		t.Fatalf("bundle failed: %v %#v", err, bundle)
	}
	if bundle.MerkleRoot != katMerkleRoot {
		t.Fatalf("merkle KAT mismatch: %s", bundle.MerkleRoot)
	}
	body := map[string]interface{}{"members": make([]interface{}, len(bundle.Members)), "merkle_root": bundle.MerkleRoot}
	for i, member := range bundle.Members {
		body["members"].([]interface{})[i] = memberMap(member)
	}
	record, err := CreateSupportingRecordV1(SupportingRecordV1{Profile: "aps-supporting-record-v1", RecordType: "aps:evidence-bundle:v2", Issuer: "did:example:issuer", IssuerKeyID: "key-1", IssuedAt: "2026-07-18T12:00:00.000Z", Body: body, SigAlg: "Ed25519"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if record.RecordID != katRecordID || record.Sig != katRecordSig {
		t.Fatalf("record KAT mismatch: %s %s", record.RecordID, record.Sig)
	}
	valid, _, _ := VerifySupportingRecordV1(record, publicKey)
	if !valid {
		t.Fatal("supporting record did not verify")
	}
	bundle.Members[0].MemberType = "changed"
	if VerifyEvidenceBundleBodyV2(bundle, payloads) {
		t.Fatal("changed member type verified")
	}
	three, err := BuildEvidenceBundleBodyV2([]EvidenceBundleMemberInputV2{
		{MemberID: "m3", MemberType: "three", Payload: map[string]interface{}{"value": int64(3)}},
		{MemberID: "m1", MemberType: "one", Payload: map[string]interface{}{"value": int64(1)}},
		{MemberID: "m2", MemberType: "two", Payload: map[string]interface{}{"value": int64(2)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildEvidenceBundleProofV2(three.Members, "m3")
	if err != nil {
		t.Fatal(err)
	}
	if three.MerkleRoot != katProofRoot || len(proof.Path) != 2 || proof.Path[0].Position != "promote" || proof.Path[1].Position != "left" || proof.Path[1].SHA256 != katProofLeft {
		t.Fatalf("proof KAT mismatch: %#v", proof)
	}
	promoted := false
	for _, step := range proof.Path {
		promoted = promoted || step.Position == "promote"
	}
	if !promoted || !VerifyEvidenceBundleProofPayloadV2(proof, three.MerkleRoot, map[string]interface{}{"value": int64(3)}) {
		t.Fatal("odd-promotion inclusion proof failed")
	}
	proof.LeafCount = 4
	if VerifyEvidenceBundleProofV2(proof, three.MerkleRoot) {
		t.Fatal("tree-shape mutation verified")
	}
}

func TestStrictNewWriteAndExplicitDispatch(t *testing.T) {
	if _, err := strictJCS(map[string]interface{}{"x": struct{}{}}); err == nil {
		t.Fatal("struct coercion accepted")
	}
	if _, err := strictJCS(map[string]interface{}{"integer": json.Number("9007199254740992")}); !errors.Is(err, ErrInvalidIJSON) {
		t.Fatalf("unsafe integer accepted: %v", err)
	}
	if _, err := ParseStrictIJSON([]byte(`{"a":1,"\u0061":2}`), 1024, 16); !errors.Is(err, ErrInvalidIJSON) {
		t.Fatalf("duplicate raw member accepted: %v", err)
	}
	legacy := ClassifySupportingRecordFormat(map[string]interface{}{"manifest": map[string]interface{}{"profile": "aps:evidence-bundle:v1"}})
	if legacy.Format != "evidence-bundle-v1" || !legacy.Legacy {
		t.Fatalf("bad dispatch: %#v", legacy)
	}
	if ClassifySupportingRecordFormat(map[string]interface{}{"profile": "future"}).Format != "unknown" {
		t.Fatal("unknown guessed")
	}
}

func TestCoreDecisionOutputBindsValidUntilIntoHashedPreimage(t *testing.T) {
	effective := hx("b")
	first := "2026-04-08T12:00:05.000Z"
	second := "2026-04-08T12:00:06.000Z"
	permit := CoreDecisionOutputV1{Profile: "aps-core-decision-output-v1", Verdict: "permit", EffectiveAuthorityRef: &effective, Constraints: []string{"commerce:read"}, ValidUntil: &first}

	normalized, err := NormalizeCoreDecisionOutputV1(permit)
	if err != nil {
		t.Fatal(err)
	}
	refA, err := ComputeDecisionComponentRefV1("output", CoreDecisionOutputMapV1(normalized))
	if err != nil {
		t.Fatal(err)
	}
	shifted := permit
	shifted.ValidUntil = &second
	normalizedShifted, err := NormalizeCoreDecisionOutputV1(shifted)
	if err != nil {
		t.Fatal(err)
	}
	refB, err := ComputeDecisionComponentRefV1("output", CoreDecisionOutputMapV1(normalizedShifted))
	if err != nil || refA == refB {
		t.Fatalf("valid_until not bound into the digest: %s %s %v", refA, refB, err)
	}

	denied, err := NormalizeCoreDecisionOutputV1(CoreDecisionOutputV1{Profile: "aps-core-decision-output-v1", Verdict: "deny", Constraints: []string{}})
	if err != nil || denied.ValidUntil != nil {
		t.Fatalf("deny with null valid_until must normalize: %v", err)
	}
	if _, err := ComputeDecisionComponentRefV1("output", CoreDecisionOutputMapV1(denied)); err != nil {
		t.Fatal(err)
	}

	noValidUntil := permit
	noValidUntil.ValidUntil = nil
	if _, err := NormalizeCoreDecisionOutputV1(noValidUntil); err == nil {
		t.Fatal("permit without valid_until must be rejected")
	}
	denyWithTimestamp := CoreDecisionOutputV1{Profile: "aps-core-decision-output-v1", Verdict: "deny", Constraints: []string{}, ValidUntil: &first}
	if _, err := NormalizeCoreDecisionOutputV1(denyWithTimestamp); err == nil {
		t.Fatal("deny with a valid_until timestamp must be rejected")
	}
	malformed := "2026-04-08T12:00:05Z"
	badShape := permit
	badShape.ValidUntil = &malformed
	if _, err := NormalizeCoreDecisionOutputV1(badShape); err == nil {
		t.Fatal("permit with a malformed valid_until must be rejected")
	}
}
