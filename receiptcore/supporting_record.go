// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package receiptcore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/aeoess/agent-passport-go/keys"
)

const SupportingRecordIDTag = "APS-SUPPORTING-RECORD-ID-V1"
const SupportingRecordSigTag = "APS-SUPPORTING-RECORD-SIG-V1"

func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

func recordMap(record SupportingRecordV1, includeID, includeSig bool) map[string]interface{} {
	out := map[string]interface{}{
		"profile": record.Profile, "record_type": record.RecordType, "issuer": record.Issuer,
		"issuer_key_id": record.IssuerKeyID, "issued_at": record.IssuedAt, "body": record.Body,
		"sig_alg": record.SigAlg,
	}
	if includeID {
		out["record_id"] = record.RecordID
	}
	if includeSig {
		out["sig"] = record.Sig
	}
	if record.ActionRef != nil {
		out["action_ref"] = *record.ActionRef
	}
	return out
}

func SupportingRecordIDPayloadV1(record SupportingRecordV1) (string, error) {
	canonical, err := strictJCS(recordMap(record, false, false))
	if err != nil {
		return "", err
	}
	return SupportingRecordIDTag + "\x00" + record.RecordType + "\x00" + canonical, nil
}

func ComputeSupportingRecordIDV1(record SupportingRecordV1) (string, error) {
	payload, err := SupportingRecordIDPayloadV1(record)
	if err != nil {
		return "", err
	}
	return sha256Hex([]byte(payload)), nil
}

func SupportingRecordSignaturePayloadV1(record SupportingRecordV1) (string, error) {
	canonical, err := strictJCS(recordMap(record, true, false))
	if err != nil {
		return "", err
	}
	return SupportingRecordSigTag + "\x00" + record.RecordType + "\x00" + canonical, nil
}

func ValidateSupportingRecordV1(record SupportingRecordV1, requireCrypto bool) error {
	if record.Profile != "aps-supporting-record-v1" || record.RecordType == "" || record.Issuer == "" || record.IssuerKeyID == "" || !isExactUTCMilliseconds(record.IssuedAt) || record.Body == nil || record.SigAlg != "Ed25519" {
		return errors.New("receiptcore: invalid SupportingRecordV1")
	}
	if record.ActionRef != nil && !hex64.MatchString(*record.ActionRef) {
		return errors.New("receiptcore: invalid supporting action_ref")
	}
	if requireCrypto && (!hex64.MatchString(record.RecordID) || !hex128.MatchString(record.Sig)) {
		return errors.New("receiptcore: invalid supporting crypto encoding")
	}
	_, err := strictJCS(recordMap(record, true, true))
	return err
}

func CreateSupportingRecordV1(fields SupportingRecordV1, privateKey string) (SupportingRecordV1, error) {
	fields.RecordID = "0000000000000000000000000000000000000000000000000000000000000000"
	fields.Sig = ""
	if err := ValidateSupportingRecordV1(fields, false); err != nil {
		return SupportingRecordV1{}, err
	}
	fields.Body = cloneJSONValue(fields.Body).(map[string]interface{})
	id, err := ComputeSupportingRecordIDV1(fields)
	if err != nil {
		return SupportingRecordV1{}, err
	}
	fields.RecordID = id
	payload, err := SupportingRecordSignaturePayloadV1(fields)
	if err != nil {
		return SupportingRecordV1{}, err
	}
	fields.Sig, err = keys.Sign(payload, privateKey)
	if err != nil {
		return SupportingRecordV1{}, err
	}
	if err := ValidateSupportingRecordV1(fields, true); err != nil {
		return SupportingRecordV1{}, err
	}
	return fields, nil
}

func VerifySupportingRecordV1(record SupportingRecordV1, publicKey string) (valid, idValid, signatureValid bool) {
	if ValidateSupportingRecordV1(record, true) != nil {
		return false, false, false
	}
	id, err := ComputeSupportingRecordIDV1(record)
	idValid = err == nil && id == record.RecordID
	payload, err := SupportingRecordSignaturePayloadV1(record)
	signatureValid = err == nil && keys.Verify(payload, record.Sig, publicKey)
	return idValid && signatureValid, idValid, signatureValid
}

func memberMap(member EvidenceBundleMemberV2) map[string]interface{} {
	return map[string]interface{}{"member_id": member.MemberID, "member_type": member.MemberType, "sha256": member.SHA256}
}

func memberCanonical(member EvidenceBundleMemberV2) (string, error) {
	return strictJCS(memberMap(member))
}

func EvidenceBundleMerkleRootV2(entries []EvidenceBundleMemberV2) (string, error) {
	if len(entries) == 0 {
		return "", errors.New("receiptcore: EvidenceBundleV2 requires a member")
	}
	level := make([][]byte, len(entries))
	seen := map[string]bool{}
	previous := ""
	for i, entry := range entries {
		if entry.MemberID == "" || entry.MemberType == "" || !hex64.MatchString(entry.SHA256) || seen[entry.MemberID] {
			return "", errors.New("receiptcore: invalid or duplicate evidence member")
		}
		seen[entry.MemberID] = true
		canonical, err := memberCanonical(entry)
		if err != nil {
			return "", err
		}
		if i > 0 && previous >= canonical {
			return "", errors.New("receiptcore: evidence members not sorted")
		}
		previous = canonical
		sum := sha256.Sum256(append([]byte{0}, []byte(canonical)...))
		level[i] = sum[:]
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			preimage := append([]byte{1}, level[i]...)
			preimage = append(preimage, level[i+1]...)
			sum := sha256.Sum256(preimage)
			next = append(next, sum[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0]), nil
}

func BuildEvidenceBundleBodyV2(members []EvidenceBundleMemberInputV2) (EvidenceBundleBodyV2, error) {
	if len(members) == 0 {
		return EvidenceBundleBodyV2{}, errors.New("receiptcore: EvidenceBundleV2 requires a member")
	}
	seen := map[string]bool{}
	entries := make([]EvidenceBundleMemberV2, 0, len(members))
	for _, member := range members {
		if member.MemberID == "" || member.MemberType == "" || seen[member.MemberID] {
			return EvidenceBundleBodyV2{}, errors.New("receiptcore: invalid or duplicate evidence member")
		}
		seen[member.MemberID] = true
		canonical, err := strictJCS(member.Payload)
		if err != nil {
			return EvidenceBundleBodyV2{}, err
		}
		entries = append(entries, EvidenceBundleMemberV2{MemberID: member.MemberID, MemberType: member.MemberType, SHA256: sha256Hex([]byte(canonical))})
	}
	sort.Slice(entries, func(i, j int) bool {
		a, _ := memberCanonical(entries[i])
		b, _ := memberCanonical(entries[j])
		return a < b
	})
	root, err := EvidenceBundleMerkleRootV2(entries)
	if err != nil {
		return EvidenceBundleBodyV2{}, err
	}
	return EvidenceBundleBodyV2{Members: entries, MerkleRoot: root}, nil
}

func VerifyEvidenceBundleBodyV2(body EvidenceBundleBodyV2, payloads map[string]interface{}) bool {
	if len(body.Members) == 0 || !hex64.MatchString(body.MerkleRoot) {
		return false
	}
	seen := map[string]bool{}
	previous := ""
	for i, member := range body.Members {
		if member.MemberID == "" || member.MemberType == "" || !hex64.MatchString(member.SHA256) || seen[member.MemberID] {
			return false
		}
		seen[member.MemberID] = true
		canonical, err := memberCanonical(member)
		if err != nil || (i > 0 && previous >= canonical) {
			return false
		}
		previous = canonical
		if payloads != nil {
			payload, ok := payloads[member.MemberID]
			if !ok {
				return false
			}
			payloadCanonical, err := strictJCS(payload)
			if err != nil || sha256Hex([]byte(payloadCanonical)) != member.SHA256 {
				return false
			}
		}
	}
	root, err := EvidenceBundleMerkleRootV2(body.Members)
	return err == nil && root == body.MerkleRoot
}

func evidenceLeaf(entry EvidenceBundleMemberV2) ([]byte, error) {
	canonical, err := memberCanonical(entry)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte{0}, []byte(canonical)...))
	return sum[:], nil
}

// BuildEvidenceBundleProofV2 creates a tree-shape-bound inclusion proof. Odd
// nodes are promoted, not duplicated, and promotion is explicit in the path.
func BuildEvidenceBundleProofV2(entries []EvidenceBundleMemberV2, memberID string) (EvidenceBundleProofV2, error) {
	if _, err := EvidenceBundleMerkleRootV2(entries); err != nil {
		return EvidenceBundleProofV2{}, err
	}
	leafIndex := -1
	level := make([][]byte, len(entries))
	for i, entry := range entries {
		if entry.MemberID == memberID {
			leafIndex = i
		}
		leaf, err := evidenceLeaf(entry)
		if err != nil {
			return EvidenceBundleProofV2{}, err
		}
		level[i] = leaf
	}
	if leafIndex < 0 {
		return EvidenceBundleProofV2{}, errors.New("receiptcore: evidence member not found")
	}
	proof := EvidenceBundleProofV2{Profile: "aps-evidence-proof-v2", Member: entries[leafIndex], LeafIndex: leafIndex, LeafCount: len(entries), Path: []EvidenceBundleProofStepV2{}}
	index := leafIndex
	for len(level) > 1 {
		switch {
		case index%2 == 1:
			proof.Path = append(proof.Path, EvidenceBundleProofStepV2{Position: "left", SHA256: hex.EncodeToString(level[index-1])})
		case index+1 < len(level):
			proof.Path = append(proof.Path, EvidenceBundleProofStepV2{Position: "right", SHA256: hex.EncodeToString(level[index+1])})
		default:
			proof.Path = append(proof.Path, EvidenceBundleProofStepV2{Position: "promote"})
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for offset := 0; offset < len(level); offset += 2 {
			if offset+1 == len(level) {
				next = append(next, level[offset])
				continue
			}
			preimage := append([]byte{1}, level[offset]...)
			preimage = append(preimage, level[offset+1]...)
			sum := sha256.Sum256(preimage)
			next = append(next, sum[:])
		}
		index /= 2
		level = next
	}
	return proof, nil
}

func verifyEvidenceBundleProofV2(proof EvidenceBundleProofV2, trustedRoot string, payload interface{}, checkPayload bool) bool {
	if proof.Profile != "aps-evidence-proof-v2" || !hex64.MatchString(trustedRoot) || proof.Member.MemberID == "" || proof.Member.MemberType == "" || !hex64.MatchString(proof.Member.SHA256) || proof.LeafCount < 1 || proof.LeafIndex < 0 || proof.LeafIndex >= proof.LeafCount || proof.Path == nil {
		return false
	}
	if checkPayload {
		canonical, err := strictJCS(payload)
		if err != nil || sha256Hex([]byte(canonical)) != proof.Member.SHA256 {
			return false
		}
	}
	digest, err := evidenceLeaf(proof.Member)
	if err != nil {
		return false
	}
	index, width, pathIndex := proof.LeafIndex, proof.LeafCount, 0
	for width > 1 {
		if pathIndex >= len(proof.Path) {
			return false
		}
		step := proof.Path[pathIndex]
		pathIndex++
		expected := "promote"
		if index%2 == 1 {
			expected = "left"
		} else if index+1 < width {
			expected = "right"
		}
		if step.Position != expected {
			return false
		}
		if expected == "promote" {
			if step.SHA256 != "" {
				return false
			}
		} else {
			if !hex64.MatchString(step.SHA256) {
				return false
			}
			sibling, decodeErr := hex.DecodeString(step.SHA256)
			if decodeErr != nil {
				return false
			}
			preimage := []byte{1}
			if expected == "left" {
				preimage = append(preimage, sibling...)
				preimage = append(preimage, digest...)
			} else {
				preimage = append(preimage, digest...)
				preimage = append(preimage, sibling...)
			}
			sum := sha256.Sum256(preimage)
			digest = sum[:]
		}
		index /= 2
		width = (width + 1) / 2
	}
	return pathIndex == len(proof.Path) && hex.EncodeToString(digest) == trustedRoot
}

func VerifyEvidenceBundleProofV2(proof EvidenceBundleProofV2, trustedRoot string) bool {
	return verifyEvidenceBundleProofV2(proof, trustedRoot, nil, false)
}

func VerifyEvidenceBundleProofPayloadV2(proof EvidenceBundleProofV2, trustedRoot string, payload interface{}) bool {
	return verifyEvidenceBundleProofV2(proof, trustedRoot, payload, true)
}

type SupportingRecordFormat struct {
	Format, Canonicalization string
	Legacy                   bool
}

// ClassifySupportingRecordFormat chooses exactly one canonicalization from an
// explicit discriminator. Verification must fail for unknown formats.
func ClassifySupportingRecordFormat(value map[string]interface{}) SupportingRecordFormat {
	if value["profile"] == "aps-supporting-record-v1" {
		return SupportingRecordFormat{"supporting-record-v1", "rfc8785", false}
	}
	if value["profile"] == "aps-composition-check-v0" {
		return SupportingRecordFormat{"composition-check-v0", "rfc8785-tagged-v0", true}
	}
	if value["spec_version"] == "0.1.0" && value["record_type"] == "accountability_record" {
		return SupportingRecordFormat{"accountability-record-0.1.0", "rfc8785-untagged", true}
	}
	if value["type"] == "read_fidelity_receipt" {
		return SupportingRecordFormat{"read-fidelity-unwrapped", "rfc8785-untagged", true}
	}
	if manifest, ok := value["manifest"].(map[string]interface{}); ok && manifest["profile"] == "aps:evidence-bundle:v1" {
		return SupportingRecordFormat{"evidence-bundle-v1", "aps-legacy-null-dropping", true}
	}
	_, authority := value["authority_ref"]
	_, observer := value["observer_key"]
	_, profile := value["profile"]
	if authority && observer && !profile {
		return SupportingRecordFormat{"revocation-observation-unversioned", "aps-legacy-null-dropping", true}
	}
	return SupportingRecordFormat{"unknown", "unknown", false}
}
