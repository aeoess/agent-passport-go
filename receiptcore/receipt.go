// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package receiptcore

import (
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/aeoess/agent-passport-go/keys"
)

const ReceiptIDTag = "APS-RECEIPT-ID-V1"
const ReceiptSigTag = "APS-RECEIPT-SIG-V1"

var hex128 = regexp.MustCompile(`^[0-9a-f]{128}$`)
var utcMS = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func isExactUTCMilliseconds(value string) bool {
	if !utcMS.MatchString(value) {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}

func evidenceRefMap(ref EvidenceRefV1) map[string]interface{} {
	return map[string]interface{}{"artifact_type": ref.ArtifactType, "sha256": ref.SHA256}
}

func signatureMap(proof ReceiptSignatureV1) map[string]interface{} {
	return map[string]interface{}{"signer": proof.Signer, "key_id": proof.KeyID, "alg": proof.Alg, "value": proof.Value}
}

func descriptorMap(proof ReceiptSignatureV1) map[string]interface{} {
	return map[string]interface{}{"signer": proof.Signer, "key_id": proof.KeyID, "alg": proof.Alg}
}

func receiptMap(receipt ReceiptV1, includeID, includeSignatures bool) map[string]interface{} {
	out := map[string]interface{}{
		"profile": receipt.Profile, "receipt_type": receipt.ReceiptType, "issuer": receipt.Issuer,
		"subject_agent": receipt.SubjectAgent, "action_ref": receipt.ActionRef,
		"delegation_ref": receipt.DelegationRef, "issued_at": receipt.IssuedAt, "result": receipt.Result,
	}
	refs := make([]interface{}, len(receipt.EvidenceRefs))
	for i, ref := range receipt.EvidenceRefs {
		refs[i] = evidenceRefMap(ref)
	}
	out["evidence_refs"] = refs
	if includeID {
		out["receipt_id"] = receipt.ReceiptID
	}
	if receipt.DecisionRef != nil {
		out["decision_ref"] = *receipt.DecisionRef
	}
	if receipt.Prev != nil {
		out["prev"] = *receipt.Prev
	}
	if includeSignatures {
		sigs := make([]interface{}, len(receipt.Signatures))
		for i, proof := range receipt.Signatures {
			sigs[i] = signatureMap(proof)
		}
		out["signatures"] = sigs
	}
	return out
}

func ReceiptIDPayloadV1(receipt ReceiptV1) (string, error) {
	canonical, err := strictJCS(receiptMap(receipt, false, false))
	if err != nil {
		return "", err
	}
	return ReceiptIDTag + "\x00" + canonical, nil
}

func ComputeReceiptIDV1(receipt ReceiptV1) (string, error) {
	payload, err := ReceiptIDPayloadV1(receipt)
	if err != nil {
		return "", err
	}
	return sha256Hex([]byte(payload)), nil
}

func ReceiptSignaturePayloadV1(receipt ReceiptV1, descriptor ReceiptSignatureV1) (string, error) {
	form := map[string]interface{}{"receipt": receiptMap(receipt, true, false), "signer": descriptorMap(descriptor)}
	canonical, err := strictJCS(form)
	if err != nil {
		return "", err
	}
	return ReceiptSigTag + "\x00" + canonical, nil
}

func ValidateReceiptV1(receipt ReceiptV1, requireValues bool) error {
	if receipt.Profile != "aps-receipt-v1" || receipt.ReceiptType == "" || receipt.Issuer == "" || receipt.SubjectAgent == "" || receipt.DelegationRef == "" {
		return errors.New("receiptcore: invalid ReceiptV1 identifiers")
	}
	if requireValues && !hex64.MatchString(receipt.ReceiptID) {
		return errors.New("receiptcore: invalid receipt_id")
	}
	if !hex64.MatchString(receipt.ActionRef) {
		return errors.New("receiptcore: invalid action_ref")
	}
	if receipt.DecisionRef != nil && !hex64.MatchString(*receipt.DecisionRef) {
		return errors.New("receiptcore: invalid decision_ref")
	}
	if receipt.Prev != nil && !hex64.MatchString(*receipt.Prev) {
		return errors.New("receiptcore: invalid prev")
	}
	if !isExactUTCMilliseconds(receipt.IssuedAt) || receipt.Result == nil || receipt.EvidenceRefs == nil || receipt.Signatures == nil {
		return errors.New("receiptcore: invalid ReceiptV1 structure")
	}
	seen := map[string]bool{}
	previous := ""
	for i, ref := range receipt.EvidenceRefs {
		if ref.ArtifactType == "" || !hex64.MatchString(ref.SHA256) {
			return errors.New("receiptcore: invalid evidence_ref")
		}
		key := ref.ArtifactType + "\x00" + ref.SHA256
		if seen[key] || (i > 0 && previous >= key) {
			return errors.New("receiptcore: duplicate or unsorted evidence_refs")
		}
		seen[key], previous = true, key
	}
	seen = map[string]bool{}
	previous = ""
	issuerSigned := false
	for i, proof := range receipt.Signatures {
		if proof.Signer == "" || proof.KeyID == "" || proof.Alg != "Ed25519" || (requireValues && !hex128.MatchString(proof.Value)) {
			return errors.New("receiptcore: invalid ReceiptSignatureV1")
		}
		key := proof.Signer + "\x00" + proof.KeyID
		if seen[key] || (i > 0 && previous >= key) {
			return errors.New("receiptcore: duplicate or unsorted signatures")
		}
		seen[key], previous = true, key
		if proof.Signer == receipt.Issuer {
			issuerSigned = true
		}
	}
	if requireValues && !issuerSigned {
		return errors.New("receiptcore: issuer signature missing")
	}
	_, err := strictJCS(receiptMap(receipt, true, true))
	return err
}

func CreateReceiptV1(fields ReceiptV1, signers []ReceiptSignerV1) (ReceiptV1, error) {
	if len(signers) == 0 {
		return ReceiptV1{}, errors.New("receiptcore: at least one signer")
	}
	fields.EvidenceRefs = append([]EvidenceRefV1(nil), fields.EvidenceRefs...)
	signers = append([]ReceiptSignerV1(nil), signers...)
	sort.Slice(fields.EvidenceRefs, func(i, j int) bool {
		if fields.EvidenceRefs[i].ArtifactType != fields.EvidenceRefs[j].ArtifactType {
			return fields.EvidenceRefs[i].ArtifactType < fields.EvidenceRefs[j].ArtifactType
		}
		return fields.EvidenceRefs[i].SHA256 < fields.EvidenceRefs[j].SHA256
	})
	sort.Slice(signers, func(i, j int) bool {
		if signers[i].Signer != signers[j].Signer {
			return signers[i].Signer < signers[j].Signer
		}
		return signers[i].KeyID < signers[j].KeyID
	})
	fields.ReceiptID = "0000000000000000000000000000000000000000000000000000000000000000"
	fields.Signatures = []ReceiptSignatureV1{}
	if err := ValidateReceiptV1(fields, false); err != nil {
		return ReceiptV1{}, err
	}
	fields.Result = cloneJSONValue(fields.Result).(map[string]interface{})
	id, err := ComputeReceiptIDV1(fields)
	if err != nil {
		return ReceiptV1{}, err
	}
	fields.ReceiptID = id
	for _, signer := range signers {
		descriptor := ReceiptSignatureV1{Signer: signer.Signer, KeyID: signer.KeyID, Alg: "Ed25519"}
		payload, err := ReceiptSignaturePayloadV1(fields, descriptor)
		if err != nil {
			return ReceiptV1{}, err
		}
		value, err := keys.Sign(payload, signer.PrivateKey)
		if err != nil {
			return ReceiptV1{}, err
		}
		descriptor.Value = value
		fields.Signatures = append(fields.Signatures, descriptor)
	}
	if err := ValidateReceiptV1(fields, true); err != nil {
		return ReceiptV1{}, err
	}
	return fields, nil
}

type ReceiptSignatureResultV1 struct {
	Signer, KeyID string
	Valid         bool
	Reason        string
}
type ReceiptVerificationV1 struct {
	Valid, ReceiptIDValid bool
	SignatureResults      []ReceiptSignatureResultV1
	Errors                []string
}

func VerifyReceiptV1(receipt ReceiptV1, resolveKey func(string, string, string) (string, bool)) ReceiptVerificationV1 {
	if err := ValidateReceiptV1(receipt, true); err != nil {
		return ReceiptVerificationV1{Errors: []string{err.Error()}}
	}
	id, err := ComputeReceiptIDV1(receipt)
	result := ReceiptVerificationV1{ReceiptIDValid: err == nil && id == receipt.ReceiptID}
	if !result.ReceiptIDValid {
		result.Errors = append(result.Errors, "receipt_id_mismatch")
	}
	for _, proof := range receipt.Signatures {
		publicKey, ok := resolveKey(proof.Signer, proof.KeyID, receipt.IssuedAt)
		item := ReceiptSignatureResultV1{Signer: proof.Signer, KeyID: proof.KeyID}
		if !ok {
			item.Reason = "key_unresolved"
		} else {
			payload, payloadErr := ReceiptSignaturePayloadV1(receipt, proof)
			item.Valid = payloadErr == nil && keys.Verify(payload, proof.Value, publicKey)
		}
		if !item.Valid {
			result.Errors = append(result.Errors, "signature_invalid")
		}
		result.SignatureResults = append(result.SignatureResults, item)
	}
	result.Valid = len(result.Errors) == 0
	return result
}
