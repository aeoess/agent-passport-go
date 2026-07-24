// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package receiptcore implements the domain-separated APS v1 receipt wire
// format. JSON field names are part of the signed protocol and remain snake_case.
package receiptcore

type EvidenceRefV1 struct {
	ArtifactType string `json:"artifact_type"`
	SHA256       string `json:"sha256"`
}

type ReceiptSignatureV1 struct {
	Signer string `json:"signer"`
	KeyID  string `json:"key_id"`
	Alg    string `json:"alg"`
	Value  string `json:"value"`
}

type ReceiptSignerV1 struct {
	Signer     string
	KeyID      string
	PrivateKey string
}

type ReceiptV1 struct {
	Profile       string                 `json:"profile"`
	ReceiptID     string                 `json:"receipt_id"`
	ReceiptType   string                 `json:"receipt_type"`
	Issuer        string                 `json:"issuer"`
	SubjectAgent  string                 `json:"subject_agent"`
	ActionRef     string                 `json:"action_ref"`
	DelegationRef string                 `json:"delegation_ref"`
	DecisionRef   *string                `json:"decision_ref,omitempty"`
	IssuedAt      string                 `json:"issued_at"`
	EvidenceRefs  []EvidenceRefV1        `json:"evidence_refs"`
	Result        map[string]interface{} `json:"result"`
	Prev          *string                `json:"prev,omitempty"`
	Signatures    []ReceiptSignatureV1   `json:"signatures"`
}

type DecisionRefInputV1 struct {
	Profile           string `json:"profile"`
	ActionRef         string `json:"action_ref"`
	AuthorityStateRef string `json:"authority_state_ref"`
	PolicyRef         string `json:"policy_ref"`
	ContextRef        string `json:"context_ref"`
	DecisionOutputRef string `json:"decision_output_ref"`
}

type CoreDecisionOutputV1 struct {
	Profile               string   `json:"profile"`
	Verdict               string   `json:"verdict"`
	EffectiveAuthorityRef *string  `json:"effective_authority_ref"`
	Constraints           []string `json:"constraints"`
}

type SupportingRecordV1 struct {
	Profile     string                 `json:"profile"`
	RecordID    string                 `json:"record_id"`
	RecordType  string                 `json:"record_type"`
	Issuer      string                 `json:"issuer"`
	IssuerKeyID string                 `json:"issuer_key_id"`
	IssuedAt    string                 `json:"issued_at"`
	ActionRef   *string                `json:"action_ref,omitempty"`
	Body        map[string]interface{} `json:"body"`
	SigAlg      string                 `json:"sig_alg"`
	Sig         string                 `json:"sig"`
}

type EvidenceBundleMemberInputV2 struct {
	MemberID   string
	MemberType string
	Payload    interface{}
}

type EvidenceBundleMemberV2 struct {
	MemberID   string `json:"member_id"`
	MemberType string `json:"member_type"`
	SHA256     string `json:"sha256"`
}

type EvidenceBundleBodyV2 struct {
	Members    []EvidenceBundleMemberV2 `json:"members"`
	MerkleRoot string                   `json:"merkle_root"`
}

type EvidenceBundleProofStepV2 struct {
	Position string `json:"position"`
	SHA256   string `json:"sha256,omitempty"`
}

type EvidenceBundleProofV2 struct {
	Profile   string                      `json:"profile"`
	Member    EvidenceBundleMemberV2      `json:"member"`
	LeafIndex int                         `json:"leaf_index"`
	LeafCount int                         `json:"leaf_count"`
	Path      []EvidenceBundleProofStepV2 `json:"path"`
}
