// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package receiptcore

import (
	"errors"
	"regexp"
	"sort"

	"golang.org/x/text/unicode/norm"
)

const DecisionRefTag = "APS-DECISION-REF-V1"

var decisionComponentTags = map[string]string{
	"authority": "APS-DECISION-AUTHORITY-V1",
	"policy":    "APS-DECISION-POLICY-V1",
	"context":   "APS-DECISION-CONTEXT-V1",
	"output":    "APS-DECISION-OUTPUT-V1",
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ComputeDecisionComponentRefV1(kind string, value interface{}) (string, error) {
	tag, ok := decisionComponentTags[kind]
	if !ok {
		return "", errors.New("receiptcore: unknown decision component")
	}
	return hashTagged(tag, value)
}

func decisionRefMap(input DecisionRefInputV1) map[string]interface{} {
	return map[string]interface{}{
		"profile": input.Profile, "action_ref": input.ActionRef,
		"authority_state_ref": input.AuthorityStateRef, "policy_ref": input.PolicyRef,
		"context_ref": input.ContextRef, "decision_output_ref": input.DecisionOutputRef,
	}
}

func ValidateDecisionRefInputV1(input DecisionRefInputV1) error {
	if input.Profile != "aps-decision-ref-v1" {
		return errors.New("receiptcore: DecisionRefInputV1 profile")
	}
	for _, value := range []string{input.ActionRef, input.AuthorityStateRef, input.PolicyRef, input.ContextRef, input.DecisionOutputRef} {
		if !hex64.MatchString(value) {
			return errors.New("receiptcore: DecisionRefInputV1 ref must be lowercase sha256 hex")
		}
	}
	_, err := strictJCS(decisionRefMap(input))
	return err
}

func ComputeDecisionRefV1(input DecisionRefInputV1) (string, error) {
	if err := ValidateDecisionRefInputV1(input); err != nil {
		return "", err
	}
	return hashTagged(DecisionRefTag, decisionRefMap(input))
}

func BuildDecisionRefV1(actionRef string, authorityState, policyInput, decisionContext, decisionOutput interface{}) (DecisionRefInputV1, string, error) {
	if !hex64.MatchString(actionRef) {
		return DecisionRefInputV1{}, "", errors.New("receiptcore: action_ref must be lowercase sha256 hex")
	}
	authority, err := ComputeDecisionComponentRefV1("authority", authorityState)
	if err != nil {
		return DecisionRefInputV1{}, "", err
	}
	policy, err := ComputeDecisionComponentRefV1("policy", policyInput)
	if err != nil {
		return DecisionRefInputV1{}, "", err
	}
	context, err := ComputeDecisionComponentRefV1("context", decisionContext)
	if err != nil {
		return DecisionRefInputV1{}, "", err
	}
	output, err := ComputeDecisionComponentRefV1("output", decisionOutput)
	if err != nil {
		return DecisionRefInputV1{}, "", err
	}
	input := DecisionRefInputV1{Profile: "aps-decision-ref-v1", ActionRef: actionRef, AuthorityStateRef: authority, PolicyRef: policy, ContextRef: context, DecisionOutputRef: output}
	ref, err := ComputeDecisionRefV1(input)
	return input, ref, err
}

func NormalizeCoreDecisionOutputV1(input CoreDecisionOutputV1) (CoreDecisionOutputV1, error) {
	if input.Profile != "aps-core-decision-output-v1" || (input.Verdict != "permit" && input.Verdict != "deny" && input.Verdict != "narrow") {
		return CoreDecisionOutputV1{}, errors.New("receiptcore: CoreDecisionOutputV1 profile or verdict")
	}
	if input.Verdict == "deny" && input.EffectiveAuthorityRef != nil {
		return CoreDecisionOutputV1{}, errors.New("receiptcore: deny requires null effective_authority_ref")
	}
	if input.Verdict != "deny" && (input.EffectiveAuthorityRef == nil || !hex64.MatchString(*input.EffectiveAuthorityRef)) {
		return CoreDecisionOutputV1{}, errors.New("receiptcore: permit/narrow require effective_authority_ref")
	}
	if input.Verdict == "deny" && input.ValidUntil != nil {
		return CoreDecisionOutputV1{}, errors.New("receiptcore: deny requires null valid_until")
	}
	if input.Verdict != "deny" && (input.ValidUntil == nil || !isExactUTCMilliseconds(*input.ValidUntil)) {
		return CoreDecisionOutputV1{}, errors.New("receiptcore: permit/narrow require valid_until as exact UTC milliseconds")
	}
	set := map[string]struct{}{}
	for _, constraint := range input.Constraints {
		if _, err := strictJCS(constraint); err != nil {
			return CoreDecisionOutputV1{}, err
		}
		set[norm.NFC.String(constraint)] = struct{}{}
	}
	constraints := make([]string, 0, len(set))
	for value := range set {
		constraints = append(constraints, value)
	}
	sort.Strings(constraints) // UTF-8 order equals Unicode code-point order for scalar strings.
	input.Constraints = constraints
	return input, nil
}

// CoreDecisionOutputMapV1 renders a normalized decision output as the I-JSON
// value that is canonicalized and hashed. strictJCS rejects Go structs, so a
// caller computing the "output" component ref must hash this map rather than
// the struct; the two would otherwise drift silently as members are added.
func CoreDecisionOutputMapV1(input CoreDecisionOutputV1) map[string]interface{} {
	constraints := make([]interface{}, len(input.Constraints))
	for i, constraint := range input.Constraints {
		constraints[i] = constraint
	}
	value := map[string]interface{}{
		"profile": input.Profile, "verdict": input.Verdict,
		"effective_authority_ref": nil, "constraints": constraints,
		"valid_until": nil,
	}
	if input.EffectiveAuthorityRef != nil {
		value["effective_authority_ref"] = *input.EffectiveAuthorityRef
	}
	if input.ValidUntil != nil {
		value["valid_until"] = *input.ValidUntil
	}
	return value
}
