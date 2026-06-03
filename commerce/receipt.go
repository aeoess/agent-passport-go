// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package commerce

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
	"github.com/aeoess/agent-passport-go/verify"
)

// ReceiptAction is the action block of a commerce receipt. Mirrors the inline
// action object in CommerceActionReceipt (src/types/commerce.ts).
type ReceiptAction struct {
	Type      string `json:"type"`
	Target    string `json:"target"`
	Method    string `json:"method"`
	ScopeUsed string `json:"scopeUsed"`
	Spend     Money  `json:"spend"`
}

// ReceiptItem is a line item inside the receipt checkout block. The reference
// SDK records skuId, name, quantity, and the unit price as a bare number.
type ReceiptItem struct {
	SkuID     string  `json:"skuId"`
	Name      string  `json:"name"`
	Quantity  float64 `json:"quantity"`
	UnitPrice float64 `json:"unitPrice"`
}

// ReceiptCheckout is the checkout snapshot inside a commerce receipt. Mirrors
// the inline checkout object in CommerceActionReceipt (src/types/commerce.ts).
type ReceiptCheckout struct {
	SessionID     string        `json:"sessionId"`
	MerchantName  string        `json:"merchantName"`
	Items         []ReceiptItem `json:"items"`
	TotalAmount   float64       `json:"totalAmount"`
	TotalCurrency string        `json:"totalCurrency"`
	Status        string        `json:"status"`
}

// CommerceActionReceipt is a signed record of a commerce action. Mirrors
// CommerceActionReceipt in src/types/commerce.ts. The signed preimage is
// jcs.Canonicalize(receipt with the signature field removed); the signature is
// Ed25519 over those bytes.
type CommerceActionReceipt struct {
	ReceiptID          string          `json:"receiptId"`
	Version            string          `json:"version"`
	Timestamp          string          `json:"timestamp"`
	AgentID            string          `json:"agentId"`
	DelegationID       string          `json:"delegationId"`
	Action             ReceiptAction   `json:"action"`
	Checkout           ReceiptCheckout `json:"checkout"`
	DelegationChain    []string        `json:"delegationChain"`
	Beneficiary        string          `json:"beneficiary"`
	ValuesFloorVersion string          `json:"valuesFloorVersion,omitempty"`
	IdempotencyKey     string          `json:"idempotencyKey,omitempty"`
	Signature          string          `json:"signature,omitempty"`
}

// SignCommerceReceipt signs a commerce action receipt with the caller's private
// key and returns the receipt with its signature populated. Mirrors
// signCommerceReceipt in src/core/commerce.ts.
//
// The signed preimage is jcs.Canonicalize(receipt with the signature field
// removed). The caller supplies all identity, timestamp, and content fields so
// the artifact is fully deterministic. The receipt argument should already
// carry an empty Signature; any value present is stripped before signing.
//
// privateKeyHex is the 32-byte Ed25519 seed in hex. It is never logged and
// never placed in an error string.
func SignCommerceReceipt(receipt CommerceActionReceipt, privateKeyHex string) (CommerceActionReceipt, error) {
	receipt.Signature = ""
	body, err := structToMap(receipt)
	if err != nil {
		return CommerceActionReceipt{}, err
	}
	// structToMap already drops omitempty-empty fields; the signature field is
	// absent because it is empty. Strip defensively in case a future caller
	// passes a non-omitempty signature.
	delete(body, "signature")

	sig, err := keys.SignArtifact(body, "signature", privateKeyHex)
	if err != nil {
		return CommerceActionReceipt{}, err
	}
	receipt.Signature = sig
	return receipt, nil
}

// VerifyCommerceReceipt verifies a commerce receipt signature against publicKey
// and validates the required structural fields. Mirrors verifyCommerceReceipt
// in src/core/commerce.ts: it returns valid plus the list of error strings.
//
// The signature is checked over jcs.Canonicalize(receipt minus signature). The
// structural checks mirror the reference exactly (receiptId, agentId,
// delegationId, action.type, action.scopeUsed, beneficiary, checkout.sessionId).
func VerifyCommerceReceipt(receipt CommerceActionReceipt, publicKey string) (bool, []string) {
	errs := []string{}

	sig := receipt.Signature
	receipt.Signature = ""
	body, err := structToMap(receipt)
	if err != nil {
		errs = append(errs, "Failed to verify commerce receipt signature")
	} else {
		delete(body, "signature")
		canonical, cerr := jcs.Canonicalize(body)
		if cerr != nil {
			errs = append(errs, "Failed to verify commerce receipt signature")
		} else if !verify.VerifyEd25519([]byte(canonical), sig, publicKey) {
			errs = append(errs, "Commerce receipt signature is invalid")
		}
	}

	if receipt.ReceiptID == "" {
		errs = append(errs, "Missing receiptId")
	}
	if receipt.AgentID == "" {
		errs = append(errs, "Missing agentId")
	}
	if receipt.DelegationID == "" {
		errs = append(errs, "Missing delegationId")
	}
	if receipt.Action.Type == "" {
		errs = append(errs, "Missing action type")
	}
	if receipt.Action.ScopeUsed == "" {
		errs = append(errs, "Missing scopeUsed")
	}
	if receipt.Beneficiary == "" {
		errs = append(errs, "Missing beneficiary")
	}
	if receipt.Checkout.SessionID == "" {
		errs = append(errs, "Missing checkout sessionId")
	}

	return len(errs) == 0, errs
}

// ── Shared canonicalization helpers ──

// structToMap round-trips v through JSON into a generic map so that the
// canonical preimage is computed from exactly the JSON shape the typed struct
// produces (honoring json tags and omitempty). Numbers are decoded as
// json.Number so jcs.Canonicalize applies the ECMAScript number formatting that
// matches the reference SDK.
func structToMap(v interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// jcsCanonicalize is a thin wrapper so callers in this package share one entry
// point into the JCS core.
func jcsCanonicalize(v interface{}) (string, error) {
	return jcs.Canonicalize(v)
}

// fmtNum formats a numeric amount the way the reference SDK interpolates a
// number into a string: integers print with no decimal point, fractional values
// print in their shortest round-trip form. Detail strings are human-readable
// only and are not part of any signed preimage.
func fmtNum(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
