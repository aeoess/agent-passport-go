// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package jcs

import (
	"errors"
	"testing"
)

// loneSurrogate is the WTF-8 encoding of U+D800, a value a Go string can carry
// without ever passing through Unmarshal (for example from a gRPC/protobuf
// endpoint or a DB driver that skipped UTF-8 validation). It is built from raw
// bytes, not decoded from JSON text.
var loneSurrogate = string([]byte{0xED, 0xA0, 0x80})

const (
	validNonBMP = "\U0001F600" // U+1F600, a valid non-BMP Unicode scalar
	replacement = "�"          // a legitimate U+FFFD replacement character (a valid scalar)
)

type walkInner struct {
	Name string
}

type walkOuter struct {
	S      string
	Inner  walkInner
	Slice  []string
	Ptr    *string
	Map    map[string]string
	Ignore string `json:"-"`
	hidden string //nolint:unused // unexported: json.Marshal omits it, so the walker must too
}

func TestValidateGoValueRejectsLoneSurrogate(t *testing.T) {
	lp := loneSurrogate
	cases := map[string]interface{}{
		"plain string":        loneSurrogate,
		"struct field":        walkOuter{S: loneSurrogate},
		"nested struct field": walkOuter{Inner: walkInner{Name: loneSurrogate}},
		"slice element":       walkOuter{Slice: []string{"ok", loneSurrogate}},
		"pointer target":      walkOuter{Ptr: &lp},
		"map value":           map[string]string{"k": loneSurrogate},
		"map key":             map[string]string{loneSurrogate: "v"},
		"interface in slice":  []interface{}{"ok", loneSurrogate},
		"generic map":         map[string]interface{}{"v": loneSurrogate},
		"array element":       [2]string{"ok", loneSurrogate},
	}
	for name, v := range cases {
		err := ValidateGoValue(v)
		if err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
			continue
		}
		if !errors.Is(err, ErrLoneSurrogate) {
			t.Errorf("%s: want ErrLoneSurrogate, got %v", name, err)
		}
	}
}

func TestValidateGoValueRejectsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0xFF, 0xFE}) // invalid UTF-8, not the surrogate byte pattern
	if err := ValidateGoValue(map[string]string{"k": invalid}); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("want ErrInvalidUTF8, got %v", err)
	}
}

func TestValidateGoValueAcceptsValidScalars(t *testing.T) {
	ok := []interface{}{
		validNonBMP,
		replacement,
		walkOuter{S: validNonBMP, Inner: walkInner{Name: replacement}, Slice: []string{"ascii", validNonBMP}},
		map[string]string{validNonBMP: replacement},
		[]interface{}{1, true, nil, "text", validNonBMP},
		// A lone surrogate in a json:"-" field is omitted by json.Marshal, so it
		// never reaches the signed bytes and must not over-reject.
		walkOuter{S: "ok", Ignore: loneSurrogate},
	}
	for i, v := range ok {
		if err := ValidateGoValue(v); err != nil {
			t.Errorf("case %d: expected accept, got %v", i, err)
		}
	}
}

// A custom marshaler that emits invalid content must reject too, or the walker's
// field traversal is bypassable.

type badJSONMarshaler struct{ X int }

func (badJSONMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"\ud800"`), nil }

type badJSONPtrMarshaler struct{ X int }

func (*badJSONPtrMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"\uD800"`), nil }

type badTextMarshaler struct{ X int }

func (badTextMarshaler) MarshalText() ([]byte, error) { return []byte{0xED, 0xA0, 0x80}, nil }

type goodJSONMarshaler struct{ X int }

func (goodJSONMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"` + validNonBMP + `"`), nil }

func TestValidateGoValueRejectsCustomMarshalers(t *testing.T) {
	if err := ValidateGoValue(badJSONMarshaler{}); !errors.Is(err, ErrLoneSurrogate) {
		t.Errorf("json.Marshaler lone-surrogate escape: want ErrLoneSurrogate, got %v", err)
	}
	// Nested behind a struct field, via a pointer-receiver marshaler.
	type holder struct{ M *badJSONPtrMarshaler }
	if err := ValidateGoValue(holder{M: &badJSONPtrMarshaler{}}); !errors.Is(err, ErrLoneSurrogate) {
		t.Errorf("nested pointer json.Marshaler: want ErrLoneSurrogate, got %v", err)
	}
	if err := ValidateGoValue(badTextMarshaler{}); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("encoding.TextMarshaler invalid utf8: want ErrInvalidUTF8, got %v", err)
	}
	// A well-formed custom marshaler is accepted.
	if err := ValidateGoValue(goodJSONMarshaler{}); err != nil {
		t.Errorf("valid json.Marshaler output: want accept, got %v", err)
	}
}
