// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package jcs

import (
	"encoding"
	"encoding/json"
	"reflect"
	"unicode/utf8"
)

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// ValidateGoValue recursively walks a typed Go value and rejects any string it
// contains that is not a sequence of Unicode scalar values: a WTF-8 lone
// surrogate (the 0xED 0xA0..0xBF byte pattern a Go string can carry without ever
// passing through Unmarshal) or any other invalid UTF-8. It returns the typed
// CanonicalizationError (errors.Is against ErrLoneSurrogate or ErrInvalidUTF8)
// on the first offending string, or nil.
//
// It MUST run BEFORE json.Marshal, because json.Marshal silently rewrites a lone
// surrogate to U+FFFD; after that a mutated surrogate and a legitimate U+FFFD
// are byte-identical, so the evidence is destroyed and Go would sign a value
// TypeScript and Python reject. A legitimate U+FFFD is a valid scalar and is
// accepted, which is exactly the distinction utf8.ValidString draws.
//
// Coverage: plain strings; map keys and values; slice and array elements;
// exported struct fields (unexported fields and json:"-" fields are skipped, the
// same fields json.Marshal omits); and values behind pointers and interfaces, to
// any depth. A value (or nested value) that implements json.Marshaler is asked
// for its JSON and the bytes are checked with ValidateJSONText (which catches a
// lone-surrogate \uXXXX escape and invalid UTF-8 in raw JSON text); a value that
// implements encoding.TextMarshaler is asked for its text and the bytes are
// checked with utf8.Valid. This mirrors json.Marshal's own dispatch, so a custom
// marshaler cannot smuggle an invalid string past the field walk.
func ValidateGoValue(v interface{}) error {
	if v == nil {
		return nil
	}
	// Copy into an addressable value so a pointer-receiver marshaler on a nested
	// field is considered exactly as json.Marshal would consider it.
	rv := reflect.New(reflect.TypeOf(v)).Elem()
	rv.Set(reflect.ValueOf(v))
	return walkGoValue(rv, map[uintptr]struct{}{})
}

func walkGoValue(rv reflect.Value, seen map[uintptr]struct{}) error {
	if !rv.IsValid() {
		return nil
	}

	if rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		return walkGoValue(rv.Elem(), seen)
	}

	// Custom marshalers are used by json.Marshal in place of the default field
	// walk, so validate their output and stop descending. A nil pointer is not
	// dispatched to a marshaler by json.Marshal (it emits null), so it is left
	// to the pointer case below.
	if !(rv.Kind() == reflect.Ptr && rv.IsNil()) {
		if m, ok := asJSONMarshaler(rv); ok {
			b, err := m.MarshalJSON()
			if err != nil {
				return err
			}
			return ValidateJSONText(b)
		}
		if m, ok := asTextMarshaler(rv); ok {
			b, err := m.MarshalText()
			if err != nil {
				return err
			}
			if !utf8.Valid(b) {
				return errInvalidUTF8()
			}
			return nil
		}
	}

	switch rv.Kind() {
	case reflect.String:
		return validateScalarString(rv.String())

	case reflect.Ptr:
		if rv.IsNil() {
			return nil
		}
		addr := rv.Pointer()
		if _, ok := seen[addr]; ok {
			return nil // a cycle; json.Marshal reports it separately
		}
		seen[addr] = struct{}{}
		return walkGoValue(rv.Elem(), seen)

	case reflect.Struct:
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // unexported: json.Marshal omits it
				continue
			}
			if tag, ok := f.Tag.Lookup("json"); ok && tag == "-" { // json:"-": omitted
				continue
			}
			if err := walkGoValue(rv.Field(i), seen); err != nil {
				return err
			}
		}
		return nil

	case reflect.Map:
		for _, k := range rv.MapKeys() {
			if err := walkGoValue(k, seen); err != nil {
				return err
			}
			if err := walkGoValue(rv.MapIndex(k), seen); err != nil {
				return err
			}
		}
		return nil

	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := walkGoValue(rv.Index(i), seen); err != nil {
				return err
			}
		}
		return nil

	default:
		return nil // numbers, bool, and other non-string-bearing kinds
	}
}

// asJSONMarshaler returns the json.Marshaler json.Marshal would use for rv: the
// value receiver if the value type implements it, otherwise the pointer receiver
// when rv is addressable (json.Marshal only takes the address of addressable
// values).
func asJSONMarshaler(rv reflect.Value) (json.Marshaler, bool) {
	if rv.Type().Implements(jsonMarshalerType) {
		if m, ok := rv.Interface().(json.Marshaler); ok {
			return m, true
		}
	}
	if rv.CanAddr() && reflect.PtrTo(rv.Type()).Implements(jsonMarshalerType) {
		if m, ok := rv.Addr().Interface().(json.Marshaler); ok {
			return m, true
		}
	}
	return nil, false
}

func asTextMarshaler(rv reflect.Value) (encoding.TextMarshaler, bool) {
	if rv.Type().Implements(textMarshalerType) {
		if m, ok := rv.Interface().(encoding.TextMarshaler); ok {
			return m, true
		}
	}
	if rv.CanAddr() && reflect.PtrTo(rv.Type()).Implements(textMarshalerType) {
		if m, ok := rv.Addr().Interface().(encoding.TextMarshaler); ok {
			return m, true
		}
	}
	return nil, false
}
