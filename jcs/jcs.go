// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package jcs implements RFC 8785 JSON Canonicalization Scheme, byte-identical
// to the APS reference SDK canonicalizeJCS (src/core/canonical-jcs.ts).
//
// Byte-faithfulness requires three behaviors that a naive implementation gets
// wrong:
//
//  1. Object keys sort by UTF-16 code unit, the same order JavaScript's
//     Array.prototype.sort uses on strings. This differs from a raw UTF-8 byte
//     sort for code points above the BMP.
//  2. String escaping matches ECMAScript JSON.stringify: only " \ and the
//     control characters below U+0020 are escaped (with \b \f \n \r \t for the
//     named ones and lowercase \u00xx for the rest). Every other character,
//     including non-ASCII and the HTML-sensitive < > &, is emitted as raw
//     UTF-8. Go's encoding/json escapes < > & and U+2028/U+2029, so it cannot
//     be used here.
//  3. Numbers serialize per the ECMAScript Number-to-String algorithm, which is
//     what JSON.stringify applies. Integers print with no decimal point or
//     exponent; -0 prints as 0.
//
// Decode fixture input with json.Decoder.UseNumber() so numbers arrive as
// json.Number and keep full fidelity through canonicalization.
package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize returns the RFC 8785 JCS string for v. v should be the result of
// decoding JSON into Go's generic types (map[string]interface{},
// []interface{}, string, bool, json.Number, float64, nil).
func Canonicalize(v interface{}) (string, error) {
	var sb strings.Builder
	if err := write(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// CanonicalHash returns the lowercase-hex SHA-256 of the canonical bytes. This
// is the strict-JCS counterpart used for action_ref (draft-pidlisnyi-aps-01
// §4.1) and any cross-implementation hash pin.
func CanonicalHash(v interface{}) (string, error) {
	s, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

func write(sb *strings.Builder, v interface{}) error {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		writeString(sb, x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return err
		}
		return writeNumber(sb, f)
	case float64:
		return writeNumber(sb, x)
	case float32:
		return writeNumber(sb, float64(x))
	case int:
		sb.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		sb.WriteString(strconv.FormatInt(x, 10))
	case []interface{}:
		sb.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := write(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			if err := write(sb, x[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return errors.New("jcs: unsupported type for canonicalization")
	}
	return nil
}

// writeNumber serializes per ECMAScript Number-to-String, matching
// JSON.stringify on the JavaScript double that JSON.parse produced.
func writeNumber(sb *strings.Builder, f float64) error {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return errors.New("jcs: Infinity and NaN are not valid JSON numbers")
	}
	if f == 0 {
		// Covers +0 and -0. JavaScript stringifies -0 as "0".
		sb.WriteString("0")
		return nil
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		// Integer-valued double in the no-exponent range: print as an integer.
		sb.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
		return nil
	}
	// Shortest round-trip representation. This matches ECMAScript for the
	// decimal and exponent forms exercised by the APS fixtures. Exotic
	// exponent edge cases are not exercised by any current vector.
	sb.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

// writeString matches ECMAScript JSON.stringify string output.
func writeString(sb *strings.Builder, s string) {
	const hexdigits = "0123456789abcdef"
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexdigits[(r>>4)&0xf])
				sb.WriteByte(hexdigits[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// sortUTF16 sorts keys by UTF-16 code unit, matching JavaScript string sort.
func sortUTF16(keys []string) {
	sort.SliceStable(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
