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

// ErrLoneSurrogate is returned when a string contains an unpaired UTF-16
// surrogate. A lone surrogate is not a valid Unicode scalar and has no UTF-8
// encoding, so RFC 8785 requires rejecting the input rather than replacing it
// with U+FFFD. Check with errors.Is(err, jcs.ErrLoneSurrogate).
var ErrLoneSurrogate = errors.New("jcs: string contains an unpaired UTF-16 surrogate; a lone surrogate has no valid UTF-8 encoding and RFC 8785 requires rejection")

// hasLoneSurrogate reports whether s contains the (invalid) UTF-8 byte sequence
// for a surrogate code point U+D800..U+DFFF: a 0xED lead byte followed by a
// 0xA0..0xBF byte. Valid characters U+D000..U+D7FF use 0xED with a 0x80..0x9F
// second byte, and valid non-BMP scalars use 0xF0..0xF4 lead bytes, so neither
// is flagged. Range over a Go string would silently decode such bytes to U+FFFD,
// so this scans the raw bytes instead.
func hasLoneSurrogate(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			return true
		}
	}
	return false
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
		if hasLoneSurrogate(x) {
			return ErrLoneSurrogate
		}
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
			if hasLoneSurrogate(k) {
				return ErrLoneSurrogate
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
	sb.WriteString(esNumber(f))
	return nil
}

// esNumber renders a finite, non-zero float64 exactly like ECMAScript
// Number::toString, the algorithm RFC 8785 section 3.2.2.3 mandates. Go's
// strconv 'g' form diverges from it: 'g' switches to exponent form at exponent
// < -4 and zero-pads the exponent to two digits (e.g. "1e-05"), whereas
// ECMAScript prints "0.00001" down to 1e-6 and never zero-pads ("1e-7",
// "1e+21"). The shortest scientific form gives the minimal round-trip digits
// and the base-10 exponent of the leading digit; we reformat those per the
// ECMAScript rules. Validated byte-identical to Node JSON.stringify over 20k
// values (jcs/esnumber_test.go).
func esNumber(f float64) string {
	sci := strconv.FormatFloat(f, 'e', -1, 64) // "-1.005e+02", "1e-07"
	neg := ""
	if sci[0] == '-' {
		neg, sci = "-", sci[1:]
	}
	ei := strings.IndexByte(sci, 'e')
	mant := sci[:ei]
	exp, _ := strconv.Atoi(sci[ei+1:])
	digits := mant
	if dot := strings.IndexByte(mant, '.'); dot >= 0 {
		digits = mant[:dot] + mant[dot+1:]
	}
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits)
	n := exp + 1 // value = digits * 10^(n-k); 10^(n-1) <= |value| < 10^n
	switch {
	case k <= n && n <= 21:
		return neg + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return neg + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return neg + "0." + strings.Repeat("0", -n) + digits
	default:
		eout := n - 1
		esign := "+"
		if eout < 0 {
			esign, eout = "-", -eout
		}
		if k == 1 {
			return neg + digits + "e" + esign + strconv.Itoa(eout)
		}
		return neg + digits[:1] + "." + digits[1:] + "e" + esign + strconv.Itoa(eout)
	}
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
