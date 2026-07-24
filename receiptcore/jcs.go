// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

package receiptcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/aeoess/agent-passport-go/jcs"
)

var ErrInvalidIJSON = errors.New("receiptcore: invalid I-JSON new-write value")

// validateJSONValue permits only actual in-memory JSON values. It deliberately
// rejects structs, custom marshalers, byte slices, non-string map keys, and
// other values that encoding/json could silently coerce before signing.
func validateJSONValue(v interface{}, path string, ancestors map[visit]bool) error {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case bool, string:
		return jcs.ValidateGoValue(x)
	case int:
		if int64(x) > 9007199254740991 || int64(x) < -9007199254740991 {
			return fmt.Errorf("%w: %s integer exceeds the interoperable IEEE 754 range", ErrInvalidIJSON, path)
		}
		return nil
	case int64:
		if x > 9007199254740991 || x < -9007199254740991 {
			return fmt.Errorf("%w: %s integer exceeds the interoperable IEEE 754 range", ErrInvalidIJSON, path)
		}
		return nil
	case json.Number:
		parsed, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return fmt.Errorf("%w: %s invalid number", ErrInvalidIJSON, path)
		}
		if !strings.ContainsAny(string(x), ".eE") && math.Abs(parsed) > 9007199254740991 {
			return fmt.Errorf("%w: %s integer exceeds the interoperable IEEE 754 range", ErrInvalidIJSON, path)
		}
		return nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("%w: %s non-finite number", ErrInvalidIJSON, path)
		}
		if math.Trunc(x) == x && math.Abs(x) > 9007199254740991 {
			return fmt.Errorf("%w: %s integer exceeds the interoperable IEEE 754 range", ErrInvalidIJSON, path)
		}
		return nil
	case float32:
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return fmt.Errorf("%w: %s non-finite number", ErrInvalidIJSON, path)
		}
		if math.Trunc(float64(x)) == float64(x) && math.Abs(float64(x)) > 9007199254740991 {
			return fmt.Errorf("%w: %s integer exceeds the interoperable IEEE 754 range", ErrInvalidIJSON, path)
		}
		return nil
	case []interface{}:
		identity := visit{kind: reflect.Slice, ptr: reflect.ValueOf(x).Pointer()}
		if identity.ptr != 0 && ancestors[identity] {
			return fmt.Errorf("%w: %s cyclic value", ErrInvalidIJSON, path)
		}
		ancestors[identity] = true
		defer delete(ancestors, identity)
		for i, item := range x {
			if err := validateJSONValue(item, fmt.Sprintf("%s[%d]", path, i), ancestors); err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		identity := visit{kind: reflect.Map, ptr: reflect.ValueOf(x).Pointer()}
		if ancestors[identity] {
			return fmt.Errorf("%w: %s cyclic value", ErrInvalidIJSON, path)
		}
		ancestors[identity] = true
		defer delete(ancestors, identity)
		for key, item := range x {
			if err := jcs.ValidateGoValue(key); err != nil {
				return err
			}
			if err := validateJSONValue(item, path+"."+key, ancestors); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: %s unsupported %T", ErrInvalidIJSON, path, v)
	}
}

type visit struct {
	kind reflect.Kind
	ptr  uintptr
}

func strictJCS(v interface{}) (string, error) {
	if err := validateJSONValue(v, "$", map[visit]bool{}); err != nil {
		return "", err
	}
	return jcs.Canonicalize(v)
}

// ParseStrictIJSON parses bounded raw JSON without losing duplicate object
// names. Names are compared after JSON escape decoding, so "a" and "\u0061"
// collide. Callers should use this before mapping untrusted wire JSON to structs.
func ParseStrictIJSON(raw []byte, maxBytes, maxDepth int) (interface{}, error) {
	if maxBytes < 1 || len(raw) > maxBytes {
		return nil, fmt.Errorf("%w: raw JSON size limit exceeded", ErrInvalidIJSON)
	}
	if maxDepth < 1 {
		return nil, fmt.Errorf("%w: invalid depth limit", ErrInvalidIJSON)
	}
	if err := jcs.ValidateJSONText(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var parse func(int) (interface{}, error)
	parse = func(depth int) (interface{}, error) {
		if depth > maxDepth {
			return nil, fmt.Errorf("%w: JSON nesting limit exceeded", ErrInvalidIJSON)
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid JSON", ErrInvalidIJSON)
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return token, nil
		}
		switch delim {
		case '{':
			value := map[string]interface{}{}
			seen := map[string]bool{}
			for decoder.More() {
				nameToken, nameErr := decoder.Token()
				name, ok := nameToken.(string)
				if nameErr != nil || !ok {
					return nil, fmt.Errorf("%w: invalid object member", ErrInvalidIJSON)
				}
				if seen[name] {
					return nil, fmt.Errorf("%w: duplicate object member", ErrInvalidIJSON)
				}
				seen[name] = true
				member, memberErr := parse(depth + 1)
				if memberErr != nil {
					return nil, memberErr
				}
				value[name] = member
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("%w: invalid object end", ErrInvalidIJSON)
			}
			return value, nil
		case '[':
			value := []interface{}{}
			for decoder.More() {
				member, memberErr := parse(depth + 1)
				if memberErr != nil {
					return nil, memberErr
				}
				value = append(value, member)
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("%w: invalid array end", ErrInvalidIJSON)
			}
			return value, nil
		default:
			return nil, fmt.Errorf("%w: unexpected delimiter", ErrInvalidIJSON)
		}
	}
	value, err := parse(1)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing JSON data", ErrInvalidIJSON)
	}
	if err = validateJSONValue(value, "$", map[visit]bool{}); err != nil {
		return nil, err
	}
	return value, nil
}

func cloneJSONValue(v interface{}) interface{} {
	switch x := v.(type) {
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, item := range x {
			out[i] = cloneJSONValue(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for key, item := range x {
			out[key] = cloneJSONValue(item)
		}
		return out
	default:
		return x
	}
}

func hashTagged(tag string, value interface{}) (string, error) {
	canonical, err := strictJCS(value)
	if err != nil {
		return "", err
	}
	return sha256Hex([]byte(tag + "\x00" + canonical)), nil
}
