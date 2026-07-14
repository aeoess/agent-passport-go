// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Cross-SDK coverage for the values raw-JSON entry point. LoadFloor decodes raw
// floor text whose principle strings reach the signed compliance report, so a
// lone surrogate must reject before encoding/json substitutes U+FFFD. This
// matches TypeScript and Python, which preserve the lone surrogate through
// parsing and reject it when the compliance report is canonicalized.
package values

import (
	"errors"
	"testing"

	"github.com/aeoess/agent-passport-go/jcs"
)

func floorWithName(nameJSON string) string {
	return `{"version":"2.0","schema":"aps-floor-v2","lastUpdated":"2026-01-01T00:00:00.000Z",` +
		`"governanceUri":"https://aeoess.org/floor","floor":[{"id":"F-001","name":"` + nameJSON +
		`","principle":"trace","enforcement":{"mechanism":"chain","technical":true},"weight":"mandatory"}]}`
}

func TestLoadFloorRejectsLoneSurrogate(t *testing.T) {
	if _, err := LoadFloor(floorWithName(`bad\uD800`)); !errors.Is(err, jcs.ErrLoneSurrogate) {
		t.Fatalf("LoadFloor want ErrLoneSurrogate, got %v", err)
	}
}

func TestLoadFloorAcceptsValidPairAndReplacementChar(t *testing.T) {
	// A valid non-BMP scalar (escaped surrogate pair) is accepted.
	if _, err := LoadFloor(floorWithName(`ok😀`)); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	// A genuine U+FFFD replacement character is a valid scalar and is accepted.
	if _, err := LoadFloor(floorWithName("ok�")); err != nil {
		t.Fatalf("genuine U+FFFD rejected: %v", err)
	}
}
