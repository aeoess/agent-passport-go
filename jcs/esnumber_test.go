// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

package jcs

import "testing"

// ECMAScript Number::toString outputs, validated byte-identical to Node
// JSON.stringify over 20k values (audit 2026-07-10). These cover the ranges
// where Go's strconv 'g' form previously diverged from RFC 8785.
func TestESNumber(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{1e21, "1e+21"}, {1.5e21, "1.5e+21"}, {1e-6, "0.000001"}, {1e-7, "1e-7"},
		{1e-8, "1e-8"}, {0.1, "0.1"}, {100.5, "100.5"}, {1e16, "10000000000000000"},
		{5e-324, "5e-324"}, {1e308, "1e+308"}, {-0.0001, "-0.0001"}, {6.022e23, "6.022e+23"},
		{1.0, "1"}, {-1.0, "-1"}, {123456789.0, "123456789"},
	}
	for _, c := range cases {
		if got := esNumber(c.in); got != c.want {
			t.Errorf("esNumber(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
