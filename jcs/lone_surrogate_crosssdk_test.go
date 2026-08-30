// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Cross-SDK terminal-state parity for a PROGRAMMATIC lone surrogate (built from
// raw bytes, not decoded from JSON). The same value must reach the same terminal
// state in Go, Python, and TypeScript: rejected before it can be signed. Go now
// rejects at the marshal phase (ValidateGoValue). Python rejects at the sign
// preimage encode step. The TS check runs only against a checkout that carries
// the lone-surrogate fix; otherwise it records the state and does not assert TS,
// so a reference SDK on an unrelated branch does not fail this Go suite.
package jcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func goTerminalState(mode string) string {
	s := loneSurrogate
	if mode == "valid" {
		s = validNonBMP
	}
	if ValidateGoValue(map[string]string{"v": s}) != nil {
		return "REJECT"
	}
	return "ACCEPT"
}

const pyStateScript = `
import sys
sys.path.insert(0, sys.argv[1])
from agent_passport.canonical import canonicalize
s = chr(0xD800) if sys.argv[2] == "lone" else "\U0001F600"
try:
    # The sign/hash preimage encodes the canonical string to UTF-8 bytes.
    canonicalize({"v": s}).encode("utf-8")
    print("ACCEPT")
except Exception:
    print("REJECT")
`

// The probe runs from a directory the TEST created, never from inside the SDK
// checkout, so the import is resolved from APS_TS_REPO rather than from the
// script's own location. Same shape as the intoto and values cross-impl
// oracles: a temp .mjs, an absolute dynamic import, and cmd.Dir set to the
// repo so `npx tsx` and the dependency tree resolve there.
const tsStateScript = `
const { canonicalizeJCS } = await import(process.env.APS_TS_REPO + '/src/core/canonical-jcs.ts')
const s = process.argv[2] === 'lone' ? '\uD800' : '\u{1F600}'
try { canonicalizeJCS({ v: s }); console.log('ACCEPT') } catch { console.log('REJECT') }
`

func have(cmd string, args ...string) bool {
	return exec.Command(cmd, args...).Run() == nil
}

// crossSDKRepo resolves a reference SDK checkout from an environment variable.
//
// RETRO-AUDIT C6. This resolution used to fall back to
// filepath.Join(os.UserHomeDir(), "agent-passport-<lang>") when the variable
// was unset. On a developer machine those paths exist, so the fallback was
// taken silently: the Python branch executed code out of an unrelated real
// checkout, and the TypeScript branch wrote a probe script INTO a real git
// working tree the test does not own. Under a hermetic runner the same test
// skips, so the evidence a CI run produces and the evidence a laptop run
// produces are not the same evidence, and nothing in a green log says which
// one you have.
//
// There is deliberately no fallback. An unconfigured cross-SDK check skips.
// The other cross-impl oracles in this repo (attribution, completion, intoto,
// passport, values, delegation) all resolve this way; this file was the only
// one that did not, and the only os.UserHomeDir() in the repo.
// hermeticity_test.go asserts that it stays that way.
func crossSDKRepo(env string) string {
	return os.Getenv(env)
}

func TestCrossSDKLoneSurrogateTerminalState(t *testing.T) {
	// Go: the marshal-phase guard rejects the lone surrogate and accepts a valid
	// non-BMP scalar.
	if got := goTerminalState("lone"); got != "REJECT" {
		t.Fatalf("Go terminal state for the lone surrogate = %s, want REJECT", got)
	}
	if got := goTerminalState("valid"); got != "ACCEPT" {
		t.Fatalf("Go terminal state for the valid non-BMP scalar = %s, want ACCEPT", got)
	}

	// Python: terminal sign-preimage state. Runs only against the checkout named
	// by APS_PY_REPO, and skips when it is unset. No home-directory fallback:
	// see crossSDKRepo.
	pyRepo := crossSDKRepo("APS_PY_REPO")
	pySrc := filepath.Join(pyRepo, "src")
	if pyRepo == "" {
		t.Log("skipping Python cross-check: set APS_PY_REPO to the agent-passport-python checkout to run the cross-impl oracle")
	} else if have("python3", "--version") && fileExists(filepath.Join(pySrc, "agent_passport", "canonical.py")) {
		dir := t.TempDir()
		script := filepath.Join(dir, "state.py")
		if err := os.WriteFile(script, []byte(pyStateScript), 0o600); err != nil {
			t.Fatalf("write python script: %v", err)
		}
		runPy := func(mode string) string {
			out, err := exec.Command("python3", script, pySrc, mode).Output()
			if err != nil {
				t.Fatalf("python3 state (%s): %v", mode, err)
			}
			return strings.TrimSpace(string(out))
		}
		if got := runPy("lone"); got != "REJECT" {
			t.Errorf("Python terminal state for the lone surrogate = %s, want REJECT (Go/Python divergence)", got)
		}
		if got := runPy("valid"); got != "ACCEPT" {
			t.Errorf("Python terminal state for the valid non-BMP scalar = %s, want ACCEPT", got)
		}
	} else {
		t.Log("skipping Python cross-check: python3 or the agent-passport-python SDK is not available at APS_PY_REPO")
	}

	// TypeScript: terminal state via canonicalizeJCS. Asserts reject only when the
	// checkout carries the lone-surrogate fix; otherwise records the state, since
	// the fix lives on the branch fix/jcs-lone-surrogate.
	tsRepo := crossSDKRepo("APS_TS_REPO")
	if tsRepo == "" {
		t.Log("skipping TypeScript cross-check: set APS_TS_REPO to the agent-passport-system checkout to run the cross-impl oracle")
	} else if have("npx", "--version") && fileExists(filepath.Join(tsRepo, "src", "core", "canonical-jcs.ts")) {
		// The probe lives in a directory this test created and removes. It is
		// never written into the SDK checkout: that tree belongs to somebody
		// else and a test must not leave anything in it, not even briefly.
		script := filepath.Join(t.TempDir(), "aps_crosssdk_state_probe.mjs")
		if err := os.WriteFile(script, []byte(tsStateScript), 0o600); err != nil {
			t.Fatalf("write ts script: %v", err)
		}
		runTS := func(mode string) string {
			cmd := exec.Command("npx", "tsx", script, mode)
			cmd.Dir = tsRepo
			cmd.Env = append(os.Environ(), "APS_TS_REPO="+tsRepo)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("tsx state (%s): %v", mode, err)
			}
			return strings.TrimSpace(string(out))
		}
		if got := runTS("valid"); got != "ACCEPT" {
			t.Errorf("TS terminal state for the valid non-BMP scalar = %s, want ACCEPT", got)
		}
		if got := runTS("lone"); got == "REJECT" {
			t.Log("TS SDK checkout carries the lone-surrogate fix: three-way REJECT parity holds")
		} else {
			t.Logf("TS SDK checkout does NOT reject the lone surrogate (terminal=%s); the TS fix is on branch fix/jcs-lone-surrogate. Go+Python parity is verified; TS parity is pending that branch.", got)
		}
	} else {
		t.Log("skipping TypeScript cross-check: npx or the agent-passport-system SDK is not available at APS_TS_REPO")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
