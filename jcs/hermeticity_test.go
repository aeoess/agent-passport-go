// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Repo-wide hermeticity guard for the test suite.
//
// RETRO-AUDIT C6. jcs/lone_surrogate_crosssdk_test.go resolved two reference
// SDK checkouts by falling back to os.UserHomeDir() when APS_PY_REPO and
// APS_TS_REPO were unset, then EXECUTED code out of one of them and WROTE a
// probe script into the other — a real git working tree belonging to an
// unrelated repository. On a hermetic runner both branches skip, so the defect
// is invisible in a passing log: `go test ./... exit 0` on a laptop and the
// same line in CI were not describing the same run.
//
// The instance is fixed. This test closes the class: a test in this repo may
// not consult the user's home directory to find anything, and may not write
// outside a directory it created. It is deliberately a source-level assertion,
// because the failure mode is a branch that does not execute under the very
// conditions that would make it safe to observe.
package jcs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleRoot walks up from the current package directory to the directory
// holding go.mod, so the scan covers every package and not just this one.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// goTestFiles returns every *_test.go under the module root, excluding
// vendored and cached trees.
func goTestFiles(t *testing.T) []string {
	t.Helper()
	root := moduleRoot(t)
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatal("scanned the module root and found no _test.go files; the guard is not looking where it thinks it is")
	}
	return out
}

// TestNoTestResolvesThroughTheUserHomeDirectory is the guard that would have
// caught C6 at the moment it was written.
//
// It parses each file and inspects CALL EXPRESSIONS, not raw text: a guard
// that greps for a string is defeated by its own documentation, and a comment
// explaining why a construct is banned must not itself trip the ban.
func TestNoTestResolvesThroughTheUserHomeDirectory(t *testing.T) {
	files := goTestFiles(t)
	t.Logf("scanned %d _test.go files under %s", len(files), moduleRoot(t))

	// os.UserHomeDir(), and os.Getenv on the home-directory variables, all
	// resolve a path the test does not own. A cross-SDK oracle must name its
	// dependency explicitly via APS_*_REPO and skip when it is unset, the way
	// every other one in this repo does.
	homeEnv := map[string]bool{"HOME": true, "USERPROFILE": true}

	var found []string
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			switch sel.Sel.Name {
			case "UserHomeDir":
				found = append(found, fset.Position(call.Pos()).String()+": os.UserHomeDir()")
			case "Getenv", "LookupEnv":
				if len(call.Args) == 1 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						name := strings.Trim(lit.Value, `"`)
						if homeEnv[name] {
							found = append(found, fset.Position(call.Pos()).String()+": os."+sel.Sel.Name+"(\""+name+"\")")
						}
					}
				}
			}
			return true
		})
	}
	if len(found) > 0 {
		t.Errorf("a test resolves a path through the user's home directory, so it reads or writes a tree it does not own:\n  %s\n"+
			"Gate on an APS_*_REPO environment variable and skip when it is unset (see crossSDKRepo in lone_surrogate_crosssdk_test.go).",
			strings.Join(found, "\n  "))
	}
}

// TestCrossSDKRepoNeverGuesses pins the resolver itself: unset means unset,
// never a path on this machine that happens to exist.
func TestCrossSDKRepoNeverGuesses(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "agent-passport-system", "src", "core"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	for _, env := range []string{"APS_TS_REPO", "APS_PY_REPO"} {
		t.Setenv(env, "")
		if got := crossSDKRepo(env); got != "" {
			t.Errorf("crossSDKRepo(%q) with the variable unset = %q, want \"\": the resolver guessed at a path outside the test's control", env, got)
		}
	}

	// And when it IS set, it is honoured verbatim.
	t.Setenv("APS_TS_REPO", "/nonexistent/explicitly/named")
	if got := crossSDKRepo("APS_TS_REPO"); got != "/nonexistent/explicitly/named" {
		t.Errorf("crossSDKRepo did not honour an explicitly named checkout: got %q", got)
	}
}

// TestCrossSDKProbeStaysInsideATestOwnedDirectory pins the second half of C6:
// the probe script is written to a directory the test created, never into the
// SDK checkout under test.
func TestCrossSDKProbeStaysInsideATestOwnedDirectory(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(moduleRoot(t), "jcs", "lone_surrogate_crosssdk_test.go"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(src)

	if !strings.Contains(s, `filepath.Join(t.TempDir(), "aps_crosssdk_state_probe.mjs")`) {
		t.Error("the cross-SDK probe script is no longer written into t.TempDir()")
	}
	if strings.Contains(s, `filepath.Join(tsRepo, "aps_crosssdk_state_probe`) {
		t.Error("the cross-SDK probe script is written into the SDK checkout again; it must stay in a directory the test created")
	}
	// The home-directory fallback itself is covered by
	// TestNoTestResolvesThroughTheUserHomeDirectory, which parses rather than
	// greps and so is not tripped by the comment that explains the ban.
}
