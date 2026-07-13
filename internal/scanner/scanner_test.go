package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	t.Parallel()
	tests := map[string]Category{
		".github/workflows/ci.yml": CategoryCI,
		"CONFIG.YAML":              CategoryConfiguration,
		"docs/guide.md":            CategoryDocumentation,
		"assets/logo.png":          CategoryOther,
		"cmd/tool/main.go":         CategorySource,
		"pkg/tool/tool_test.go":    CategoryTest,
		"tests/fixture.txt":        CategoryTest,
	}
	for path, want := range tests {
		path, want := path, want
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if got := Classify(path); got != want {
				t.Fatalf("Classify(%q) = %q, want %q", path, got, want)
			}
		})
	}
}

func TestClassifyPortableSeparators(t *testing.T) {
	t.Parallel()
	for _, filePath := range []string{
		".github/workflows/ci.yml",
		`.github\workflows\ci.yml`,
	} {
		if got := Classify(filePath); got != CategoryCI {
			t.Errorf("Classify(%q) = %q, want %q", filePath, got, CategoryCI)
		}
	}
}

func TestScanTraversesAndIgnoresDirectories(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "README.md", "read me")
	writeFixture(t, root, "cmd/tool/main.go", "package main")
	writeFixture(t, root, ".git/config", "ignored")
	writeFixture(t, root, "node_modules/module.js", "ignored")
	writeFixture(t, root, "vendor/dependency.go", "ignored")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got, want := len(result.Files), 2; got != want {
		t.Fatalf("len(Files) = %d, want %d: %#v", got, want, result.Files)
	}
	if result.Files[0].Path != "README.md" || result.Files[1].Path != "cmd/tool/main.go" {
		t.Fatalf("unexpected sorted paths: %#v", result.Files)
	}
	if result.CountByCategory[CategoryDocumentation] != 1 || result.CountByCategory[CategorySource] != 1 {
		t.Fatalf("unexpected category counts: %#v", result.CountByCategory)
	}
}

func TestScanSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks can require elevated Windows privileges")
	}
	root := t.TempDir()
	writeFixture(t, root, "target.txt", "target")
	if err := os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got, want := len(result.Files), 1; got != want {
		t.Fatalf("len(Files) = %d, want %d", got, want)
	}
}

func TestScanRejectsInvalidRoots(t *testing.T) {
	t.Parallel()
	if _, err := Scan(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Scan() error = nil, want missing-root error")
	}

	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(file); err == nil {
		t.Fatal("Scan() error = nil, want non-directory error")
	}
}

func TestScanWithOptionsExcludesPortablePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "keep.go", "package keep")
	writeFixture(t, root, "generated/code.go", "package generated")
	writeFixture(t, root, "nested/cache.tmp", "fixture")

	result, err := ScanWithOptions(root, Options{ExcludePatterns: []string{"generated", `nested\*.tmp`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "keep.go" {
		t.Fatalf("Files = %#v", result.Files)
	}
	want := []string{"generated", "nested/cache.tmp"}
	if !reflect.DeepEqual(result.ExcludedPaths, want) {
		t.Fatalf("ExcludedPaths = %#v, want %#v", result.ExcludedPaths, want)
	}
}

func TestNormalizeExcludePatternRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	for _, patternValue := range []string{"", "../outside", `..\outside`, `C:\outside`, filepath.Join(t.TempDir(), "absolute"), "[bad"} {
		if _, err := NormalizeExcludePattern(patternValue); err == nil {
			t.Errorf("NormalizeExcludePattern(%q) error = nil", patternValue)
		}
	}
}

func TestScanWithWalkerReturnsSanitizedPartialResults(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "README.md", "fixture")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	walker := func(walkRoot string, callback fs.WalkDirFunc) error {
		if err := callback(walkRoot, nil, nil); err != nil {
			return err
		}
		if err := callback(filepath.Join(walkRoot, entries[0].Name()), entries[0], nil); err != nil {
			return err
		}
		return callback(filepath.Join(walkRoot, "denied\x1b[31m"), nil, errors.New("permission denied with absolute path "+walkRoot))
	}

	partial, err := scanWithWalker(root, Options{AllowPartial: true}, walker)
	if err != nil {
		t.Fatal(err)
	}
	if partial.Complete || len(partial.Files) != 1 || len(partial.Errors) != 1 {
		t.Fatalf("partial result = %#v", partial)
	}
	want := ScanIssue{Kind: "walk-error", Path: "denied\x1b[31m", Message: "cannot access path"}
	if !reflect.DeepEqual(partial.Errors[0], want) {
		t.Fatalf("Errors = %#v, want %#v", partial.Errors, want)
	}
	if strings.Contains(partial.Errors[0].Message, root) {
		t.Fatalf("error leaked root: %#v", partial.Errors[0])
	}

	conservative, err := scanWithWalker(root, Options{}, walker)
	var incomplete IncompleteError
	if !errors.As(err, &incomplete) || incomplete.Count != 1 || conservative.Complete {
		t.Fatalf("conservative result = %#v, err = %v", conservative, err)
	}
}

func writeFixture(t *testing.T, root, relativePath, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
