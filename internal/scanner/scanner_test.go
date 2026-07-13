package scanner

import (
	"os"
	"path/filepath"
	"runtime"
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
