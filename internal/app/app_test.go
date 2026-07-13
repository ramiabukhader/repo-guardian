package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScansProvidedDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run() code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Files scanned: 1") || !strings.Contains(stdout.String(), "documentation: 1") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Health checks: 1/8") || !strings.Contains(stdout.String(), "[PASS] README") {
		t.Fatalf("health output missing: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Risks: 0 (Git tracking unavailable)") {
		t.Fatalf("risk output missing: %q", stdout.String())
	}
}

func TestRunRejectsTooManyArguments(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"one", "two"}, &stdout, &stderr); code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestQuotePathsEscapesTerminalControlCharacters(t *testing.T) {
	t.Parallel()
	got := quotePaths([]string{"safe.md", "bad\x1b[31m.md"})
	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("quotePaths() emitted a raw escape character: %q", got)
	}
	if !strings.Contains(got, `bad\x1b[31m.md`) {
		t.Fatalf("quotePaths() = %q, want escaped path", got)
	}
}
