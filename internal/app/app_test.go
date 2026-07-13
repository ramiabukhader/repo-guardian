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
