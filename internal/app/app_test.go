package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ramiabukhader/repo-guardian/internal/report"
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
	if !strings.Contains(stdout.String(), "Health score: 45/100") {
		t.Fatalf("score output missing: %q", stdout.String())
	}
}

func TestRunProducesJSONAndGateExitCode(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("not-a-real-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--format", "json", "--fail-on-risk", root}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("Run() code = %d, want gate failure 1; stderr = %q", code, stderr.String())
	}
	var document report.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("JSON output invalid: %v: %q", err, stdout.String())
	}
	if document.Version != "1" || len(document.Risks) != 1 || document.Risks[0].Path != ".env" {
		t.Fatalf("unexpected JSON document: %#v", document)
	}
}

func TestRunValidatesConfigurationFlags(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--large-file-threshold", "0"},
		{"--min-score", "101"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%v) code = %d, want 2", args, code)
		}
	}
}

func TestRunMinimumScoreGate(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--min-score", "31", t.TempDir()}, &stdout, &stderr); code != 1 {
		t.Fatalf("Run() code = %d, want score-gate failure 1; output = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunCustomLargeFileThreshold(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "archive.bin"), []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--large-file-threshold", "3", "--fail-on-risk", root}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("Run() code = %d, want risk-gate failure 1; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[large-file]") {
		t.Fatalf("large-file finding missing: %q", stdout.String())
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
