package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

func TestRunLoadsRepositoryConfiguration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	config := `{"format":"json","min_score":100,"fail_on_risk":true,"large_file_threshold":2}`
	if err := os.WriteFile(filepath.Join(root, defaultConfigName), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "large.bin"), []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{root}, &stdout, &stderr); code != 1 {
		t.Fatalf("Run() code = %d, want policy failure 1; stderr = %q", code, stderr.String())
	}
	var document report.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("configured JSON output invalid: %v: %q", err, stdout.String())
	}
	foundLargeFile := false
	for _, finding := range document.Risks {
		foundLargeFile = foundLargeFile || finding.Path == "large.bin"
	}
	if !foundLargeFile {
		t.Fatalf("configured threshold not applied: %#v", document.Risks)
	}
}

func TestRunExplicitFlagsOverrideConfiguration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "policy with spaces.json")
	config := `{"format":"json","min_score":100,"fail_on_risk":true}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"--config", configPath, "--format", "human", "--min-score", "0", "--fail-on-risk=false", root}
	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Repository:") || strings.HasPrefix(strings.TrimSpace(stdout.String()), "{") {
		t.Fatalf("explicit human format not applied: %q", stdout.String())
	}
}

func TestRunRejectsInvalidConfigurationFiles(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"unknown field":  `{"min_socre":80}`,
		"trailing value": `{} {}`,
		"invalid range":  `{"min_score":101}`,
		"invalid type":   `{"fail_on_risk":"yes"}`,
		"null document":  `null`,
	}
	for name, contents := range tests {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := filepath.Join(root, "policy.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"--config", path, root}, &stdout, &stderr); code != 2 {
				t.Fatalf("Run() code = %d, want 2; stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "configuration") && name != "invalid range" {
				t.Fatalf("stderr = %q, want configuration context", stderr.String())
			}
		})
	}
}

func TestRunRejectsMissingExplicitConfiguration(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--config", missing, t.TempDir()}, &stdout, &stderr); code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "open configuration") {
		t.Fatalf("stderr = %q, want actionable open error", stderr.String())
	}
}

func TestRunAppliesConfigExclusionsAndCLIReplacesThem(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, relative := range []string{"keep.go", "config-only.txt", "cli-only.txt"} {
		if err := os.WriteFile(filepath.Join(root, relative), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := `{"format":"json","exclude":["config-only.txt"]}`
	if err := os.WriteFile(filepath.Join(root, defaultConfigName), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("config-only Run() code = %d, stderr = %q", code, stderr.String())
	}
	var document report.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document.Repository.ExcludedPaths, []string{"config-only.txt"}) {
		t.Fatalf("config ExcludedPaths = %#v", document.Repository.ExcludedPaths)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--exclude", "cli-only.txt", "--format", "json", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run() code = %d, stderr = %q", code, stderr.String())
	}
	document = report.Document{}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	want := []string{"cli-only.txt"}
	if !reflect.DeepEqual(document.Repository.ExcludedPaths, want) {
		t.Fatalf("ExcludedPaths = %#v, want CLI replacement %#v", document.Repository.ExcludedPaths, want)
	}
}

func TestRunRejectsUnsafeConfigExclusion(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, defaultConfigName), []byte(`{"exclude":["../outside"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{root}, &stdout, &stderr); code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "must not traverse") {
		t.Fatalf("stderr = %q", stderr.String())
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
