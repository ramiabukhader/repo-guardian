package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/risk"
	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

func TestBuildProducesVersionedJSON(t *testing.T) {
	t.Parallel()
	scan := scanner.Result{
		Root:            "/repo",
		Files:           []scanner.File{{Path: "README.md", Size: 7, Category: scanner.CategoryDocumentation}},
		CountByCategory: map[scanner.Category]int{scanner.CategoryDocumentation: 1},
		TotalSize:       7,
	}
	health := audit.Result{Checks: []audit.Check{{ID: audit.CheckREADME, Label: "README", Passed: true}}, Passed: 1, Total: 8}
	document := Build(scan, health, []risk.Finding{{Kind: risk.KindSecretFile, Path: "bad\x1b.pem"}}, true)

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.ContainsRune(string(encoded), '\x1b') {
		t.Fatalf("JSON contains raw escape character: %q", encoded)
	}
	for _, fragment := range []string{`"version":"1"`, `"files_scanned":1`, `"git_tracking_available":true`, `"score"`} {
		if !strings.Contains(string(encoded), fragment) {
			t.Fatalf("JSON %q missing %q", encoded, fragment)
		}
	}
}
