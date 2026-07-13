package audit

import (
	"reflect"
	"testing"

	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

func TestEvaluateRecognizesHealthFiles(t *testing.T) {
	t.Parallel()
	scan := scanWithPaths(
		"README.MD",
		"LICENSE",
		".gitignore",
		".github/workflows/CI.YAML",
		"internal/tool/tool_test.go",
		".github/SECURITY.md",
		"docs/CONTRIBUTING.adoc",
		".github/PULL_REQUEST_TEMPLATE/feature.md",
	)

	result := Evaluate(scan)
	if result.Passed != result.Total || result.Total != 8 {
		t.Fatalf("Evaluate() passed %d/%d, want 8/8: %#v", result.Passed, result.Total, result.Checks)
	}
	for _, check := range result.Checks {
		if !check.Passed || len(check.Evidence) != 1 {
			t.Fatalf("check = %#v, want one item of evidence", check)
		}
	}
}

func TestEvaluateDoesNotAcceptLookalikes(t *testing.T) {
	t.Parallel()
	scan := scanWithPaths(
		"docs/README.md",
		"third_party/LICENSE",
		"gitignore",
		".github/workflows/notes.txt",
		".github/workflows/archive/old.yml",
		"tests/fixture.json",
		"notes.test.txt",
		"security/policy.md",
		"notes/contributing.md",
		".github/pull_request_template.txt",
	)

	result := Evaluate(scan)
	if result.Passed != 0 {
		t.Fatalf("Evaluate() passed = %d, want 0: %#v", result.Passed, result.Checks)
	}
}

func TestEvaluateSortsMultipleTemplateEvidence(t *testing.T) {
	t.Parallel()
	result := Evaluate(scanWithPaths(
		".github/PULL_REQUEST_TEMPLATE/z-fix.md",
		".github/PULL_REQUEST_TEMPLATE/a-feature.md",
	))

	var evidence []string
	for _, check := range result.Checks {
		if check.ID == CheckPullRequestTemplate {
			evidence = check.Evidence
		}
	}
	want := []string{
		".github/PULL_REQUEST_TEMPLATE/a-feature.md",
		".github/PULL_REQUEST_TEMPLATE/z-fix.md",
	}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("template evidence = %#v, want %#v", evidence, want)
	}
}

func TestTestFileConventions(t *testing.T) {
	t.Parallel()
	for _, filePath := range []string{
		"tool_test.go", "test_tool.py", "tool_test.py", "tool.test.js", "tool.spec.ts", "ToolTest.java", "ToolTests.cs",
	} {
		if !isTestFile(filePath) {
			t.Errorf("isTestFile(%q) = false, want true", filePath)
		}
	}
	for _, filePath := range []string{"tests/fixture.json", "contest.go", "latest.py", "notes.test.txt"} {
		if isTestFile(filePath) {
			t.Errorf("isTestFile(%q) = true, want false", filePath)
		}
	}
}

func scanWithPaths(paths ...string) scanner.Result {
	files := make([]scanner.File, 0, len(paths))
	for _, filePath := range paths {
		files = append(files, scanner.File{Path: filePath})
	}
	return scanner.Result{Files: files}
}
