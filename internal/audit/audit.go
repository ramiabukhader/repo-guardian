// Package audit evaluates repository-health checks from scanner metadata.
package audit

import (
	"path"
	"sort"
	"strings"

	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

const (
	CheckREADME              = "readme"
	CheckLicense             = "license"
	CheckGitignore           = "gitignore"
	CheckCI                  = "ci"
	CheckTests               = "tests"
	CheckSecurity            = "security_policy"
	CheckContributing        = "contributing_guide"
	CheckPullRequestTemplate = "pull_request_template"
)

// Check is one auditable repository-health requirement.
type Check struct {
	ID       string
	Label    string
	Passed   bool
	Evidence []string
}

// Result contains checks and aggregate counts.
type Result struct {
	Checks []Check
	Passed int
	Total  int
}

type checkDefinition struct {
	id    string
	label string
	match func(string) bool
}

// Evaluate applies all health checks using paths and categories only.
func Evaluate(scan scanner.Result) Result {
	definitions := []checkDefinition{
		{CheckREADME, "README", isREADME},
		{CheckLicense, "License", isLicense},
		{CheckGitignore, ".gitignore", func(p string) bool { return p == ".gitignore" }},
		{CheckCI, "CI workflow", isCIWorkflow},
		{CheckTests, "Test files", isTestFile},
		{CheckSecurity, "Security policy", isSecurityPolicy},
		{CheckContributing, "Contribution guide", isContributionGuide},
		{CheckPullRequestTemplate, "Pull-request template", isPullRequestTemplate},
	}

	result := Result{Total: len(definitions)}
	for _, definition := range definitions {
		check := Check{ID: definition.id, Label: definition.label}
		for _, file := range scan.Files {
			normalized := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(file.Path, "\\", "/"), "./"))
			if definition.match(normalized) {
				check.Evidence = append(check.Evidence, file.Path)
			}
		}
		sort.Strings(check.Evidence)
		check.Passed = len(check.Evidence) > 0
		if check.Passed {
			result.Passed++
		}
		result.Checks = append(result.Checks, check)
	}
	return result
}

func isREADME(filePath string) bool {
	if strings.Contains(filePath, "/") {
		return false
	}
	base, extension := splitDocumentName(filePath)
	return base == "readme" && isDocumentExtension(extension)
}

func isLicense(filePath string) bool {
	if strings.Contains(filePath, "/") {
		return false
	}
	base, extension := splitDocumentName(filePath)
	return (base == "license" || base == "copying") && isDocumentExtension(extension)
}

func isCIWorkflow(filePath string) bool {
	extension := path.Ext(filePath)
	return strings.HasPrefix(filePath, ".github/workflows/") && (extension == ".yml" || extension == ".yaml")
}

func isTestFile(filePath string) bool {
	filePath = strings.ToLower(filePath)
	base := path.Base(filePath)
	extension := path.Ext(base)
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") || (strings.HasPrefix(base, "test_") && extension == ".py") {
		return true
	}
	for _, marker := range []string{".test.", ".spec."} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return (extension == ".java" && strings.HasSuffix(strings.TrimSuffix(base, extension), "test")) ||
		(extension == ".cs" && strings.HasSuffix(strings.TrimSuffix(base, extension), "tests"))
}

func isSecurityPolicy(filePath string) bool {
	return filePath == "security.md" || filePath == ".github/security.md" || filePath == "docs/security.md"
}

func isContributionGuide(filePath string) bool {
	directory := path.Dir(filePath)
	if directory != "." && directory != ".github" && directory != "docs" {
		return false
	}
	base, extension := splitDocumentName(path.Base(filePath))
	return base == "contributing" && isDocumentExtension(extension)
}

func isPullRequestTemplate(filePath string) bool {
	if filePath == "pull_request_template.md" || filePath == ".github/pull_request_template.md" || filePath == "docs/pull_request_template.md" {
		return true
	}
	return strings.HasPrefix(filePath, ".github/pull_request_template/") && path.Ext(filePath) == ".md"
}

func splitDocumentName(fileName string) (string, string) {
	extension := path.Ext(fileName)
	return strings.TrimSuffix(fileName, extension), extension
}

func isDocumentExtension(extension string) bool {
	return extension == "" || extension == ".md" || extension == ".txt" || extension == ".rst" || extension == ".adoc"
}
