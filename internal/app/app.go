// Package app implements the repo-guardian command-line application.
package app

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: repo-guardian [path]")
		return 2
	}
	root := "."
	if len(args) == 1 {
		root = args[0]
	}

	result, err := scanner.Scan(root)
	if err != nil {
		fmt.Fprintf(stderr, "repo-guardian: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "Repository: %s\n", result.Root)
	fmt.Fprintf(stdout, "Files scanned: %d\n", len(result.Files))
	fmt.Fprintf(stdout, "Total size: %d bytes\n", result.TotalSize)

	categories := make([]string, 0, len(result.CountByCategory))
	for category := range result.CountByCategory {
		categories = append(categories, string(category))
	}
	sort.Strings(categories)
	for _, category := range categories {
		fmt.Fprintf(stdout, "  %s: %d\n", category, result.CountByCategory[scanner.Category(category)])
	}

	health := audit.Evaluate(result)
	fmt.Fprintf(stdout, "Health checks: %d/%d\n", health.Passed, health.Total)
	for _, check := range health.Checks {
		status := "MISSING"
		if check.Passed {
			status = "PASS"
		}
		fmt.Fprintf(stdout, "  [%s] %s", status, check.Label)
		if len(check.Evidence) > 0 {
			fmt.Fprintf(stdout, ": %s", strings.Join(check.Evidence, ", "))
		}
		fmt.Fprintln(stdout)
	}
	return 0
}
