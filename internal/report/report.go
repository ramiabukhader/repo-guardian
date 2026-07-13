// Package report assembles the versioned machine-readable audit document.
package report

import (
	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/risk"
	"github.com/ramiabukhader/repo-guardian/internal/scanner"
	"github.com/ramiabukhader/repo-guardian/internal/score"
)

const Version = "1"

// Document is the stable top-level JSON representation.
type Document struct {
	Version    string         `json:"version"`
	Repository Repository     `json:"repository"`
	Health     audit.Result   `json:"health"`
	Risks      []risk.Finding `json:"risks"`
	Score      score.Result   `json:"score"`
}

// Repository contains aggregate scanner and Git-index metadata.
type Repository struct {
	Root                 string         `json:"root"`
	FilesScanned         int            `json:"files_scanned"`
	TotalSizeBytes       int64          `json:"total_size_bytes"`
	Categories           map[string]int `json:"categories"`
	GitTrackingAvailable bool           `json:"git_tracking_available"`
	ExcludedPaths        []string       `json:"excluded_paths"`
	Complete             bool           `json:"complete"`
	Errors               []ScanIssue    `json:"errors"`
}

// ScanIssue is a sanitized incomplete-coverage record.
type ScanIssue struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Build assembles a report without adding nondeterministic timestamps.
func Build(scan scanner.Result, health audit.Result, findings []risk.Finding, trackingAvailable bool) Document {
	categories := make(map[string]int, len(scan.CountByCategory))
	for category, count := range scan.CountByCategory {
		categories[string(category)] = count
	}
	if findings == nil {
		findings = []risk.Finding{}
	}
	excludedPaths := append([]string{}, scan.ExcludedPaths...)
	scanErrors := make([]ScanIssue, 0, len(scan.Errors))
	for _, issue := range scan.Errors {
		scanErrors = append(scanErrors, ScanIssue{Kind: issue.Kind, Path: issue.Path, Message: issue.Message})
	}
	return Document{
		Version: Version,
		Repository: Repository{
			Root:                 scan.Root,
			FilesScanned:         len(scan.Files),
			TotalSizeBytes:       scan.TotalSize,
			Categories:           categories,
			GitTrackingAvailable: trackingAvailable,
			ExcludedPaths:        excludedPaths,
			Complete:             scan.Complete,
			Errors:               scanErrors,
		},
		Health: health,
		Risks:  findings,
		Score:  score.Calculate(health, findings),
	}
}
