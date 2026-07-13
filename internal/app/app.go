// Package app implements the repo-guardian command-line application.
package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/report"
	"github.com/ramiabukhader/repo-guardian/internal/risk"
	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

// Run executes the CLI and returns a documented process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("repo-guardian", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "human", "output format: human or json")
	largeFileThreshold := flags.Int64("large-file-threshold", risk.DefaultLargeFileThreshold, "large-file threshold in bytes")
	minimumScore := flags.Int("min-score", 0, "minimum acceptable health score (0-100)")
	failOnRisk := flags.Bool("fail-on-risk", false, "exit 1 when any risk is found")
	configPath := flags.String("config", "", "path to a JSON configuration file")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: repo-guardian [flags] [path]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return 2
	}

	root := "."
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}
	explicit := make(map[string]bool)
	flags.Visit(func(item *flag.Flag) { explicit[item.Name] = true })
	resolvedConfigPath := *configPath
	configRequired := explicit["config"]
	if !configRequired {
		resolvedConfigPath = filepath.Join(root, defaultConfigName)
	}
	config, found, err := loadConfig(resolvedConfigPath, configRequired)
	if err != nil {
		fmt.Fprintf(stderr, "repo-guardian: %v\n", err)
		return 2
	}
	if found {
		if config.Format != nil && !explicit["format"] {
			*format = *config.Format
		}
		if config.LargeFileThreshold != nil && !explicit["large-file-threshold"] {
			*largeFileThreshold = *config.LargeFileThreshold
		}
		if config.MinimumScore != nil && !explicit["min-score"] {
			*minimumScore = *config.MinimumScore
		}
		if config.FailOnRisk != nil && !explicit["fail-on-risk"] {
			*failOnRisk = *config.FailOnRisk
		}
	}
	if *format != "human" && *format != "json" {
		fmt.Fprintf(stderr, "repo-guardian: unsupported format %q\n", *format)
		return 2
	}
	if *largeFileThreshold <= 0 {
		fmt.Fprintln(stderr, "repo-guardian: --large-file-threshold must be greater than zero")
		return 2
	}
	if *minimumScore < 0 || *minimumScore > 100 {
		fmt.Fprintln(stderr, "repo-guardian: --min-score must be between 0 and 100")
		return 2
	}

	scan, err := scanner.Scan(root)
	if err != nil {
		fmt.Fprintf(stderr, "repo-guardian: %v\n", err)
		return 2
	}
	health := audit.Evaluate(scan)
	tracked, trackingAvailable, err := risk.DiscoverTracked(scan.Root)
	if err != nil {
		fmt.Fprintf(stderr, "repo-guardian: %v\n", err)
		return 2
	}
	findings := risk.Detect(scan, tracked, risk.Options{LargeFileThreshold: *largeFileThreshold})
	document := report.Build(scan, health, findings, trackingAvailable)

	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(document); err != nil {
			fmt.Fprintf(stderr, "repo-guardian: encode JSON: %v\n", err)
			return 2
		}
	} else {
		writeHuman(stdout, scan, document)
	}

	if document.Score.Total < *minimumScore || (*failOnRisk && len(document.Risks) > 0) {
		return 1
	}
	return 0
}

func writeHuman(output io.Writer, scan scanner.Result, document report.Document) {
	fmt.Fprintf(output, "Repository: %q\n", scan.Root)
	fmt.Fprintf(output, "Files scanned: %d\n", len(scan.Files))
	fmt.Fprintf(output, "Total size: %d bytes\n", scan.TotalSize)

	categories := make([]string, 0, len(scan.CountByCategory))
	for category := range scan.CountByCategory {
		categories = append(categories, string(category))
	}
	sort.Strings(categories)
	for _, category := range categories {
		fmt.Fprintf(output, "  %s: %d\n", category, scan.CountByCategory[scanner.Category(category)])
	}

	fmt.Fprintf(output, "Health checks: %d/%d\n", document.Health.Passed, document.Health.Total)
	for _, check := range document.Health.Checks {
		status := "MISSING"
		if check.Passed {
			status = "PASS"
		}
		fmt.Fprintf(output, "  [%s] %s", status, check.Label)
		if len(check.Evidence) > 0 {
			fmt.Fprintf(output, ": %s", quotePaths(check.Evidence))
		}
		fmt.Fprintln(output)
	}

	fmt.Fprintf(output, "Risks: %d", len(document.Risks))
	if !document.Repository.GitTrackingAvailable {
		fmt.Fprint(output, " (Git tracking unavailable)")
	}
	fmt.Fprintln(output)
	for _, finding := range document.Risks {
		fmt.Fprintf(output, "  [%s] %s", finding.Kind, quotePaths([]string{finding.Path}))
		if finding.Size > 0 {
			fmt.Fprintf(output, " (%d bytes)", finding.Size)
		}
		if finding.Tracked {
			fmt.Fprint(output, " (tracked)")
		}
		fmt.Fprintln(output)
	}
	fmt.Fprintf(output, "Health score: %d/%d (health %d, risk hygiene %d)\n",
		document.Score.Total,
		document.Score.Maximum,
		document.Score.HealthPoints,
		document.Score.RiskHygienePoints,
	)
}

func quotePaths(paths []string) string {
	quoted := make([]string, len(paths))
	for i, filePath := range paths {
		quoted[i] = strconv.Quote(filePath)
	}
	return strings.Join(quoted, ", ")
}
