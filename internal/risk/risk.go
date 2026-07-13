// Package risk detects security and repository-storage hazards from metadata.
package risk

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strings"

	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

const DefaultLargeFileThreshold int64 = 10 * 1024 * 1024

// Kind is a stable category for a risk finding.
type Kind string

const (
	KindBuildOutput     Kind = "build-output"
	KindEnvironmentFile Kind = "environment-file"
	KindLargeFile       Kind = "large-file"
	KindSecretFile      Kind = "secret-file"
)

// Finding describes metadata about a risk. It never contains file content.
type Finding struct {
	Kind    Kind
	Path    string
	Size    int64
	Tracked bool
}

// Options configures risk detection.
type Options struct {
	LargeFileThreshold int64
}

// Detect finds repository risks and returns them in deterministic order.
func Detect(scan scanner.Result, tracked map[string]struct{}, options Options) []Finding {
	threshold := options.LargeFileThreshold
	if threshold <= 0 {
		threshold = DefaultLargeFileThreshold
	}

	var findings []Finding
	for _, file := range scan.Files {
		normalized := strings.TrimPrefix(strings.ReplaceAll(file.Path, "\\", "/"), "./")
		_, isTracked := tracked[normalized]
		if isEnvironmentFile(normalized) {
			findings = append(findings, Finding{Kind: KindEnvironmentFile, Path: file.Path, Tracked: isTracked})
		}
		if isSecretFile(normalized) {
			findings = append(findings, Finding{Kind: KindSecretFile, Path: file.Path, Tracked: isTracked})
		}
		if file.Size >= threshold {
			findings = append(findings, Finding{Kind: KindLargeFile, Path: file.Path, Size: file.Size, Tracked: isTracked})
		}
		if isTracked && isBuildOutput(normalized) {
			findings = append(findings, Finding{Kind: KindBuildOutput, Path: file.Path, Tracked: true})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}

// DiscoverTracked returns paths from the local Git index. available is false
// when root is not a worktree or the Git executable is unavailable.
func DiscoverTracked(root string) (tracked map[string]struct{}, available bool, err error) {
	probe := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree")
	if output, probeErr := probe.Output(); probeErr != nil || strings.TrimSpace(string(output)) != "true" {
		if probeErr != nil && !isUnavailableOrNotRepository(probeErr) {
			return nil, false, fmt.Errorf("inspect Git worktree: %w", probeErr)
		}
		return map[string]struct{}{}, false, nil
	}

	command := exec.Command("git", "-C", root, "ls-files", "--cached", "-z")
	output, err := command.Output()
	if err != nil {
		return nil, true, fmt.Errorf("list tracked files: %w", err)
	}

	tracked = make(map[string]struct{})
	for _, item := range bytes.Split(output, []byte{0}) {
		if len(item) == 0 {
			continue
		}
		tracked[strings.ReplaceAll(string(item), "\\", "/")] = struct{}{}
	}
	return tracked, true, nil
}

func isUnavailableOrNotRepository(err error) bool {
	var exitError *exec.ExitError
	return errors.Is(err, exec.ErrNotFound) || errors.As(err, &exitError)
}

func isEnvironmentFile(filePath string) bool {
	base := strings.ToLower(path.Base(filePath))
	if base == ".env" {
		return true
	}
	if !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, safeSuffix := range []string{".example", ".sample", ".template"} {
		if strings.HasSuffix(base, safeSuffix) {
			return false
		}
	}
	return true
}

func isSecretFile(filePath string) bool {
	base := strings.ToLower(path.Base(filePath))
	secretNames := map[string]struct{}{
		".npmrc": {}, ".pypirc": {}, "credentials.json": {}, "id_dsa": {}, "id_ecdsa": {},
		"id_ed25519": {}, "id_rsa": {}, "secrets.json": {}, "secrets.yaml": {}, "secrets.yml": {},
		"service-account.json": {}, "service_account.json": {},
	}
	if _, ok := secretNames[base]; ok {
		return true
	}
	switch path.Ext(base) {
	case ".key", ".p12", ".pem", ".pfx":
		return true
	default:
		return false
	}
}

func isBuildOutput(filePath string) bool {
	for _, segment := range strings.Split(strings.ToLower(filePath), "/")[:len(strings.Split(filePath, "/"))-1] {
		switch segment {
		case "bin", "build", "coverage", "dist", "out", "target":
			return true
		}
	}
	return false
}
