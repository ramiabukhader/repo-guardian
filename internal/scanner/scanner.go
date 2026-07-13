// Package scanner discovers and classifies files in a local project.
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Category describes the role a file appears to have in a repository.
type Category string

const (
	CategoryCI            Category = "ci"
	CategoryConfiguration Category = "configuration"
	CategoryDocumentation Category = "documentation"
	CategoryOther         Category = "other"
	CategorySource        Category = "source"
	CategoryTest          Category = "test"
)

var defaultIgnoredDirectories = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
}

var sourceExtensions = map[string]struct{}{
	".c": {}, ".cc": {}, ".cpp": {}, ".cs": {}, ".go": {}, ".h": {}, ".hpp": {},
	".java": {}, ".js": {}, ".kt": {}, ".php": {}, ".py": {}, ".rb": {}, ".rs": {},
	".sh": {}, ".swift": {}, ".ts": {}, ".tsx": {},
}

var configurationExtensions = map[string]struct{}{
	".cfg": {}, ".conf": {}, ".ini": {}, ".json": {}, ".mod": {}, ".sum": {},
	".toml": {}, ".xml": {}, ".yaml": {}, ".yml": {},
}

// File is metadata about one regular file. The scanner never reads its contents.
type File struct {
	Path     string
	Size     int64
	Category Category
}

// Result summarizes a completed scan.
type Result struct {
	Root            string
	Files           []File
	CountByCategory map[Category]int
	TotalSize       int64
}

// Scan recursively scans root while excluding dependency and VCS directories.
func Scan(root string) (Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("resolve scan root: %w", err)
	}

	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return Result{}, fmt.Errorf("inspect scan root: %w", err)
	}
	if !rootInfo.IsDir() {
		return Result{}, fmt.Errorf("scan root is not a directory: %s", absRoot)
	}

	result := Result{
		Root:            absRoot,
		CountByCategory: make(map[Category]int),
	}
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == absRoot {
			return nil
		}

		if entry.IsDir() {
			if _, ignored := defaultIgnoredDirectories[strings.ToLower(entry.Name())]; ignored {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		relativePath, err := filepath.Rel(absRoot, path)
		if err != nil {
			return fmt.Errorf("make path relative: %w", err)
		}
		relativePath = filepath.ToSlash(relativePath)
		category := Classify(relativePath)
		result.Files = append(result.Files, File{
			Path:     relativePath,
			Size:     info.Size(),
			Category: category,
		})
		result.CountByCategory[category]++
		result.TotalSize += info.Size()
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("scan project: %w", err)
	}

	sort.Slice(result.Files, func(i, j int) bool {
		return result.Files[i].Path < result.Files[j].Path
	})
	return result, nil
}

// Classify assigns a category using only a file's relative path.
func Classify(relativePath string) Category {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(relativePath), "\\", "/"))
	base := filepath.Base(normalized)
	extension := filepath.Ext(base)

	if strings.HasPrefix(normalized, ".github/workflows/") && (extension == ".yml" || extension == ".yaml") {
		return CategoryCI
	}
	if strings.HasSuffix(base, "_test.go") || strings.HasPrefix(normalized, "test/") || strings.HasPrefix(normalized, "tests/") || strings.Contains(normalized, "/test/") || strings.Contains(normalized, "/tests/") {
		return CategoryTest
	}
	if extension == ".md" || extension == ".rst" || extension == ".adoc" || strings.HasPrefix(base, "readme") || strings.HasPrefix(base, "license") {
		return CategoryDocumentation
	}
	if _, ok := sourceExtensions[extension]; ok {
		return CategorySource
	}
	if strings.HasPrefix(base, ".") {
		return CategoryConfiguration
	}
	if _, ok := configurationExtensions[extension]; ok {
		return CategoryConfiguration
	}
	return CategoryOther
}
