package risk

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ramiabukhader/repo-guardian/internal/scanner"
)

func TestDetectFindsRiskKindsWithoutContent(t *testing.T) {
	t.Parallel()
	scan := scanner.Result{Files: []scanner.File{
		{Path: ".env.production", Size: 100},
		{Path: "certs/server.pem", Size: 200},
		{Path: "dist/tool.exe", Size: 300},
		{Path: "assets/archive.zip", Size: 1024},
	}}
	tracked := map[string]struct{}{
		".env.production": {},
		"dist/tool.exe":   {},
	}

	got := Detect(scan, tracked, Options{LargeFileThreshold: 1024})
	want := []Finding{
		{Kind: KindEnvironmentFile, Path: ".env.production", Tracked: true},
		{Kind: KindLargeFile, Path: "assets/archive.zip", Size: 1024},
		{Kind: KindSecretFile, Path: "certs/server.pem"},
		{Kind: KindBuildOutput, Path: "dist/tool.exe", Tracked: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %#v, want %#v", got, want)
	}
}

func TestDetectExcludesEnvironmentExamplesAndUntrackedBuilds(t *testing.T) {
	t.Parallel()
	scan := scanner.Result{Files: []scanner.File{
		{Path: ".env.example", Size: 1},
		{Path: ".env.sample", Size: 1},
		{Path: ".env.template", Size: 1},
		{Path: "build/local.bin", Size: 1},
	}}
	if got := Detect(scan, nil, Options{LargeFileThreshold: 100}); len(got) != 0 {
		t.Fatalf("Detect() = %#v, want no findings", got)
	}
}

func TestDiscoverTrackedInGitRepository(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dist", "tool.bin"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "--", "dist/tool.bin")

	tracked, available, err := DiscoverTracked(root)
	if err != nil {
		t.Fatalf("DiscoverTracked() error = %v", err)
	}
	if !available {
		t.Fatal("DiscoverTracked() available = false, want true")
	}
	if _, ok := tracked["dist/tool.bin"]; !ok {
		t.Fatalf("tracked = %#v, want dist/tool.bin", tracked)
	}
}

func TestDiscoverTrackedOutsideGitRepository(t *testing.T) {
	t.Parallel()
	tracked, available, err := DiscoverTracked(t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverTracked() error = %v", err)
	}
	if available || len(tracked) != 0 {
		t.Fatalf("DiscoverTracked() = %#v, %v, want empty and unavailable", tracked, available)
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	if output, err := exec.Command("git", commandArgs...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
