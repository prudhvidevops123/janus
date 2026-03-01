package version

import (
	"runtime/debug"
	"testing"
)

func TestCurrentFromBuildInfoUsesModuleVersionFallback(t *testing.T) {
	originalVersion := Version
	originalCommit := Commit
	originalBuildDate := BuildDate
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
		BuildDate = originalBuildDate
	})

	Version = defaultVersion
	Commit = defaultCommit
	BuildDate = defaultBuildDate

	info := currentFromBuildInfo(&debug.BuildInfo{
		GoVersion: "go1.test",
		Main: debug.Module{
			Version: "v1.2.3",
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-03-01T00:00:00Z"},
		},
	})

	if info.Version != "v1.2.3" {
		t.Fatalf("expected module version fallback, got %q", info.Version)
	}
	if info.Commit != "abc123" {
		t.Fatalf("expected vcs revision fallback, got %q", info.Commit)
	}
	if info.BuildDate != "2026-03-01T00:00:00Z" {
		t.Fatalf("expected vcs time fallback, got %q", info.BuildDate)
	}
	if info.GoVersion != "go1.test" {
		t.Fatalf("expected go version from build info, got %q", info.GoVersion)
	}
}

func TestCurrentFromBuildInfoKeepsInjectedValues(t *testing.T) {
	originalVersion := Version
	originalCommit := Commit
	originalBuildDate := BuildDate
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
		BuildDate = originalBuildDate
	})

	Version = "v9.9.9"
	Commit = "release-commit"
	BuildDate = "release-date"

	info := currentFromBuildInfo(&debug.BuildInfo{
		GoVersion: "go1.test",
		Main: debug.Module{
			Version: "v1.2.3",
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-03-01T00:00:00Z"},
		},
	})

	if info.Version != "v9.9.9" {
		t.Fatalf("expected injected version to win, got %q", info.Version)
	}
	if info.Commit != "release-commit" {
		t.Fatalf("expected injected commit to win, got %q", info.Commit)
	}
	if info.BuildDate != "release-date" {
		t.Fatalf("expected injected build date to win, got %q", info.BuildDate)
	}
}
