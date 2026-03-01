package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

var (
	Version   = "0.0.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const (
	defaultVersion   = "0.0.0"
	defaultCommit    = "unknown"
	defaultBuildDate = "unknown"
)

type Info struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
	Modified  bool
}

func Current() Info {
	var buildInfo *debug.BuildInfo
	if bi, ok := debug.ReadBuildInfo(); ok {
		buildInfo = bi
	}
	return currentFromBuildInfo(buildInfo)
}

func currentFromBuildInfo(buildInfo *debug.BuildInfo) Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: "unknown",
		Modified:  false,
	}
	if buildInfo != nil {
		info.GoVersion = buildInfo.GoVersion
		if info.Version == defaultVersion && buildInfo.Main.Version != "" && buildInfo.Main.Version != "(devel)" {
			info.Version = buildInfo.Main.Version
		}
		for _, setting := range buildInfo.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == defaultCommit && setting.Value != "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.BuildDate == defaultBuildDate && setting.Value != "" {
					info.BuildDate = setting.Value
				}
			case "vcs.modified":
				info.Modified = strings.EqualFold(strings.TrimSpace(setting.Value), "true")
			}
		}
	}
	return info
}

func (i Info) String() string {
	parts := []string{
		fmt.Sprintf("version=%s", i.Version),
	}
	if strings.TrimSpace(i.Commit) != "" && i.Commit != defaultCommit {
		parts = append(parts, fmt.Sprintf("commit=%s", shortCommit(i.Commit)))
	}
	if strings.TrimSpace(i.BuildDate) != "" && i.BuildDate != defaultBuildDate {
		parts = append(parts, fmt.Sprintf("build_date=%s", i.BuildDate))
	}
	if i.Modified {
		parts = append(parts, "dirty=true")
	}
	parts = append(parts, fmt.Sprintf("go=%s", i.GoVersion))
	return strings.Join(parts, " ")
}

func shortCommit(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12]
}
