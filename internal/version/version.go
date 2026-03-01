package version

import (
	"fmt"
	"runtime/debug"
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
			}
		}
	}
	return info
}

func (i Info) String() string {
	return fmt.Sprintf("version=%s commit=%s build_date=%s go=%s", i.Version, i.Commit, i.BuildDate, i.GoVersion)
}
