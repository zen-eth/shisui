// Portions of this code are derived from code written by The go-ethereum Authors.
// See original source: https://github.com/optimism-java/shisui/blob/06751b3ec9fec0b4bbead878bbb7a502dc728692/internal/version/vcs.go
//
// --- Original License Notice ---
//
// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package version

import (
	"runtime"
	"runtime/debug"
	"time"
)

// In go 1.18 and beyond, the go tool embeds VCS information into the build.

const (
	govcsTimeLayout = "2006-01-02T15:04:05Z"
	ourTimeLayout   = "20060102"
)

// These variables are set at build-time by the linker when the build is
// done by build/ci.go.
var gitCommit, gitDate string

// VCSInfo represents the git repository state.
type VCSInfo struct {
	Commit string // head commit hash
	Date   string // commit time in YYYYMMDD format
	Dirty  bool
}

// VCS returns version control information of the current executable.
func VCS() (VCSInfo, bool) {
	if gitCommit != "" {
		// Use information set by the build script if present.
		return VCSInfo{Commit: gitCommit, Date: gitDate}, true
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		if buildInfo.Main.Path == ourPath {
			return buildInfoVCS(buildInfo)
		}
	}
	return VCSInfo{}, false
}

// "trin/v0.1.1-b61fdc5c/linux-x86_64/rustc1.81.0"
// "Shisui/linux-amd64/go1.23.4/937d0954/2024-12-26"
func ClientInfo() string {
	info, _ := VCS()
	name := "shisui"
	// TODO replease with tag when a release is created
	name += "/latest-" + info.Commit
	name += "/" + runtime.GOOS + "-" + runtime.GOARCH
	name += "/" + runtime.Version()
	return name
}

// buildInfoVCS returns VCS information of the build.
func buildInfoVCS(info *debug.BuildInfo) (s VCSInfo, ok bool) {
	for _, v := range info.Settings {
		switch v.Key {
		case "vcs.revision":
			s.Commit = v.Value
		case "vcs.modified":
			if v.Value == "true" {
				s.Dirty = true
			}
		case "vcs.time":
			t, err := time.Parse(govcsTimeLayout, v.Value)
			if err == nil {
				s.Date = t.Format(ourTimeLayout)
			}
		}
	}
	if s.Commit != "" && s.Date != "" {
		ok = true
	}
	return
}
