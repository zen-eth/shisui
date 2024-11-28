// Portions of this code are derived from code written by The go-ethereum Authors.
// See original source: https://github.com/optimism-java/shisui/blob/06751b3ec9fec0b4bbead878bbb7a502dc728692/internal/flags/categories.go
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

package flags

import "github.com/urfave/cli/v2"

const (
	LoggingCategory       = "LOGGING AND DEBUGGING"
	MetricsCategory       = "METRICS AND STATS"
	MiscCategory          = "MISC"
	TestingCategory       = "TESTING"
	PortalNetworkCategory = "PORTAL NETWORK"
)

func init() {
	cli.HelpFlag.(*cli.BoolFlag).Category = MiscCategory
	cli.VersionFlag.(*cli.BoolFlag).Category = MiscCategory
}
