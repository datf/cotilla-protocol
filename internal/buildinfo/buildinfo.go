package buildinfo

import "fmt"

// Populated at build time via -ldflags "-X github.com/datf/cotilla-protocol/internal/buildinfo.Version=...".
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a human-readable build version summary.
func String() string {
	return fmt.Sprintf("%s (commit=%s built=%s)", Version, Commit, Date)
}
