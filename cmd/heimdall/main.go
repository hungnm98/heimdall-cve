// Command heimdall scans repositories for vulnerable dependencies and EOL runtimes.
package main

import (
	"os"

	"github.com/hungnm98/heimdall-cve/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
