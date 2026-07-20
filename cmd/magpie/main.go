// Command magpie is a passive, read-only reconnaissance tool that maps and
// validates the /.well-known/ directory of a domain.
package main

import (
	"fmt"
	"os"

	"github.com/harborproject/magpie/cmd/magpie/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
