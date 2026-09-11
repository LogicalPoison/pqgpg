package main

import (
	"os"

	"github.com/pqgpg/pqgpg/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
