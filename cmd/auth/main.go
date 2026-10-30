package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: auth <init|add|list|code> [flags]")
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "add":
		return runAdd(args[1:])
	case "list":
		return runList(args[1:])
	case "code":
		return runCode(args[1:])
	default:
		return fmt.Errorf(
			"unknown command %q; usage: auth <init|add|list|code> [flags]",
			args[0],
		)
	}
}
