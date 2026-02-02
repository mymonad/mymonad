package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cli := NewCLIWithDefaults()
	defer cli.Close()

	var err error

	switch os.Args[1] {
	case "status":
		err = cli.Status()
	case "peers":
		err = cli.Peers()
	case "bootstrap":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: mymonad-cli bootstrap <multiaddr>")
			os.Exit(1)
		}
		err = cli.Bootstrap(os.Args[2])
	case "identity":
		err = cli.Identity()
	case "handshake":
		err = cli.Handshake(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
