package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

const usage = `usage:
  jimichi enroll -suite c25519 -node name=host:port,admin=host:port,info=host:port [-node ...]
      certify every listed relay under a CA that lives for this run only and
      print its anchor, or print nothing and exit 1
  jimichi keygen-ca -suite c25519
      print the anchor of a CA key that is thrown away at once
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "enroll":
		err = runEnroll(args[1:], stdout, stderr)
	case "keygen-ca":
		err = runKeygenCA(args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "jimichi: unknown command %q\n%s", args[0], usage)
		return 2
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		fmt.Fprintf(stderr, "jimichi %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func runKeygenCA(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen-ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteName := fs.String("suite", suite.Default.String(), "primitive suite: gost or c25519")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	chosen, err := suite.Parse(*suiteName)
	if err != nil {
		return err
	}
	p, err := suite.New(chosen)
	if err != nil {
		return err
	}
	ca, err := pki.NewCA(p)
	if err != nil {
		return err
	}
	anchor := ca.Anchor()
	ca.Close()
	fmt.Fprintln(stdout, anchor.String())
	return nil
}
