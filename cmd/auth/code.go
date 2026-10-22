package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/naftalimurgor/auth/internal/totp"
	"golang.org/x/term"
)

func runCode(args []string) error {
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	secret := fs.String("secret", "", "Base32 test secret (avoid for real secrets)")
	digits := fs.Int("digits", 6, "OTP length (6-8)")
	at := fs.Int64("at", -1, "Unix timestamp for testing")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return fmt.Errorf("usage: auth code [--secret BASE32] [--digits 6] [--at UNIX_TIMESTAMP]")
	}

	secretValue := *secret

	if secretValue == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("secret must be entered interactively")
		}

		fmt.Fprint(os.Stderr, "Base32 secret: ")
		secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)

		if err != nil {
			return fmt.Errorf("read secret: %w", err)
		}
		defer clear(secretBytes)

		secretValue = string(secretBytes)
	}

	now := time.Now()
	if *at >= 0 {
		now = time.Unix(*at, 0)
	}

	code, err := totp.Generate(secretValue, now, *digits)
	if err != nil {
		return err
	}

	fmt.Println(code)
	return nil
}
