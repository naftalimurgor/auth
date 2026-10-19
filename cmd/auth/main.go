package main

import (
	"auth/internal/totp"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "code" {
		fmt.Fprintln(os.Stderr, "usage: auth code --secret BASE32 [--digits 6]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	secret := fs.String("secret", "", "Base32-encoded-TOTP secret")
	digits := fs.Int("digits", 6, "Number of digits (6-8)")
	at := fs.Int64("at", 0, "Unix timestamp for testing; omit for your current time")

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Missing --secret")
		os.Exit(2)
	}

	now := time.Now()

	if *at != 0 {
		now = time.Unix(*at, 0)
	}

	code, err := totp.Generate(*secret, now, *digits)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(code)
}
