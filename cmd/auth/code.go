package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/naftalimurgor/auth/internal/totp"
	"github.com/naftalimurgor/auth/internal/vault"
	"golang.org/x/term"
)

func runCode(args []string) error {
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultPath, err := defaultVaultPath()
	if err != nil {
		return err
	}

	vaultPath := fs.String("vault", defaultPath, "path to encrypted vault")
	secret := fs.String("secret", "", "Base32 test secret; avoid for real secrets")
	digits := fs.Int("digits", 6, "OTP length (6-8)")
	at := fs.Int64("at", -1, "Unix timestamp for testing")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 1 {
		return errors.New("usage: auth code [ACCOUNT] [--vault PATH] [--secret BASE32] [--digits 6] [--at UNIX_TIMESTAMP]")
	}

	// Preserve standalone mode for RFC testing.
	if *secret != "" {
		if fs.NArg() != 0 {
			return errors.New("do not combine ACCOUNT with --secret")
		}
		return generateStandaloneCode(*secret, *digits, *at)
	}

	// No explicit secret: use the encrypted vault.
	if fs.NArg() != 1 {
		return errors.New("usage: auth code ACCOUNT [--vault PATH]")
	}

	accountName := strings.TrimSpace(fs.Arg(0))
	if accountName == "" {
		return errors.New("account name must not be empty")
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("vault unlock requires an interactive terminal")
	}

	password, err := readHidden("Master password: ")
	if err != nil {
		return err
	}
	defer clear(password)

	blob, err := vault.Load(*vaultPath)
	if err != nil {
		return fmt.Errorf("load vault: %w", err)
	}

	data, err := vault.Decrypt(blob, password)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	for _, account := range data.Accounts {
		if strings.EqualFold(account.Name, accountName) {
			now := time.Now()
			if *at >= 0 {
				now = time.Unix(*at, 0)
			}

			code, err := totp.Generate(account.Secret, now, *digits)
			if err != nil {
				return fmt.Errorf("generate code: %w", err)
			}

			fmt.Println(code)
			return nil
		}
	}

	return fmt.Errorf("account %q not found", accountName)
}

func generateStandaloneCode(secret string, digits int, at int64) error {
	now := time.Now()
	if at >= 0 {
		now = time.Unix(at, 0)
	}

	code, err := totp.Generate(secret, now, digits)
	if err != nil {
		return err
	}

	fmt.Println(code)
	return nil
}
