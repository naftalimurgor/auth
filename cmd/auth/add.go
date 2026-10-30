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

func runAdd(args []string) error {
	defaultPath, err := defaultVaultPath()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	vaultPath := fs.String("vault", defaultPath, "path to encrypted vault")
	issuer := fs.String("issuer", "", "account issuer, e.g. GitHub")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return errors.New("usage: auth add [--vault PATH] [--issuer ISSUER] ACCOUNT")
	}

	name := strings.TrimSpace(fs.Arg(0))
	issuerValue := strings.TrimSpace(*issuer)

	if name == "" {
		return errors.New("account name must not be empty")
	}
	if *vaultPath == "" {
		return errors.New("vault path must not be empty")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("add requires an interactive terminal")
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
		if strings.EqualFold(account.Name, name) {
			return fmt.Errorf("account %q already exists", name)
		}
	}

	secretBytes, err := readHidden("Account Base32 secret: ")
	if err != nil {
		return err
	}
	defer clear(secretBytes)

	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return errors.New("account secret must not be empty")
	}

	// Validate the secret before putting it in the vault.
	if _, err := totp.Generate(secret, time.Now(), 6); err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}

	data.Accounts = append(data.Accounts, vault.Account{
		Issuer: issuerValue,
		Name:   name,
		Secret: secret,
	})

	updatedBlob, err := vault.Encrypt(data, password)
	if err != nil {
		return fmt.Errorf("encrypt updated vault: %w", err)
	}

	if err := vault.Save(*vaultPath, updatedBlob); err != nil {
		return fmt.Errorf("save updated vault: %w", err)
	}

	fmt.Printf("Added account %q.\n", name)
	return nil
}

func readHidden(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read hidden input: %w", err)
	}

	return value, nil
}
