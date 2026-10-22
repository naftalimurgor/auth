package main

import (
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/naftalimurgor/auth/internal/vault"
	"golang.org/x/term"
)

func runInit(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)

	defaultPath, err := defaultVaultPath()
	if err != nil {
		return err
	}
	valuePath := flags.String("vault", defaultPath, "path to encrytped vault")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("vault path must not be empt")
	}

	if *valuePath == "" {
		return errors.New("usage: auth init [--vault PATH]")
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("init requires an interaactive terminal")
	}

	fmt.Println("Initialize encrypted authenticator vault")
	fmt.Printf("Vault path: %s\n", *valuePath)
	fmt.Print("master password: ")

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}
	defer clear(password)

	if len(password) == 0 {
		return errors.New("Master password must not be empty")
	}

	fmt.Print("confirm master password: ")

	fmt.Println()
	confirmation, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		clear(confirmation)
		return fmt.Errorf("read password confirmation %w", err)
	}
	defer clear(confirmation)

	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		return errors.New("Password do not match")
	}

	data := vault.Data{
		Accounts: []vault.Account{},
	}
	blob, err := vault.Encrypt(data, password)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	dir := filepath.Dir(*valuePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	if err := vault.Create(*valuePath, blob); err != nil {
		return fmt.Errorf("create vault %w", err)
	}

	fmt.Println("Vault initialized successfully")
	fmt.Println("Keep your master password safe, it cannot be recovered by this application")
	return nil
}

func defaultVaultPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(configDir, "auth", "vault.enc"), nil
}
