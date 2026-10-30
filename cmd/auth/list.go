package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/naftalimurgor/auth/internal/vault"
	"golang.org/x/term"
)

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultPath, err := defaultVaultPath()
	if err != nil {
		return err
	}

	vaultPath := fs.String("vault", defaultPath, "path to encrypted vault")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: auth list [--vault PATH]")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("list requires an interactive terminal")
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

	if len(data.Accounts) == 0 {
		fmt.Println("No accounts stored.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ISSUER\tACCOUNT")
	fmt.Fprintln(w, "------\t-------")

	for _, account := range data.Accounts {
		issuer := account.Issuer
		if issuer == "" {
			issuer = "-"
		}
		fmt.Fprintf(w, "%s\t%s\n", issuer, account.Name)
	}

	return w.Flush()
}
