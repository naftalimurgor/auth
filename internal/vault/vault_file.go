package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxVaultSize = 1 << 20 // 1 MiB

// Create writes a new encrypted vault without overiting an existing file.

func Create(path string, blob []byte) error {
	if err := validateBlob(blob); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".auth-vault-*")
	if err != nil {
		return fmt.Errorf("create temporary fault %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("Set vault permissions: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync vault:%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close vault %w", err)
	}

	// On the same filesystem, linking fails if path already exists.
	// This avoids accidentally overwritting an existing vault.

	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("vault already exists %s", path)
		}
		return fmt.Errorf("install vault: %w", err)
	}

	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}

	return nil
}

// Save atomically replaces an existing vault with new encrypted bytes.
func Save(path string, blob []byte) error {
	if err := validateBlob(blob); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".auth-vault-*")
	if err != nil {
		return fmt.Errorf("create temporary %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("set vault permission: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync vault %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close vault %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("sync vault directory %w", err)
	}
	return nil
}

// Load reads an encrypted vault, rejecting symlinks and oversized files
func Load(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat vault: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("vault must be a regular file, not a symlink or special file")
	}
	if info.Size() > maxVaultSize {
		return nil, errors.New("vault file exceeds maximum size")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()

	blob, err := io.ReadAll(io.LimitReader(f, maxVaultSize+1))
	if err != nil {
		return nil, fmt.Errorf("read vault: %w", err)
	}
	if len(blob) > maxVaultSize {
		return nil, errors.New("vault file exceeds maximum size")
	}
	return blob, nil
}

func validateBlob(blob []byte) error {
	if len(blob) == 0 {
		return errors.New("vault data must not be empy")

	}

	if len(blob) > maxVaultSize {
		return errors.New("vault data exceeds maximum size")

	}
	return nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err

	}
	defer f.Close()

	return f.Sync()

}
