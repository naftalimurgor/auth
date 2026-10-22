package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	original := Data{
		Accounts: []Account{
			{
				Issuer: "GitHub",
				Name:   "test-user",
				Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			},
		},
	}
	password := []byte("test-only-master-password")

	blob, err := Encrypt(original, password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if bytes.Contains(blob, []byte(original.Accounts[0].Secret)) {
		t.Fatal("vault contains plaintext account secret")
	}

	got, err := Decrypt(blob, password)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(got.Accounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(got.Accounts))
	}
	if got.Accounts[0] != original.Accounts[0] {
		t.Fatalf("got account %#v, want %#v", got.Accounts[0], original.Accounts[0])
	}
}

func TestWrongPassword(t *testing.T) {
	blob, err := Encrypt(Data{}, []byte("correct"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(blob, []byte("incorrect"))
	if !errors.Is(err, ErrWrongPasswordOrCorrupt) {
		t.Fatalf("got error %v, want ErrWrongPasswordOrCorrupt", err)
	}
}

func TestTamperedVault(t *testing.T) {
	blob, err := Encrypt(Data{}, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}

	blob[len(blob)-1] ^= 0x01

	_, err = Decrypt(blob, []byte("password"))
	if !errors.Is(err, ErrWrongPasswordOrCorrupt) {
		t.Fatalf("got error %v, want ErrWrongPasswordOrCorrupt", err)
	}
}

func TestEmptyPassword(t *testing.T) {
	if _, err := Encrypt(Data{}, nil); err == nil {
		t.Fatal("Encrypt() accepted an empty password")
	}

	if _, err := Decrypt([]byte("anything"), nil); err == nil {
		t.Fatal("Decrypt() accepted an empty password")
	}
}

func TestInvalidVault(t *testing.T) {
	_, err := Decrypt([]byte("short"), []byte("password"))
	if !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("got error %v, want ErrInvalidVault", err)
	}
}
