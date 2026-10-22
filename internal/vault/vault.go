package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	formatVersion = byte(1)
	saltSize      = 16
	keySize       = 32
	nonceSize     = 12

	// These settings are intentionally configurable in one place

	argonTime    = 3
	argonMemory  = 64 * 1024 // kiB: 64 MiB
	argonThreads = 2
)

var (
	ErrInvalidVault           = errors.New("Invalid valut")
	ErrWrongPasswordOrCorrupt = errors.New("wrong password or corrupted vault")
)

type Account struct {
	Issuer string `json:"issuer"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type Data struct {
	Accounts []Account `json:"accounts"`
}

// Encrypt serializes and encrypts vault dta using a master password.
// The returned bytes are safe to store as a vault file.
func Encrypt(data Data, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("masters password must not be empty")
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode vault data: %w", err)

	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate Salt: %w", err)
	}

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keySize)
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create authenticated cipher %w", err)

	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Layout: version | salt | nonce | ciphertext + authentication tag.
	header := make([]byte, 1+saltSize+nonceSize)
	header[0] = formatVersion
	copy(header[1:1+saltSize], salt)
	copy(header[1+saltSize:], nonce)

	// Authenticate the header as associated data
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)
	return append(header, ciphertext...), nil
}

// Decrypt authenticate and decrypts a vault file.
func Decrypt(blob, password []byte) (Data, error) {
	var data Data

	if len(password) == 0 {
		return data, errors.New("master password must not be empty")
	}

	headerSize := 1 + saltSize + nonceSize

	if len(blob) < headerSize+16 {
		return data, ErrInvalidVault
	}
	if blob[0] != formatVersion {
		return data, ErrInvalidVault
	}

	salt := blob[1 : 1+saltSize]
	nonce := blob[1+saltSize : headerSize]
	header := blob[:headerSize]
	ciphertext := blob[headerSize:]

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keySize)
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return data, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return data, fmt.Errorf("create authenticated cipher: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return data, ErrWrongPasswordOrCorrupt
	}
	defer clear(plaintext)

	if err := json.Unmarshal(plaintext, &data); err != nil {
		return Data{}, ErrWrongPasswordOrCorrupt
	}

	return data, nil
}

// EncodeLength is not part of the file format; it is a small helper
// reserved for future format extensions.
func EncodeLength(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// ReadAll is a convenience helper for bounded callers that already have
// an io.Reader. File-size limits should be enforced by the caller.
func ReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
