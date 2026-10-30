# auth

A minimalist, encrypted terminal-based TOTP authenticator written in Go.

## Features

- TOTP generation (RFC 6238)
- Encrypted local vault
- AES-256-GCM authenticated encryption
- Argon2id key derivation
- Hidden password and secret input
- Multiple account support

## Requirements

- Go 1.27+
- Linux, macOS or another supported Go platform

## Build

Clone the repository:

```bash
git clone https://github.com/naftalimurgor/auth.git
cd auth
```

Build:

```bash
go build -o auth ./cmd/auth
```

Run:

```bash
./auth
```

## Usage

Initialize an encrypted vault:

```bash
./auth init
```

Add an account:

```bash
./auth add --issuer GitHub github
```

List stored accounts:

```bash
./auth list
```

Generate a TOTP code:

```bash
./auth code github
```

Use a custom vault location with `--vault`:

```bash
./auth init --vault /path/to/vault.enc
```

## Testing

Run the test suite:

```bash
go test -v -count=1 ./...
```

Run static analysis:

```bash
go vet ./...
```

## Security

Account secrets are stored in an encrypted local vault.

The vault uses Argon2id for key derivation and AES-256-GCM for authenticated encryption.

Your master password is not stored by the application. Keep it safe; it cannot be recovered if lost.

## License: `MIT`

```
MIT License

Copyright (c) 2026 Naftali Murgor

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
