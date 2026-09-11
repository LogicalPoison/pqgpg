# pqgpg-go – Post-Quantum Privacy Guard (Pure Go)

Reliable GPG-like tool using post-quantum cryptography via [Cloudflare CIRCL](https://github.com/cloudflare/circl).

| Role | Algorithm |
|------|-----------|
| Signatures | Dilithium3 (≈ ML-DSA-65) |
| KEM | Kyber768 (≈ ML-KEM-768) |
| Hybrid | Ed25519 + X25519 |
| Symmetric | AES-256-GCM |

**No CGO. No liboqs. Just `go build`.**

## Features

- Key generation (PQ + optional hybrid classical)
- Passphrase-protected private keys (PBKDF2 + AES-GCM)
- Hidden passphrase input
- Import / export (ASCII armor)
- File encrypt / decrypt (multi-recipient)
- **Hybrid encryption** (`--hybrid`)
- **Directory encrypt / decrypt**
- Symmetric passphrase encryption (`--symmetric`)
- Detached sign / verify
- **Key revocation**
- Key expiration
- **Benchmarks** and algorithm listing
- Cross-platform single binary

## Build

```bash
go mod tidy
go build -o pqgpg ./cmd/pqgpg
```

Windows:

```powershell
go mod tidy
go build -o pqgpg.exe ./cmd/pqgpg
```

## Usage

```bash
# Hybrid key
./pqgpg keygen --name "Alice" --email alice@example.com --hybrid

./pqgpg list

# Encrypt (pure PQ or hybrid)
./pqgpg encrypt --recipient alice@example.com --input secret.txt --output secret.pqg
./pqgpg encrypt -r alice@example.com -i secret.txt -o secret.pqg --hybrid

./pqgpg decrypt --input secret.pqg --output secret.txt

# Directory
./pqgpg encrypt-dir --input myfolder --recipient alice@example.com --output myfolder.pqg
./pqgpg decrypt-dir --input myfolder.pqg --output restored

# Sign / verify
./pqgpg sign --input doc.pdf --output doc.sig
./pqgpg verify --input doc.pdf --signature doc.sig

# Symmetric
./pqgpg encrypt --symmetric --input secret.txt --output secret.sym.pqg

# Revoke
./pqgpg revoke --id alice@example.com --reason "compromised"

# Benchmarks
./pqgpg bench
./pqgpg algorithms
```

## Keyring

Default: `~/.pqgpg/` (`PQGPG_HOME` overrides)

## License

MIT
