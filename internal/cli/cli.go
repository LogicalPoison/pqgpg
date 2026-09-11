package cli

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/pqgpg/pqgpg/internal/armor"
	"github.com/pqgpg/pqgpg/internal/crypto"
	"github.com/pqgpg/pqgpg/internal/keyring"
	"golang.org/x/term"
)

var Version = "0.0.0-dev"

func Run(args []string) int {
	if len(args) < 1 {
		printHelp()
		return 1
	}
	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("pqgpg", "v"+Version)
		return 0
	case "help", "--help", "-h":
		printHelp()
		return 0
	}

	kr, err := keyring.Open("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "keyring: %v\n", err)
		return 1
	}

	switch cmd {
	case "keygen":
		return cmdKeygen(kr, rest)
	case "list", "list-keys":
		return cmdList(kr, rest)
	case "export":
		return cmdExport(kr, rest)
	case "import":
		return cmdImport(kr, rest)
	case "encrypt":
		return cmdEncrypt(kr, rest)
	case "decrypt":
		return cmdDecrypt(kr, rest)
	case "sign":
		return cmdSign(kr, rest)
	case "verify":
		return cmdVerify(kr, rest)
	case "delete", "del":
		return cmdDelete(kr, rest)
	case "fingerprint", "fp":
		return cmdFingerprint(kr, rest)
	case "revoke":
		return cmdRevoke(kr, rest)
	case "encrypt-dir", "encrypt_dir":
		return cmdEncryptDir(kr, rest)
	case "decrypt-dir", "decrypt_dir":
		return cmdDecryptDir(kr, rest)
	case "bench", "benchmark":
		return cmdBench(rest)
	case "algorithms", "algs":
		return cmdAlgorithms(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printHelp()
		return 1
	}
}

func printHelp() {
	fmt.Print(`pqgpg - Post-Quantum Privacy Guard

Usage: pqgpg <command> [options]

Commands:
  keygen        Generate a new keypair
  list          List keys
  export        Export public key (armored)
  import        Import public key
  encrypt       Encrypt a file
  decrypt       Decrypt a file
  sign          Detached sign a file
  verify        Verify a detached signature
  delete        Delete a key
  fingerprint   Show fingerprint(s)
  version       Show version
  help          Show this help

Examples:
  pqgpg keygen --name "Alice" --email alice@example.com
  pqgpg list
  pqgpg export --id alice@example.com > alice.pub
  pqgpg import alice.pub
  pqgpg encrypt --recipient alice@example.com --input secret.txt --output secret.pqg
  pqgpg decrypt --input secret.pqg --output secret.txt
  pqgpg sign --input doc.pdf --output doc.sig
  pqgpg verify --input doc.pdf --signature doc.sig

Environment:
  PQGPG_HOME   Keyring directory (default ~/.pqgpg)
`)
}

func flag(args []string, name string) (string, bool) {
	long := "--" + name
	short := "-" + name
	for i := 0; i < len(args); i++ {
		if (args[i] == long || args[i] == short || args[i] == name) && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func has(args []string, name string) bool {
	long := "--" + name
	short := "-" + name
	for _, a := range args {
		if a == long || a == short || a == name {
			return true
		}
	}
	return false
}

func readPass(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytePw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		// fallback for non-tty
		var s string
		fmt.Scanln(&s)
		return s, nil
	}
	return string(bytePw), nil
}

func resolve(kr *keyring.Keyring, q string) *crypto.KeyPair {
	// try as hex keyid
	if len(q) == 16 {
		var id crypto.KeyID
		fmt.Sscanf(strings.ToUpper(q), "%16X", &id)
		if kp := kr.FindPublic(id); kp != nil {
			return kp
		}
	}
	return kr.FindPublicByQuery(q)
}

func cmdKeygen(kr *keyring.Keyring, args []string) int {
	name, _ := flag(args, "name")
	email, _ := flag(args, "email")
	comment, _ := flag(args, "comment")
	if name == "" {
		fmt.Fprintln(os.Stderr, "--name is required")
		return 1
	}
	expDays := 0
	if s, ok := flag(args, "expires"); ok {
		fmt.Sscanf(s, "%d", &expDays)
	}

	pass, _ := flag(args, "passphrase")
	if pass == "" {
		var err error
		pass, err = readPass("Passphrase: ")
		if err != nil || pass == "" {
			fmt.Fprintln(os.Stderr, "passphrase required")
			return 1
		}
		pass2, _ := readPass("Confirm passphrase: ")
		if pass != pass2 {
			fmt.Fprintln(os.Stderr, "passphrases do not match")
			return 1
		}
	}

	hybrid := has(args, "hybrid")
	fmt.Println("Generating Dilithium3 + Kyber768 keypair...")
	if hybrid {
		fmt.Println("  (hybrid: + Ed25519 + X25519)")
	}
	kp, err := crypto.GenerateKeyPair(crypto.KeygenOpts{
		UID:         crypto.UserID{Name: name, Email: email, Comment: comment},
		ExpiresDays: expDays,
		Hybrid:      hybrid,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		return 1
	}
	if err := kr.Add(kp, pass); err != nil {
		fmt.Fprintf(os.Stderr, "store failed: %v\n", err)
		return 1
	}
	fmt.Printf("Key generated.\n")
	fmt.Printf("  User ID     : %s\n", kp.Meta.UID.String())
	fmt.Printf("  Key ID      : %s\n", kp.Meta.ID.String())
	fmt.Printf("  Fingerprint : %s\n", kp.Meta.Fingerprint.String())
	if kp.Meta.Expires > 0 {
		fmt.Printf("  Expires     : %s\n", keyring.FormatTime(kp.Meta.Expires))
	}
	return 0
}

func cmdList(kr *keyring.Keyring, _ []string) int {
	list := kr.ListPublic()
	if len(list) == 0 {
		fmt.Println("No keys.")
		return 0
	}
	for _, kp := range list {
		fmt.Printf("pub  ML-DSA-65/ML-KEM-768  %s\n", kp.Meta.ID.String())
		fmt.Printf("     %s\n", kp.Meta.UID.String())
		fmt.Printf("     Fingerprint: %s\n", kp.Meta.Fingerprint.String())
		fmt.Printf("     Created: %s\n", keyring.FormatTime(kp.Meta.Created))
		if kp.Meta.Expires > 0 {
			fmt.Printf("     Expires: %s\n", keyring.FormatTime(kp.Meta.Expires))
		}
		if kp.Meta.Revoked {
			fmt.Printf("     REVOKED: %s\n", kp.Meta.Reason)
		}
		fmt.Println()
	}
	return 0
}

func cmdExport(kr *keyring.Keyring, args []string) int {
	q, _ := flag(args, "id")
	if q == "" {
		q, _ = flag(args, "recipient")
	}
	if q == "" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		q = args[0]
	}
	if q == "" {
		fmt.Fprintln(os.Stderr, "specify --id")
		return 1
	}
	kp := resolve(kr, q)
	if kp == nil {
		fmt.Fprintln(os.Stderr, "key not found")
		return 1
	}
	out, err := kr.ExportPublic(kp.Meta.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if outfile, ok := flag(args, "output"); ok {
		if err := os.WriteFile(outfile, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
		fmt.Println("Exported to", outfile)
	} else {
		fmt.Print(out)
	}
	return 0
}

func cmdImport(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		infile = args[0]
	}
	if infile == "" {
		fmt.Fprintln(os.Stderr, "specify input file")
		return 1
	}
	data, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return 1
	}
	raw, err := armor.Decode(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "armor: %v\n", err)
		return 1
	}
	kp, err := keyring.DeserializePublic(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		return 1
	}
	if err := kr.ImportPublic(kp); err != nil {
		fmt.Fprintf(os.Stderr, "import: %v\n", err)
		return 1
	}
	fmt.Printf("Imported %s (%s)\n", kp.Meta.UID.String(), kp.Meta.ID.String())
	return 0
}

func cmdEncrypt(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" {
		infile, _ = flag(args, "i")
	}
	outfile, _ := flag(args, "output")
	if outfile == "" {
		outfile, _ = flag(args, "o")
	}
	symmetric := has(args, "symmetric") || has(args, "c")

	// collect recipients
	var recipients []string
	for i := 0; i < len(args); i++ {
		if (args[i] == "--recipient" || args[i] == "-r" || args[i] == "recipient") && i+1 < len(args) {
			recipients = append(recipients, args[i+1])
			i++
		}
	}

	if infile == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg encrypt --recipient <id> --input <file> [--output <file>]")
		return 1
	}
	if !symmetric && len(recipients) == 0 {
		fmt.Fprintln(os.Stderr, "specify --recipient or --symmetric")
		return 1
	}
	if outfile == "" {
		if symmetric {
			outfile = infile + ".sym.pqg"
		} else {
			outfile = infile + ".pqg"
		}
	}

	plaintext, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", infile, err)
		return 1
	}

	var msg *crypto.EncryptedMessage
	if symmetric {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
			pass2, _ := readPass("Confirm: ")
			if pass != pass2 {
				fmt.Fprintln(os.Stderr, "passphrases do not match")
				return 1
			}
		}
		msg, err = crypto.EncryptSymmetricPassphrase(plaintext, pass, infile)
	} else {
		var recs []*crypto.KeyPair
		for _, r := range recipients {
			kp := resolve(kr, r)
			if kp == nil {
				fmt.Fprintf(os.Stderr, "recipient not found: %s\n", r)
				return 1
			}
			recs = append(recs, kp)
		}
		msg, err = crypto.EncryptTo(recs, plaintext, infile, has(args, "hybrid"))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt failed: %v\n", err)
		return 1
	}

	blob := serializeEncrypted(msg)
	armored := armor.Encode(blob, "ENCRYPTED MESSAGE")
	if err := os.WriteFile(outfile, []byte(armored), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outfile, err)
		return 1
	}
	fmt.Printf("Encrypted to %s\n", outfile)
	return 0
}

func serializeEncrypted(msg *crypto.EncryptedMessage) []byte {
	buf := []byte{'P', 'Q', 'E', 'N', 3} // v3 adds hybrid flag
	if msg.Symmetric {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	if msg.Hybrid {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	if msg.Symmetric {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(msg.Salt)))
		buf = append(buf, msg.Salt...)
	} else {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(msg.Recipients)))
		for _, r := range msg.Recipients {
			buf = append(buf, r.ID[:]...)
			buf = binary.LittleEndian.AppendUint32(buf, uint32(len(r.CT)))
			buf = append(buf, r.CT...)
		}
	}
	buf = append(buf, msg.Nonce...)
	buf = append(buf, msg.Tag...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(msg.Ciphertext)))
	buf = append(buf, msg.Ciphertext...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(msg.Filename)))
	buf = append(buf, msg.Filename...)
	return buf
}

func cmdDecrypt(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" {
		infile, _ = flag(args, "i")
	}
	outfile, _ := flag(args, "output")
	if outfile == "" {
		outfile, _ = flag(args, "o")
	}
	if infile == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg decrypt --input <file> [--output <file>]")
		return 1
	}

	data, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return 1
	}
	raw, err := armor.Decode(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "armor: %v\n", err)
		return 1
	}
	msg, err := parseEncrypted(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		return 1
	}

	var pt []byte
	if msg.Symmetric {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
		}
		pt, err = crypto.DecryptSymmetricPassphrase(msg, pass)
	} else {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
		}
		for _, r := range msg.Recipients {
			kp, err2 := kr.FindPrivate(r.ID, pass)
			if err2 != nil {
				continue
			}
			pt, err = crypto.DecryptWith(kp, msg)
			if err == nil {
				break
			}
		}
		if pt == nil {
			fmt.Fprintln(os.Stderr, "decryption failed (wrong passphrase or no matching key)")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		return 1
	}

	if outfile == "" {
		if msg.Filename != "" {
			outfile = msg.Filename + ".decrypted"
		} else {
			outfile = "decrypted.out"
		}
	}
	if err := os.WriteFile(outfile, pt, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	fmt.Printf("Decrypted to %s\n", outfile)
	return 0
}

func parseEncrypted(data []byte) (*crypto.EncryptedMessage, error) {
	if len(data) < 6 || string(data[:4]) != "PQEN" {
		return nil, fmt.Errorf("not a pqgpg message")
	}
	version := data[4]
	off := 5
	msg := &crypto.EncryptedMessage{}

	readU32 := func() (uint32, error) {
		if off+4 > len(data) {
			return 0, fmt.Errorf("truncated")
		}
		v := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		return v, nil
	}

	if version >= 2 {
		if off >= len(data) {
			return nil, fmt.Errorf("truncate")
		}
		msg.Symmetric = data[off] != 0
		off++
		if version >= 3 {
			if off >= len(data) {
				return nil, fmt.Errorf("truncate")
			}
			msg.Hybrid = data[off] != 0
			off++
		}
		if msg.Symmetric {
			n, err := readU32()
			if err != nil {
				return nil, err
			}
			if off+int(n) > len(data) {
				return nil, fmt.Errorf("truncated salt")
			}
			msg.Salt = data[off : off+int(n)]
			off += int(n)
		} else {
			nrec, err := readU32()
			if err != nil || nrec == 0 || nrec > 64 {
				return nil, fmt.Errorf("bad recipient count")
			}
			for i := uint32(0); i < nrec; i++ {
				if off+8 > len(data) {
					return nil, fmt.Errorf("truncated id")
				}
				var id crypto.KeyID
				copy(id[:], data[off:off+8])
				off += 8
				n, err := readU32()
				if err != nil || off+int(n) > len(data) {
					return nil, fmt.Errorf("truncate ct")
				}
				ct := data[off : off+int(n)]
				off += int(n)
				msg.Recipients = append(msg.Recipients, crypto.RecipientBlob{ID: id, CT: ct})
			}
		}
	} else {
		return nil, fmt.Errorf("unsupported version")
	}

	if off+12+16 > len(data) {
		return nil, fmt.Errorf("truncate nonce/tag")
	}
	msg.Nonce = data[off : off+12]
	off += 12
	msg.Tag = data[off : off+16]
	off += 16
	n, err := readU32()
	if err != nil || off+int(n) > len(data) {
		return nil, fmt.Errorf("truncate ciphertext")
	}
	msg.Ciphertext = data[off : off+int(n)]
	off += int(n)
	if off+4 <= len(data) {
		n, err = readU32()
		if err == nil && off+int(n) <= len(data) {
			msg.Filename = string(data[off : off+int(n)])
		}
	}
	return msg, nil
}

func cmdSign(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" {
		infile, _ = flag(args, "i")
	}
	outfile, _ := flag(args, "output")
	if outfile == "" {
		outfile, _ = flag(args, "o")
	}
	signer, _ := flag(args, "local-user")
	if signer == "" {
		signer, _ = flag(args, "signer")
	}
	if infile == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg sign --input <file> [--output <file>] [--local-user <id>]")
		return 1
	}
	if outfile == "" {
		outfile = infile + ".sig"
	}

	data, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return 1
	}

	// pick signer
	var id crypto.KeyID
	if signer != "" {
		kp := resolve(kr, signer)
		if kp == nil {
			fmt.Fprintln(os.Stderr, "signer not found")
			return 1
		}
		id = kp.Meta.ID
	} else {
		// first private key
		for k := range kr.Private {
			id = k
			break
		}
		if id == (crypto.KeyID{}) {
			fmt.Fprintln(os.Stderr, "no secret keys")
			return 1
		}
	}

	pass, _ := flag(args, "passphrase")
	if pass == "" {
		pass, _ = readPass("Passphrase: ")
	}
	kp, err := kr.FindPrivate(id, pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unlock: %v\n", err)
		return 1
	}
	sig, err := crypto.Sign(kp.SigSec, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		return 1
	}

	// blob: magic | id | sig
	blob := []byte{'P', 'Q', 'S', 'G', 1}
	blob = append(blob, id[:]...)
	blob = binary.LittleEndian.AppendUint32(blob, uint32(len(sig)))
	blob = append(blob, sig...)
	armored := armor.Encode(blob, "SIGNATURE")
	if err := os.WriteFile(outfile, []byte(armored), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	fmt.Printf("Signature written to %s\n", outfile)
	return 0
}

func cmdVerify(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" {
		infile, _ = flag(args, "i")
	}
	sigfile, _ := flag(args, "signature")
	if sigfile == "" {
		sigfile, _ = flag(args, "s")
	}
	if infile == "" || sigfile == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg verify --input <file> --signature <sigfile>")
		return 1
	}
	data, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read data: %v\n", err)
		return 1
	}
	sigdata, err := os.ReadFile(sigfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read sig: %v\n", err)
		return 1
	}
	raw, err := armor.Decode(string(sigdata))
	if err != nil || len(raw) < 5+8+4 || string(raw[:4]) != "PQSG" {
		fmt.Fprintln(os.Stderr, "invalid signature")
		return 1
	}
	var id crypto.KeyID
	copy(id[:], raw[5:13])
	sigLen := binary.LittleEndian.Uint32(raw[13:17])
	if 17+int(sigLen) > len(raw) {
		fmt.Fprintln(os.Stderr, "corrupt signature")
		return 1
	}
	sig := raw[17 : 17+sigLen]

	kp := kr.FindPublic(id)
	if kp == nil {
		fmt.Fprintln(os.Stderr, "signer public key not found")
		return 1
	}
	if crypto.Verify(kp.SigPub, data, sig) {
		fmt.Printf("Good signature from %s\n", kp.Meta.UID.String())
		fmt.Printf("  Key ID: %s\n", id.String())
		return 0
	}
	fmt.Println("BAD signature")
	return 1
}

func cmdDelete(kr *keyring.Keyring, args []string) int {
	q, _ := flag(args, "id")
	if q == "" && len(args) > 0 {
		q = args[0]
	}
	if q == "" {
		fmt.Fprintln(os.Stderr, "specify --id")
		return 1
	}
	kp := resolve(kr, q)
	if kp == nil {
		fmt.Fprintln(os.Stderr, "key not found")
		return 1
	}
	if err := kr.Delete(kp.Meta.ID); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Println("Key deleted.")
	return 0
}

func cmdFingerprint(kr *keyring.Keyring, args []string) int {
	q, _ := flag(args, "id")
	if q == "" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		q = args[0]
	}
	if q == "" {
		for _, kp := range kr.ListPublic() {
			fmt.Printf("%s  %s\n", kp.Meta.Fingerprint.String(), kp.Meta.UID.String())
		}
		return 0
	}
	kp := resolve(kr, q)
	if kp == nil {
		fmt.Fprintln(os.Stderr, "key not found")
		return 1
	}
	fmt.Println(kp.Meta.Fingerprint.String())
	return 0
}

func cmdRevoke(kr *keyring.Keyring, args []string) int {
	q, _ := flag(args, "id")
	if q == "" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		q = args[0]
	}
	if q == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg revoke --id <key>")
		return 1
	}
	reason, _ := flag(args, "reason")
	if reason == "" {
		reason = "No reason specified"
	}
	kp := resolve(kr, q)
	if kp == nil {
		fmt.Fprintln(os.Stderr, "key not found")
		return 1
	}
	if err := kr.Revoke(kp.Meta.ID, reason); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Printf("Key %s revoked: %s\n", kp.Meta.ID.String(), reason)
	if has(args, "delete") || has(args, "remove") {
		_ = kr.Delete(kp.Meta.ID)
		fmt.Println("Key removed from keyring.")
	}
	return 0
}

func cmdEncryptDir(kr *keyring.Keyring, args []string) int {
	indir, _ := flag(args, "input")
	if indir == "" {
		indir, _ = flag(args, "i")
	}
	outfile, _ := flag(args, "output")
	if outfile == "" {
		outfile, _ = flag(args, "o")
	}
	symmetric := has(args, "symmetric") || has(args, "c")
	if indir == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg encrypt-dir --input <dir> [--recipient <id>|--symmetric] [--output <file>]")
		return 1
	}
	if outfile == "" {
		outfile = strings.TrimRight(indir, "/\\") + ".pqg"
	}
	archive, err := crypto.ArchiveDirectory(indir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "archive: %v\n", err)
		return 1
	}
	fmt.Printf("Archived %d bytes from %s\n", len(archive), indir)

	var msg *crypto.EncryptedMessage
	if symmetric {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
			pass2, _ := readPass("Confirm: ")
			if pass != pass2 {
				fmt.Fprintln(os.Stderr, "passphrases do not match")
				return 1
			}
		}
		msg, err = crypto.EncryptSymmetricPassphrase(archive, pass, indir)
	} else {
		var recipients []string
		for i := 0; i < len(args); i++ {
			if (args[i] == "--recipient" || args[i] == "-r") && i+1 < len(args) {
				recipients = append(recipients, args[i+1])
				i++
			}
		}
		if len(recipients) == 0 {
			fmt.Fprintln(os.Stderr, "specify --recipient or --symmetric")
			return 1
		}
		var recs []*crypto.KeyPair
		for _, r := range recipients {
			kp := resolve(kr, r)
			if kp == nil {
				fmt.Fprintf(os.Stderr, "recipient not found: %s\n", r)
				return 1
			}
			if kp.Meta.Revoked {
				fmt.Fprintf(os.Stderr, "warning: key %s is revoked\n", r)
			}
			recs = append(recs, kp)
		}
		msg, err = crypto.EncryptTo(recs, archive, indir, has(args, "hybrid"))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
		return 1
	}
	blob := serializeEncrypted(msg)
	armored := armor.Encode(blob, "ENCRYPTED DIRECTORY")
	if err := os.WriteFile(outfile, []byte(armored), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	fmt.Printf("Encrypted directory written to %s\n", outfile)
	return 0
}

func cmdDecryptDir(kr *keyring.Keyring, args []string) int {
	infile, _ := flag(args, "input")
	if infile == "" {
		infile, _ = flag(args, "i")
	}
	outdir, _ := flag(args, "output")
	if outdir == "" {
		outdir, _ = flag(args, "o")
	}
	if infile == "" {
		fmt.Fprintln(os.Stderr, "Usage: pqgpg decrypt-dir --input <file.pqg> [--output <dir>]")
		return 1
	}
	if outdir == "" {
		outdir = "decrypted_dir"
	}
	data, err := os.ReadFile(infile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return 1
	}
	raw, err := armor.Decode(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "armor: %v\n", err)
		return 1
	}
	msg, err := parseEncrypted(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		return 1
	}
	var pt []byte
	if msg.Symmetric {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
		}
		pt, err = crypto.DecryptSymmetricPassphrase(msg, pass)
	} else {
		pass, _ := flag(args, "passphrase")
		if pass == "" {
			pass, _ = readPass("Passphrase: ")
		}
		for _, r := range msg.Recipients {
			kp, err2 := kr.FindPrivate(r.ID, pass)
			if err2 != nil {
				continue
			}
			pt, err = crypto.DecryptWith(kp, msg)
			if err == nil {
				break
			}
		}
		if pt == nil {
			fmt.Fprintln(os.Stderr, "decryption failed")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		return 1
	}
	if err := crypto.ExtractArchive(pt, outdir); err != nil {
		fmt.Fprintf(os.Stderr, "extract: %v\n", err)
		return 1
	}
	fmt.Printf("Decrypted directory extracted to %s\n", outdir)
	return 0
}

func cmdBench(args []string) int {
	n := 20
	if s, ok := flag(args, "iterations"); ok {
		fmt.Sscanf(s, "%d", &n)
	}
	results := crypto.RunBenchmarks(n)
	if has(args, "json") {
		fmt.Println("[")
		for i, r := range results {
			comma := ","
			if i == len(results)-1 {
				comma = ""
			}
			fmt.Printf("  {\"alg\":%q,\"op\":%q,\"avg_ms\":%.4f,\"iterations\":%d}%s\n", r.Alg, r.Op, r.AvgMs, r.N, comma)
		}
		fmt.Println("]")
		return 0
	}
	fmt.Printf("%-12s %-8s %10s\n", "ALG", "OP", "AVG ms")
	for _, r := range results {
		fmt.Printf("%-12s %-8s %10.3f\n", r.Alg, r.Op, r.AvgMs)
	}
	return 0
}

func cmdAlgorithms(_ []string) int {
	fmt.Println("Signature algorithms:")
	fmt.Println("  Dilithium3  (≈ ML-DSA-65, default)")
	fmt.Println("KEM algorithms:")
	fmt.Println("  Kyber768    (≈ ML-KEM-768, default)")
	fmt.Println("Classical (hybrid mode):")
	fmt.Println("  Ed25519, X25519")
	fmt.Println("Symmetric: AES-256-GCM")
	return 0
}
