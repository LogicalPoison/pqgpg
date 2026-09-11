package crypto

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/pbkdf2"
)

const (
	AESKeySize      = 32
	NonceSize       = 12
	TagSize         = 16
	SaltSize        = 16
	PBKDF2Iters     = 600_000
	KeyIDSize       = 8
	FingerprintSize = 32

	AlgSigDefault = "Dilithium3" // ML-DSA-65 equivalent
	AlgKemDefault = "Kyber768"   // ML-KEM-768 equivalent
)

type KeyID [KeyIDSize]byte
type Fingerprint [FingerprintSize]byte

func (id KeyID) String() string       { return fmt.Sprintf("%X", id[:]) }
func (fp Fingerprint) String() string { return fmt.Sprintf("%X", fp[:]) }

type UserID struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Comment string `json:"comment"`
}

func (u UserID) String() string {
	s := u.Name
	if u.Email != "" {
		s += " <" + u.Email + ">"
	}
	if u.Comment != "" {
		s += " (" + u.Comment + ")"
	}
	return s
}

type KeyMeta struct {
	ID          KeyID       `json:"id"`
	Fingerprint Fingerprint `json:"fingerprint"`
	UID         UserID      `json:"uid"`
	Created     int64       `json:"created"`
	Expires     int64       `json:"expires"`
	Revoked     bool        `json:"revoked"`
	Reason      string      `json:"reason,omitempty"`
	Hybrid      bool        `json:"hybrid"`
	SigAlg      string      `json:"sig_alg"`
	KemAlg      string      `json:"kem_alg"`
}

type KeyPair struct {
	Meta      KeyMeta
	SigPub    []byte
	SigSec    []byte
	KemPub    []byte
	KemSec    []byte
	// Classical (hybrid)
	EdPub  []byte // 32
	EdSec  []byte // 64
	XPub   []byte // 32
	XSec   []byte // 32
	HasSecret bool
}

type KeygenOpts struct {
	UID         UserID
	ExpiresDays int
	Hybrid      bool
	HighSec     bool // reserved; Kyber768/Dilithium3 are the solid defaults in this CIRCL version
}

func GenerateKeyPair(opts KeygenOpts) (*KeyPair, error) {
	// Dilithium3 (≈ ML-DSA-65)
	sigPub, sigSec, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("dilithium keygen: %w", err)
	}
	var sigPubBuf [mode3.PublicKeySize]byte
	var sigSecBuf [mode3.PrivateKeySize]byte
	sigPub.Pack(&sigPubBuf)
	sigSec.Pack(&sigSecBuf)

	// Kyber768 (≈ ML-KEM-768)
	kemPub, kemSec, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kyber keygen: %w", err)
	}
	kemPubBytes, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemSecBytes, err := kemSec.MarshalBinary()
	if err != nil {
		return nil, err
	}

	kp := &KeyPair{
		SigPub:    append([]byte{}, sigPubBuf[:]...),
		SigSec:    append([]byte{}, sigSecBuf[:]...),
		KemPub:    kemPubBytes,
		KemSec:    kemSecBytes,
		HasSecret: true,
	}

	if opts.Hybrid {
		edPub, edSec, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		x, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		kp.EdPub = append([]byte{}, edPub...)
		kp.EdSec = append([]byte{}, edSec...)
		kp.XPub = append([]byte{}, x.PublicKey().Bytes()...)
		kp.XSec = append([]byte{}, x.Bytes()...)
	}

	fp := fingerprint(kp)
	var id KeyID
	copy(id[:], fp[len(fp)-KeyIDSize:])

	var expires int64
	if opts.ExpiresDays > 0 {
		expires = time.Now().Unix() + int64(opts.ExpiresDays)*86400
	}

	kp.Meta = KeyMeta{
		ID:          id,
		Fingerprint: fp,
		UID:         opts.UID,
		Created:     time.Now().Unix(),
		Expires:     expires,
		Hybrid:      opts.Hybrid,
		SigAlg:      AlgSigDefault,
		KemAlg:      AlgKemDefault,
	}
	return kp, nil
}

func fingerprint(kp *KeyPair) Fingerprint {
	h := sha256.New()
	h.Write(kp.SigPub)
	h.Write(kp.KemPub)
	h.Write(kp.EdPub)
	h.Write(kp.XPub)
	var fp Fingerprint
	copy(fp[:], h.Sum(nil))
	return fp
}

// ----- Symmetric -----

func EncryptSymmetric(plaintext, key []byte) (ct, nonce, tag []byte, err error) {
	if len(key) != AESKeySize {
		return nil, nil, nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	out := gcm.Seal(nil, nonce, plaintext, nil)
	return out[:len(out)-TagSize], nonce, out[len(out)-TagSize:], nil
}

func DecryptSymmetric(ct, key, nonce, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, append(append([]byte{}, ct...), tag...), nil)
}

// ----- KEM / Sign -----

func KemEncapsulate(kemPubBytes []byte) (ct, ss []byte, err error) {
	pk, err := kyber768.Scheme().UnmarshalBinaryPublicKey(kemPubBytes)
	if err != nil {
		return nil, nil, err
	}
	return kyber768.Scheme().Encapsulate(pk)
}

func KemDecapsulate(kemSecBytes, ct []byte) ([]byte, error) {
	sk, err := kyber768.Scheme().UnmarshalBinaryPrivateKey(kemSecBytes)
	if err != nil {
		return nil, err
	}
	return kyber768.Scheme().Decapsulate(sk, ct)
}

func hybridCombine(pqSS, classicalSS []byte) []byte {
	h := sha256.Sum256(append(append([]byte{}, pqSS...), classicalSS...))
	return h[:]
}

func Sign(sigSecBytes, message []byte) ([]byte, error) {
	if len(sigSecBytes) != mode3.PrivateKeySize {
		return nil, errors.New("bad sig secret size")
	}
	var sk mode3.PrivateKey
	var buf [mode3.PrivateKeySize]byte
	copy(buf[:], sigSecBytes)
	sk.Unpack(&buf)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&sk, message, sig)
	return sig, nil
}

func Verify(sigPubBytes, message, signature []byte) bool {
	if len(sigPubBytes) != mode3.PublicKeySize {
		return false
	}
	var pk mode3.PublicKey
	var buf [mode3.PublicKeySize]byte
	copy(buf[:], sigPubBytes)
	pk.Unpack(&buf)
	return mode3.Verify(&pk, message, signature)
}

func SignHybrid(kp *KeyPair, message []byte) (pqSig, edSig []byte, err error) {
	pqSig, err = Sign(kp.SigSec, message)
	if err != nil {
		return nil, nil, err
	}
	if len(kp.EdSec) == ed25519.PrivateKeySize {
		edSig = ed25519.Sign(ed25519.PrivateKey(kp.EdSec), message)
	}
	return pqSig, edSig, nil
}

func VerifyHybrid(kp *KeyPair, message, pqSig, edSig []byte) bool {
	if !Verify(kp.SigPub, message, pqSig) {
		return false
	}
	if len(kp.EdPub) == ed25519.PublicKeySize && len(edSig) > 0 {
		return ed25519.Verify(ed25519.PublicKey(kp.EdPub), message, edSig)
	}
	return true
}

// ----- High-level encrypt -----

type RecipientBlob struct {
	ID KeyID
	CT []byte
}

type EncryptedMessage struct {
	Symmetric  bool
	Hybrid     bool
	Recipients []RecipientBlob
	Nonce      []byte
	Tag        []byte
	Ciphertext []byte
	Filename   string
	Salt       []byte
}

func EncryptTo(recipients []*KeyPair, plaintext []byte, filename string, forceHybrid bool) (*EncryptedMessage, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients")
	}
	cek := make([]byte, AESKeySize)
	if _, err := io.ReadFull(rand.Reader, cek); err != nil {
		return nil, err
	}
	defer zero(cek)

	ct, nonce, tag, err := EncryptSymmetric(plaintext, cek)
	if err != nil {
		return nil, err
	}

	msg := &EncryptedMessage{
		Nonce: nonce, Tag: tag, Ciphertext: ct, Filename: filename,
	}

	for _, r := range recipients {
		useHybrid := (forceHybrid || r.Meta.Hybrid) && len(r.XPub) == 32
		if useHybrid {
			msg.Hybrid = true
		}

		kemCT, pqSS, err := KemEncapsulate(r.KemPub)
		if err != nil {
			return nil, err
		}

		var wrapKey []byte
		var ephPub []byte
		if useHybrid {
			eph, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				zero(pqSS)
				return nil, err
			}
			peer, err := ecdh.X25519().NewPublicKey(r.XPub)
			if err != nil {
				zero(pqSS)
				return nil, err
			}
			classSS, err := eph.ECDH(peer)
			if err != nil {
				zero(pqSS)
				return nil, err
			}
			wrapKey = hybridCombine(pqSS, classSS)
			zero(pqSS)
			zero(classSS)
			ephPub = eph.PublicKey().Bytes()
		} else {
			sum := sha256.Sum256(pqSS)
			zero(pqSS)
			wrapKey = sum[:]
		}

		wct, wnonce, wtag, err := EncryptSymmetric(cek, wrapKey)
		zero(wrapKey)
		if err != nil {
			return nil, err
		}

		// hybrid: ephPub(32) || kemCT || wnonce || wtag || wct
		// pure:            kemCT || wnonce || wtag || wct
		var blob []byte
		if useHybrid {
			blob = append(blob, ephPub...)
		}
		blob = append(blob, kemCT...)
		blob = append(blob, wnonce...)
		blob = append(blob, wtag...)
		blob = append(blob, wct...)
		msg.Recipients = append(msg.Recipients, RecipientBlob{ID: r.Meta.ID, CT: blob})
	}
	return msg, nil
}

func DecryptWith(kp *KeyPair, msg *EncryptedMessage) ([]byte, error) {
	if !kp.HasSecret {
		return nil, errors.New("no secret key")
	}
	kemCTSize := kyber768.CiphertextSize

	for _, r := range msg.Recipients {
		if r.ID != kp.Meta.ID {
			continue
		}
		off := 0
		var ephPub []byte
		useHybrid := msg.Hybrid && len(kp.XSec) == 32
		if useHybrid {
			if len(r.CT) < 32+kemCTSize+NonceSize+TagSize+1 {
				continue
			}
			ephPub = r.CT[:32]
			off = 32
		} else if len(r.CT) < kemCTSize+NonceSize+TagSize+1 {
			continue
		}

		kemCT := r.CT[off : off+kemCTSize]
		off += kemCTSize
		wnonce := r.CT[off : off+NonceSize]
		off += NonceSize
		wtag := r.CT[off : off+TagSize]
		off += TagSize
		wct := r.CT[off:]

		pqSS, err := KemDecapsulate(kp.KemSec, kemCT)
		if err != nil {
			continue
		}

		var wrapKey []byte
		if useHybrid {
			priv, err := ecdh.X25519().NewPrivateKey(kp.XSec)
			if err != nil {
				zero(pqSS)
				continue
			}
			peer, err := ecdh.X25519().NewPublicKey(ephPub)
			if err != nil {
				zero(pqSS)
				continue
			}
			classSS, err := priv.ECDH(peer)
			if err != nil {
				zero(pqSS)
				continue
			}
			wrapKey = hybridCombine(pqSS, classSS)
			zero(pqSS)
			zero(classSS)
		} else {
			sum := sha256.Sum256(pqSS)
			zero(pqSS)
			wrapKey = sum[:]
		}

		cek, err := DecryptSymmetric(wct, wrapKey, wnonce, wtag)
		zero(wrapKey)
		if err != nil {
			continue
		}
		pt, err := DecryptSymmetric(msg.Ciphertext, cek, msg.Nonce, msg.Tag)
		zero(cek)
		if err != nil {
			continue
		}
		return pt, nil
	}
	return nil, errors.New("no matching recipient or decryption failed")
}

func EncryptSymmetricPassphrase(plaintext []byte, passphrase, filename string) (*EncryptedMessage, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iters, AESKeySize, sha256.New)
	defer zero(key)
	ct, nonce, tag, err := EncryptSymmetric(plaintext, key)
	if err != nil {
		return nil, err
	}
	return &EncryptedMessage{
		Symmetric: true, Salt: salt, Nonce: nonce, Tag: tag,
		Ciphertext: ct, Filename: filename,
	}, nil
}

func DecryptSymmetricPassphrase(msg *EncryptedMessage, passphrase string) ([]byte, error) {
	if !msg.Symmetric {
		return nil, errors.New("not symmetric")
	}
	key := pbkdf2.Key([]byte(passphrase), msg.Salt, PBKDF2Iters, AESKeySize, sha256.New)
	defer zero(key)
	return DecryptSymmetric(msg.Ciphertext, key, msg.Nonce, msg.Tag)
}

func ProtectPrivate(kp *KeyPair, passphrase string) ([]byte, error) {
	// sigSec | kemSec | edSec | xSec with length prefixes
	var buf []byte
	appendField := func(b []byte) {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(b)))
		buf = append(buf, b...)
	}
	appendField(kp.SigSec)
	appendField(kp.KemSec)
	appendField(kp.EdSec)
	appendField(kp.XSec)

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iters, AESKeySize, sha256.New)
	defer zero(key)
	ct, nonce, tag, err := EncryptSymmetric(buf, key)
	zero(buf)
	if err != nil {
		return nil, err
	}
	out := []byte{'P', 'Q', 'P', 'K', 2}
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, tag...)
	out = append(out, ct...)
	return out, nil
}

func UnprotectPrivate(blob []byte, passphrase string) (sigSec, kemSec, edSec, xSec []byte, err error) {
	if len(blob) < 5+SaltSize+NonceSize+TagSize || string(blob[:4]) != "PQPK" {
		return nil, nil, nil, nil, errors.New("invalid protected key")
	}
	ver := blob[4]
	off := 5
	salt := blob[off : off+SaltSize]
	off += SaltSize
	nonce := blob[off : off+NonceSize]
	off += NonceSize
	tag := blob[off : off+TagSize]
	off += TagSize
	ct := blob[off:]

	key := pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iters, AESKeySize, sha256.New)
	defer zero(key)
	plain, err := DecryptSymmetric(ct, key, nonce, tag)
	if err != nil {
		return nil, nil, nil, nil, errors.New("wrong passphrase or corrupt key")
	}
	read := func() ([]byte, error) {
		if len(plain) < 4 {
			return nil, errors.New("corrupt")
		}
		n := binary.LittleEndian.Uint32(plain[:4])
		plain = plain[4:]
		if uint32(len(plain)) < n {
			return nil, errors.New("corrupt")
		}
		b := append([]byte{}, plain[:n]...)
		plain = plain[n:]
		return b, nil
	}
	if sigSec, err = read(); err != nil {
		return
	}
	if kemSec, err = read(); err != nil {
		return
	}
	if ver >= 2 {
		if edSec, err = read(); err != nil {
			return
		}
		if xSec, err = read(); err != nil {
			return
		}
	}
	return
}

// ----- Directory archive (tar) -----

func ArchiveDirectory(dir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.Contains(rel, "..") {
			return fmt.Errorf("path traversal: %s", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ExtractArchive(data []byte, outDir string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}
		target := filepath.Join(outDir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

// ----- Benchmarks -----

type BenchResult struct {
	Alg  string  `json:"alg"`
	Op   string  `json:"op"`
	AvgMs float64 `json:"avg_ms"`
	N    int     `json:"iterations"`
}

func RunBenchmarks(iterations int) []BenchResult {
	if iterations < 1 {
		iterations = 10
	}
	var results []BenchResult
	// Kyber768
	{
		t0 := time.Now()
		for i := 0; i < iterations; i++ {
			_, _, _ = kyber768.GenerateKeyPair(rand.Reader)
		}
		results = append(results, BenchResult{"Kyber768", "keygen", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})

		pk, sk, _ := kyber768.GenerateKeyPair(rand.Reader)
		pkB, _ := pk.MarshalBinary()
		t0 = time.Now()
		for i := 0; i < iterations; i++ {
			_, _, _ = KemEncapsulate(pkB)
		}
		results = append(results, BenchResult{"Kyber768", "encaps", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})

		ct, _, _ := KemEncapsulate(pkB)
		skB, _ := sk.MarshalBinary()
		t0 = time.Now()
		for i := 0; i < iterations; i++ {
			_, _ = KemDecapsulate(skB, ct)
		}
		results = append(results, BenchResult{"Kyber768", "decaps", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})
	}
	// Dilithium3
	{
		t0 := time.Now()
		for i := 0; i < iterations; i++ {
			_, _, _ = mode3.GenerateKey(rand.Reader)
		}
		results = append(results, BenchResult{"Dilithium3", "keygen", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})

		pk, sk, _ := mode3.GenerateKey(rand.Reader)
		var skBuf [mode3.PrivateKeySize]byte
		sk.Pack(&skBuf)
		msg := []byte("benchmark message")
		t0 = time.Now()
		var sig []byte
		for i := 0; i < iterations; i++ {
			sig, _ = Sign(skBuf[:], msg)
		}
		results = append(results, BenchResult{"Dilithium3", "sign", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})

		var pkBuf [mode3.PublicKeySize]byte
		pk.Pack(&pkBuf)
		t0 = time.Now()
		for i := 0; i < iterations; i++ {
			_ = Verify(pkBuf[:], msg, sig)
		}
		results = append(results, BenchResult{"Dilithium3", "verify", float64(time.Since(t0).Microseconds()) / float64(iterations) / 1000, iterations})
	}
	return results
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
