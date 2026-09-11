package keyring

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pqgpg/pqgpg/internal/armor"
	"github.com/pqgpg/pqgpg/internal/crypto"
)

type Keyring struct {
	Home     string
	Public   map[crypto.KeyID]*crypto.KeyPair // public only
	Private  map[crypto.KeyID]*protectedKey   // encrypted secrets
}

type protectedKey struct {
	Meta           crypto.KeyMeta
	SigPub, KemPub []byte
	Blob           []byte // from crypto.ProtectPrivate
}

func DefaultHome() string {
	if h := os.Getenv("PQGPG_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".pqgpg"
	}
	return filepath.Join(home, ".pqgpg")
}

func Open(home string) (*Keyring, error) {
	if home == "" {
		home = DefaultHome()
	}
	kr := &Keyring{
		Home:    home,
		Public:  make(map[crypto.KeyID]*crypto.KeyPair),
		Private: make(map[crypto.KeyID]*protectedKey),
	}
	if err := kr.load(); err != nil {
		// start empty
		_ = os.MkdirAll(home, 0o700)
	}
	return kr, nil
}

func (kr *Keyring) pubPath() string  { return filepath.Join(kr.Home, "pubring.json") }
func (kr *Keyring) privPath() string { return filepath.Join(kr.Home, "secring.json") }

func (kr *Keyring) load() error {
	// Public
	if data, err := os.ReadFile(kr.pubPath()); err == nil {
		var list []jsonPub
		if err := json.Unmarshal(data, &list); err == nil {
			for _, j := range list {
				kp := j.toKeyPair()
				kr.Public[kp.Meta.ID] = kp
			}
		}
	}
	// Private
	if data, err := os.ReadFile(kr.privPath()); err == nil {
		var list []jsonPriv
		if err := json.Unmarshal(data, &list); err == nil {
			for _, j := range list {
				pk := j.toProtected()
				kr.Private[pk.Meta.ID] = pk
			}
		}
	}
	return nil
}

func (kr *Keyring) Save() error {
	if err := os.MkdirAll(kr.Home, 0o700); err != nil {
		return err
	}
	// Public
	var pubs []jsonPub
	for _, kp := range kr.Public {
		pubs = append(pubs, fromKeyPair(kp))
	}
	data, _ := json.MarshalIndent(pubs, "", "  ")
	if err := os.WriteFile(kr.pubPath(), data, 0o644); err != nil {
		return err
	}
	// Private
	var privs []jsonPriv
	for _, pk := range kr.Private {
		privs = append(privs, fromProtected(pk))
	}
	data, _ = json.MarshalIndent(privs, "", "  ")
	return os.WriteFile(kr.privPath(), data, 0o600)
}

func (kr *Keyring) Add(kp *crypto.KeyPair, passphrase string) error {
	blob, err := crypto.ProtectPrivate(kp, passphrase)
	if err != nil {
		return err
	}
	pubOnly := *kp
	pubOnly.SigSec, pubOnly.KemSec = nil, nil
	pubOnly.EdSec, pubOnly.XSec = nil, nil
	pubOnly.HasSecret = false
	kr.Public[kp.Meta.ID] = &pubOnly
	kr.Private[kp.Meta.ID] = &protectedKey{
		Meta:   kp.Meta,
		SigPub: kp.SigPub,
		KemPub: kp.KemPub,
		Blob:   blob,
	}
	// also keep classical pubs on public key
	kr.Public[kp.Meta.ID].EdPub = append([]byte{}, kp.EdPub...)
	kr.Public[kp.Meta.ID].XPub = append([]byte{}, kp.XPub...)
	return kr.Save()
}

func (kr *Keyring) ImportPublic(kp *crypto.KeyPair) error {
	pubOnly := *kp
	pubOnly.SigSec = nil
	pubOnly.KemSec = nil
	pubOnly.HasSecret = false
	kr.Public[kp.Meta.ID] = &pubOnly
	return kr.Save()
}

func (kr *Keyring) FindPublic(id crypto.KeyID) *crypto.KeyPair {
	return kr.Public[id]
}

func (kr *Keyring) FindPublicByQuery(q string) *crypto.KeyPair {
	q = strings.ToLower(strings.TrimSpace(q))
	for _, kp := range kr.Public {
		if strings.Contains(strings.ToLower(kp.Meta.UID.Name), q) ||
			strings.Contains(strings.ToLower(kp.Meta.UID.Email), q) ||
			strings.Contains(strings.ToLower(kp.Meta.ID.String()), q) {
			return kp
		}
	}
	return nil
}

func (kr *Keyring) FindPrivate(id crypto.KeyID, passphrase string) (*crypto.KeyPair, error) {
	pk, ok := kr.Private[id]
	if !ok {
		return nil, fmt.Errorf("secret key not found")
	}
	sigSec, kemSec, edSec, xSec, err := crypto.UnprotectPrivate(pk.Blob, passphrase)
	if err != nil {
		return nil, err
	}
	pub := kr.Public[id]
	var edPub, xPub []byte
	if pub != nil {
		edPub, xPub = pub.EdPub, pub.XPub
	}
	return &crypto.KeyPair{
		Meta:      pk.Meta,
		SigPub:    pk.SigPub,
		SigSec:    sigSec,
		KemPub:    pk.KemPub,
		KemSec:    kemSec,
		EdPub:     edPub,
		EdSec:     edSec,
		XPub:      xPub,
		XSec:      xSec,
		HasSecret: true,
	}, nil
}

func (kr *Keyring) Revoke(id crypto.KeyID, reason string) error {
	if kp, ok := kr.Public[id]; ok {
		kp.Meta.Revoked = true
		kp.Meta.Reason = reason
	}
	if pk, ok := kr.Private[id]; ok {
		pk.Meta.Revoked = true
		pk.Meta.Reason = reason
	}
	return kr.Save()
}

func (kr *Keyring) ListPublic() []*crypto.KeyPair {
	var out []*crypto.KeyPair
	for _, kp := range kr.Public {
		out = append(out, kp)
	}
	return out
}

func (kr *Keyring) Delete(id crypto.KeyID) error {
	delete(kr.Public, id)
	delete(kr.Private, id)
	return kr.Save()
}

// Export public key as armored
func (kr *Keyring) ExportPublic(id crypto.KeyID) (string, error) {
	kp := kr.Public[id]
	if kp == nil {
		return "", fmt.Errorf("key not found")
	}
	data := serializePublic(kp)
	return armor.Encode(data, "PUBLIC KEY BLOCK"), nil
}

func serializePublic(kp *crypto.KeyPair) []byte {
	// Simple binary: magic | meta json len | meta json | sigPub len | sigPub | kemPub len | kemPub
	meta, _ := json.Marshal(kp.Meta)
	buf := []byte{'P', 'Q', 'P', 'B', 1}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(meta)))
	buf = append(buf, meta...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(kp.SigPub)))
	buf = append(buf, kp.SigPub...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(kp.KemPub)))
	buf = append(buf, kp.KemPub...)
	return buf
}

func DeserializePublic(data []byte) (*crypto.KeyPair, error) {
	if len(data) < 9 || string(data[:4]) != "PQPB" || data[4] != 1 {
		return nil, fmt.Errorf("invalid public key")
	}
	off := 5
	read := func() ([]byte, error) {
		if off+4 > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		n := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		if off+int(n) > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		b := data[off : off+int(n)]
		off += int(n)
		return b, nil
	}
	metaBytes, err := read()
	if err != nil {
		return nil, err
	}
	var meta crypto.KeyMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	sigPub, err := read()
	if err != nil {
		return nil, err
	}
	kemPub, err := read()
	if err != nil {
		return nil, err
	}
	return &crypto.KeyPair{
		Meta:   meta,
		SigPub: sigPub,
		KemPub: kemPub,
	}, nil
}

// JSON helpers for on-disk format
type jsonPub struct {
	Meta   crypto.KeyMeta `json:"meta"`
	SigPub []byte         `json:"sig_pub"`
	KemPub []byte         `json:"kem_pub"`
	EdPub  []byte         `json:"ed_pub,omitempty"`
	XPub   []byte         `json:"x_pub,omitempty"`
}

type jsonPriv struct {
	Meta   crypto.KeyMeta `json:"meta"`
	SigPub []byte         `json:"sig_pub"`
	KemPub []byte         `json:"kem_pub"`
	Blob   []byte         `json:"blob"`
}

func fromKeyPair(kp *crypto.KeyPair) jsonPub {
	return jsonPub{Meta: kp.Meta, SigPub: kp.SigPub, KemPub: kp.KemPub, EdPub: kp.EdPub, XPub: kp.XPub}
}
func (j jsonPub) toKeyPair() *crypto.KeyPair {
	return &crypto.KeyPair{Meta: j.Meta, SigPub: j.SigPub, KemPub: j.KemPub, EdPub: j.EdPub, XPub: j.XPub}
}
func fromProtected(pk *protectedKey) jsonPriv {
	return jsonPriv{Meta: pk.Meta, SigPub: pk.SigPub, KemPub: pk.KemPub, Blob: pk.Blob}
}
func (j jsonPriv) toProtected() *protectedKey {
	return &protectedKey{Meta: j.Meta, SigPub: j.SigPub, KemPub: j.KemPub, Blob: j.Blob}
}

func FormatTime(ts int64) string {
	if ts == 0 {
		return "never"
	}
	return time.Unix(ts, 0).Format(time.RFC1123)
}
