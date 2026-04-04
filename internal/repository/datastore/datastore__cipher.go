package datastore

import (
	"crypto/ecdh"
	"crypto/rand"
	"slices"

	"github.com/gunawanwijaya/diego/pkg"
	// "github.com/rs/xid"
	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------------------------------------------------------------------
// CipherResolver
// ---------------------------------------------------------------------------------------------------------------------

type CipherResolver interface {
	New() (lookup []byte, c Cipher)
	Load(lookup []byte) (c Cipher)
}

var (
	mcr1 = "" // xid.New().String()
)

func DefaultCipherResolver(k1 *[32]byte) CipherResolver {
	return MapCipherResolver{
		mcr1: NaCl{datastoreCipher{}, k1},
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// MapCipherResolver
// ---------------------------------------------------------------------------------------------------------------------

type MapCipherResolver map[string]Cipher

func (m MapCipherResolver) New() (lookup []byte, c Cipher) { return m.load(nil) }
func (m MapCipherResolver) Load(lookup []byte) (c Cipher)  { _, c = m.load(lookup); return }
func (m MapCipherResolver) load(lookup []byte) (_ []byte, c Cipher) {
	var ok bool
	if c, ok = m[string(lookup)]; !ok {
		for k, v := range m {
			return []byte(k), v
		}
		c = datastoreCipher{}
	}
	return
}

// ---------------------------------------------------------------------------------------------------------------------
// NaCl
// ---------------------------------------------------------------------------------------------------------------------

type NaCl struct {
	datastoreCipher
	PrivateKey *[32]byte
}

func (x NaCl) Encrypt(msg []byte) (cip []byte, err error) {
	var pub *[32]byte
	if pub, _, err = box.GenerateKey(rand.Reader); err != nil {
		return
	}
	if cip, err = pkg.NaCl.Box(pub, x.PrivateKey).Encrypt(msg); err != nil {
		return
	}
	return slices.Concat(pub[:], cip), nil
}
func (x NaCl) Decrypt(cip []byte) (msg []byte, err error) {
	if err = pkg.ErrorStr("invalid ciphertext"); len(cip) < 32 {
		return
	}
	var pub = (*[32]byte)(cip[:32])
	return pkg.NaCl.Box(pub, x.PrivateKey).Decrypt(cip[32:])
}
func (x NaCl) Validate() error { return nil }

// ---------------------------------------------------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------------------------------------------------

type ECDH struct {
	datastoreCipher
	PrivateKey *ecdh.PrivateKey
	NewCipher  func(key []byte) pkg.Cipher
}

func (x ECDH) Encrypt(msg []byte) (cip []byte, err error) {
	if x.PrivateKey == nil {
		err = pkg.ErrorStr("invalid *ecdh.PrivateKey")
		return
	}
	if x.NewCipher == nil {
		err = pkg.ErrorStr("invalid pkg.Cipher")
		return
	}
	var k *ecdh.PrivateKey
	if k, err = x.PrivateKey.Curve().GenerateKey(rand.Reader); err != nil {
		return
	}
	var s []byte
	if s, err = x.PrivateKey.ECDH(k.PublicKey()); err != nil {
		return
	}
	var c pkg.Cipher
	if x.NewCipher != nil {
		if c, err = pkg.Validate(x.NewCipher(s[:32])); err != nil {
			return
		}
	}
	if c == nil {
		err = pkg.ErrorStr("invalid pkg.Cipher")
		return
	}
	if cip, err = c.Encrypt(msg); err != nil {
		return
	}
	return slices.Concat(k.PublicKey().Bytes(), cip), nil
}
func (x ECDH) Decrypt(cip []byte) (msg []byte, err error) {
	if x.PrivateKey == nil || x.PrivateKey.PublicKey() == nil {
		err = pkg.ErrorStr("invalid *ecdh.PrivateKey")
		return
	}
	var n = len(x.PrivateKey.PublicKey().Bytes())
	if len(cip) <= n {
		err = pkg.ErrorStr("len(cip) <= n")
		return
	}
	var pub *ecdh.PublicKey
	if pub, err = x.PrivateKey.Curve().NewPublicKey(cip[:n]); err != nil {
		return
	}
	var s []byte
	if s, err = x.PrivateKey.ECDH(pub); err != nil {
		return
	}
	var c pkg.Cipher
	if x.NewCipher != nil {
		if c, err = pkg.Validate(x.NewCipher(s[:32])); err != nil {
			return
		}
	}
	if c == nil {
		err = pkg.ErrorStr("invalid pkg.Cipher")
		return
	}
	return c.Decrypt(cip[n:])
}
func (x ECDH) Validate() error { return nil }

// ---------------------------------------------------------------------------------------------------------------------
// cipher
// ---------------------------------------------------------------------------------------------------------------------

type datastoreCipher struct{ pkg.NopCipher }

func (datastoreCipher) is() datastoreCipher { return datastoreCipher{} }

type Cipher interface {
	pkg.Cipher
	is() datastoreCipher
}
