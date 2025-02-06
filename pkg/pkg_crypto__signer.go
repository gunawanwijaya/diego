package pkg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/nacl/sign"
)

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Verifier
}

type Verifier interface {
	Validator
	Verify(msg []byte, sig []byte) error
}

var _ Signer = NopSigner{}

type NopSigner struct{}

func (NopSigner) Sign([]byte) ([]byte, error) { return nil, ErrUnimplemented }
func (NopSigner) Verify([]byte, []byte) error { return ErrUnimplemented }
func (NopSigner) Validate() error             { return ErrUnimplemented }

// ---------------------------------------------------------------------------------------------------------------------

// OAEP
func OAEP(key *rsa.PrivateKey, hash crypto.Hash, label []byte) Cipher {
	return rsaArgs{&key.PublicKey, key, hash, 1, nil, label}
}

// OAEPEncrypt
func OAEPEncrypt(pub *rsa.PublicKey, hash crypto.Hash, label []byte) Encrypter {
	return rsaArgs{pub, nil, hash, 1, nil, label}
}

// PKCS1v15
func PKCS1v15(key *rsa.PrivateKey, hash crypto.Hash) interface {
	Signer
	Cipher
} {
	return rsaArgs{&key.PublicKey, key, hash, 2, nil, nil}
}

// PKCS1v15EncryptVerify
func PKCS1v15EncryptVerify(pub *rsa.PublicKey, hash crypto.Hash) interface {
	Encrypter
	Verifier
} {
	return rsaArgs{pub, nil, hash, 2, nil, nil}
}

// PSS
func PSS(key *rsa.PrivateKey, hash crypto.Hash, opts *rsa.PSSOptions) Signer {
	return rsaArgs{&key.PublicKey, key, hash, 3, opts, nil}
}

// PSSVerify
func PSSVerify(pub *rsa.PublicKey, hash crypto.Hash, opts *rsa.PSSOptions) Verifier {
	return rsaArgs{pub, nil, hash, 3, opts, nil}
}

type rsaArgs struct {
	pub  *rsa.PublicKey
	key  *rsa.PrivateKey
	hash crypto.Hash
	mode int // 1=OAEP 2=PKCS1v15 2=PSS

	pssOpts   *rsa.PSSOptions
	oaepLabel []byte
}

func (x rsaArgs) Encrypt(msg []byte) ([]byte, error) {
	switch x.mode {
	default:
		return nil, ErrUnimplemented
	case 1:
		return rsa.EncryptOAEP(x.hash.New(), rand.Reader, x.pub, msg, x.oaepLabel)
	case 2:
		return rsa.EncryptPKCS1v15(rand.Reader, x.pub, msg)
	}
}

func (x rsaArgs) Decrypt(cip []byte) ([]byte, error) {
	switch x.mode {
	default:
		return nil, ErrUnimplemented
	case 1:
		return rsa.DecryptOAEP(x.hash.New(), rand.Reader, x.key, cip, x.oaepLabel)
	case 2:
		return rsa.DecryptPKCS1v15(rand.Reader, x.key, cip)
	}
}

func (x rsaArgs) Sign(msg []byte) ([]byte, error) {
	switch x.mode {
	default:
		return nil, ErrUnimplemented
	case 2:
		return rsa.SignPKCS1v15(rand.Reader, x.key, x.hash, Digest(x.hash, msg))
	case 3:
		return rsa.SignPSS(rand.Reader, x.key, x.hash, Digest(x.hash, msg), x.pssOpts)
	}
}

func (x rsaArgs) Verify(msg []byte, sig []byte) error {
	switch x.mode {
	default:
		return ErrUnimplemented
	case 2:
		return rsa.VerifyPKCS1v15(x.pub, x.hash, Digest(x.hash, msg), sig)
	case 3:
		return rsa.VerifyPSS(x.pub, x.hash, Digest(x.hash, msg), sig, x.pssOpts)
	}
}

func (x rsaArgs) Validate() error {
	var key *rsa.PrivateKey
	var err error
	if x.key != nil {
		if err = x.key.Validate(); err != nil {
			return err
		}
		key = x.key
	} else {
		if key, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			return err
		}
	}
	var y = rsaArgs{&key.PublicKey, key, x.hash, x.mode, x.pssOpts, x.oaepLabel}
	switch x.mode {
	default:
		return ErrUnimplemented
	case 1:
		return validateCipher(y)
	case 2:
		return errors.Join(validateCipher(y), validateSigner(y))
	case 3:
		return validateSigner(y)
	}
}

// ---------------------------------------------------------------------------------------------------------------------

// ECDSASign
func ECDSASign(key *ecdsa.PrivateKey) Signer { return ecdsaArgs{&key.PublicKey, key} }

// ECDSAVerify
func ECDSAVerify(pub *ecdsa.PublicKey) Verifier { return ecdsaArgs{pub, nil} }

type ecdsaArgs struct {
	pub *ecdsa.PublicKey
	key *ecdsa.PrivateKey
}

func (x ecdsaArgs) Sign(msg []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, x.key, Digest(x.hash(), msg))
}
func (x ecdsaArgs) Verify(msg []byte, sig []byte) error {
	if !ecdsa.VerifyASN1(x.pub, Digest(x.hash(), msg), sig) {
		return ErrorStr("invalid sig")
	}
	return nil
}

func (x ecdsaArgs) Validate() error {
	if x.key != nil {
		return validateSigner(ecdsaArgs{&x.key.PublicKey, x.key})
	}
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}
	return validateSigner(ecdsaArgs{&key.PublicKey, key})
}

func (x ecdsaArgs) hash() crypto.Hash {
	var c elliptic.Curve
	if x.key != nil {
		c = x.key.Curve
	} else if x.pub != nil {
		c = x.pub.Curve
	}
	switch c {
	default:
		return 0
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	}
}

// ---------------------------------------------------------------------------------------------------------------------

// Ed25519Sign
func Ed25519Sign(pub ed25519.PublicKey, key ed25519.PrivateKey, opts *ed25519.Options) Signer {
	return ed25519Args{pub, key, opts}
}

// Ed25519Verify
func Ed25519Verify(pub ed25519.PublicKey, opts *ed25519.Options) Verifier {
	return ed25519Args{pub, nil, opts}
}

type ed25519Args struct {
	pub  ed25519.PublicKey
	key  ed25519.PrivateKey
	opts *ed25519.Options
}

func (x ed25519Args) Sign(msg []byte) ([]byte, error) {
	if len(x.key) != ed25519.PrivateKeySize {
		return nil, ErrorStr("invalid key")
	}
	if x.opts != nil && x.opts.Hash == crypto.SHA512 {
		msg = Digest(x.opts.Hash, msg)
		return x.key.Sign(rand.Reader, msg, x.opts)
	}
	return ed25519.Sign(x.key, msg), nil
}

func (x ed25519Args) Verify(msg []byte, sig []byte) error {
	if len(x.pub) != ed25519.PublicKeySize {
		return ErrorStr("invalid key")
	} else if len(sig) != ed25519.SignatureSize {
		return ErrorStr("invalid sig")
	}
	if x.opts != nil && x.opts.Hash == crypto.SHA512 {
		msg = Digest(x.opts.Hash, msg)
		return ed25519.VerifyWithOptions(x.pub, msg, sig, x.opts)
	}
	if !ed25519.Verify(x.pub, msg, sig) {
		return ErrorStr("invalid sig")
	}
	return nil

}

func (x ed25519Args) Validate() error {
	if x.key != nil {
		if x.pub != nil {
			return validateSigner(ed25519Args{x.pub, x.key, nil})
		} else if pub, ok := x.key.Public().(ed25519.PublicKey); ok {
			return validateSigner(ed25519Args{pub, x.key, nil})
		}
		return ErrorStr("invalid key")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return validateSigner(ed25519Args{pub, key, nil})
}

// ---------------------------------------------------------------------------------------------------------------------

// NaClSign
func NaClSign(pub *[32]byte, key *[64]byte) Signer { return naclSignArgs{pub, key} }

// NaClVerify
func NaClVerify(pub *[32]byte) Verifier { return naclSignArgs{pub, nil} }

type naclSignArgs struct {
	pub *[32]byte
	key *[64]byte
}

func (x naclSignArgs) Sign(msg []byte) ([]byte, error) {
	return sign.Sign(nil, msg, x.key), nil
}
func (x naclSignArgs) Verify(msg []byte, sig []byte) error {
	msg0, ok := sign.Open(nil, sig, x.pub)
	if !ok || subtle.ConstantTimeCompare(msg0, msg) != 1 {
		return ErrorStr("invalid sig")
	}
	return nil
}

func (x naclSignArgs) Validate() error {
	if x.key != nil && x.pub != nil {
		return validateSigner(x)
	}
	if pub, key, err := sign.GenerateKey(rand.Reader); err != nil {
		return err
	} else {
		return validateSigner(naclSignArgs{pub, key})
	}
}

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

func validateSigner(s Signer) error {
	msg := []byte("good day")
	sig, err := s.Sign(msg)
	if err != nil {
		return err
	}
	if err := s.Verify(msg, sig); err != nil {
		return err
	}
	return nil
}

func Digest(h crypto.Hash, p []byte) []byte {
	hh := h.New()
	hh.Reset()
	hh.Write(p)
	return hh.Sum(nil)
}
