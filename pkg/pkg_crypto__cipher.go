package pkg

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"slices"
)

type Encrypter interface {
	Encrypt(msg []byte) ([]byte, error)
	Validator
}

type Cipher interface {
	Decrypt(cip []byte) ([]byte, error)
	Encrypter
}

var _ Cipher = NopCipher{}

type NopCipher struct{}

func (NopCipher) Encrypt([]byte) ([]byte, error) { return nil, ErrUnimplemented }
func (NopCipher) Decrypt([]byte) ([]byte, error) { return nil, ErrUnimplemented }
func (NopCipher) Validate() error                { return ErrUnimplemented }

type implCipher[T any] struct {
	metadata T
	implEncrypt
	implDecrypt
}

type implEncrypt func(msg []byte) ([]byte, error)
type implDecrypt func(cip []byte) ([]byte, error)

func (f implEncrypt) Encrypt(msg []byte) ([]byte, error) { return f(msg) }
func (f implDecrypt) Decrypt(cip []byte) ([]byte, error) { return f(cip) }
func (x implCipher[T]) Validate() error {
	if x.implEncrypt == nil {
		return ErrUnimplemented
	} else if cip, err := x.Encrypt([]byte("test")); err != nil {
		return ErrorStr("invalid encrypt")
	} else if x.implDecrypt == nil {
		return nil
	} else if msg, err := x.Decrypt(cip); err != nil || string(msg) != "test" {
		return ErrorStr("invalid decrypt")
	}
	return nil
}

type CipherStream interface {
	Cipher
	io.Reader
	io.Writer
}

type implIOReader func(p []byte) (int, error)
type implIOWriter func(p []byte) (int, error)

func (f implIOReader) Read(p []byte) (int, error)  { return f(p) }
func (f implIOWriter) Write(p []byte) (int, error) { return f(p) }

type pkcs5 struct{}

func (pkcs5) padding(n int, p []byte) []byte {
	m := n - (len(p) % n)
	return slices.Concat(p, bytes.Repeat([]byte{byte(m)}, m))
}

func (pkcs5) trimming(_ int, p []byte) []byte {
	m := p[len(p)-1]
	return p[:len(p)-int(m)]
}

type iv struct{}

func (iv) buildCache(n int, iv []byte) (int, []byte, []byte) {
	if len(iv) == n && n > 0 {
		return n, nil, iv
	} else {
		iv = Nonce(n)
		return n, iv, iv
	}
}

func (iv) parseFromCiphertext(n int, iv []byte, cip []byte) (int, []byte, []byte) {
	if len(iv) == n && n > 0 {
		return n, iv, cip
	} else {
		return n, cip[:n], cip[n:]
	}
}

type aead struct{ iv }

func (x aead) Cipher(z cipher.AEAD, iv, add []byte) Cipher {
	return implCipher[aead]{
		metadata: x,
		implEncrypt: func(msg []byte) ([]byte, error) {
			_, dst, iv := x.buildCache(z.NonceSize(), iv)
			return z.Seal(dst, iv, msg, add), nil
		},
		implDecrypt: func(cip []byte) ([]byte, error) {
			_, iv, cip := x.parseFromCiphertext(z.NonceSize(), iv, cip)
			return z.Open(nil, iv, cip, add)
		},
	}
}

func Nonce(n int) []byte { p := make([]byte, n); rand.Read(p); return p }

var Curve curve

type curve struct{}

func (curve) X25519() ecdh.Curve { return ecdh.X25519() }
func (curve) P256() ecdh.Curve   { return ecdh.P256() }
func (curve) P384() ecdh.Curve   { return ecdh.P384() }
func (curve) P521() ecdh.Curve   { return ecdh.P521() }

type ECDHPrivateKey = ecdh.PrivateKey
type ECDHPublicKey = ecdh.PublicKey
