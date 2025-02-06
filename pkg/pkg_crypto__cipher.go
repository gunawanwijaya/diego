package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
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

// ---------------------------------------------------------------------------------------------------------------------

// NaClSecretBox
func NaClSecretBox(key *[32]byte) Cipher { return &naclSecretBox{key: key} }

// NaClBox
func NaClBox(peersPublicKey, privateKey *[32]byte) Cipher {
	var sharedKey = new([32]byte)
	box.Precompute(sharedKey, peersPublicKey, privateKey)
	return &naclSecretBox{key: sharedKey}
}

type naclSecretBox struct{ key *[32]byte }

func (x *naclSecretBox) Encrypt(msg []byte) ([]byte, error) {
	var nonce = (*[24]byte)(Nonce(24))
	return secretbox.Seal(nonce[:], msg, nonce, x.key), nil
}

func (x *naclSecretBox) Decrypt(cip []byte) ([]byte, error) {
	if len(cip) > 24 {
		var nonce = (*[24]byte)(cip[:24])
		if msg, ok := secretbox.Open(nil, cip[24:], nonce, x.key); ok {
			return msg, nil
		}
	}
	return nil, ErrorStr("nacl: invalid encrypt/decrypt")
}

func (x *naclSecretBox) Validate() error { return validateCipher(x) }

// ---------------------------------------------------------------------------------------------------------------------

// AES_CBC
func AES_CBC(key []byte) Cipher { return &cipherArgs{_AES_CBC, key, nil} }

// AES_CFB
func AES_CFB(key []byte) CipherStream { return &cipherArgs{_AES_CFB, key, nil} }

// AES_CTR
func AES_CTR(key []byte) CipherStream { return &cipherArgs{_AES_CTR, key, nil} }

// AES_OFB
func AES_OFB(key []byte) CipherStream { return &cipherArgs{_AES_OFB, key, nil} }

// AES_GCM
func AES_GCM(key []byte) Cipher { return &cipherArgs{_AES_GCM, key, nil} }

// ChaCha20Poly1305
func ChaCha20Poly1305(key []byte) Cipher { return &cipherArgs{_ChaCha20Poly1305, key, nil} }

// XChaCha20Poly1305
func XChaCha20Poly1305(key []byte) Cipher { return &cipherArgs{_XChaCha20Poly1305, key, nil} }

// AES_GCM_Data
func AES_GCM_Data(key, add []byte) Cipher { return &cipherArgs{_AES_GCM, key, add} }

// ChaCha20Poly1305_Data
func ChaCha20Poly1305_Data(key, add []byte) Cipher { return &cipherArgs{_ChaCha20Poly1305, key, add} }

// XChaCha20Poly1305_Data
func XChaCha20Poly1305_Data(key, add []byte) Cipher { return &cipherArgs{_XChaCha20Poly1305, key, add} }

type cipherMode int

const (
	_ cipherMode = iota
	_AES_CBC
	_AES_CFB
	_AES_CTR
	_AES_GCM
	_AES_OFB
	_ChaCha20Poly1305
	_XChaCha20Poly1305
)

type cipherArgs struct {
	cipherMode
	key            []byte
	additionalData []byte
}

func (x *cipherArgs) Encrypt(msg []byte) ([]byte, error) {
	if len(msg) < 1 {
		return msg, ErrorStr("invalid encrypt")
	}
	var b cipher.Block
	var iv, cip []byte

	switch x.cipherMode {
	case _AES_CBC, _AES_CFB, _AES_CTR, _AES_GCM, _AES_OFB:
		var err error
		if b, err = aes.NewCipher(x.key); err != nil {
			return nil, err
		}
		iv, cip = Nonce(b.BlockSize()), make([]byte, len(msg))
	}

	var seal = func(aead cipher.AEAD, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		iv = Nonce(aead.NonceSize())
		return aead.Seal(iv, iv, msg, x.additionalData), nil
	}

	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CBC:
		msgPad := pkcs5padding(b.BlockSize(), msg)
		cip = make([]byte, len(msgPad))
		cipher.NewCBCEncrypter(b, iv).CryptBlocks(cip, msgPad)
		return slices.Concat(iv, cip), nil
	case _AES_CFB:
		cipher.NewCFBEncrypter(b, iv).XORKeyStream(cip, msg)
		return slices.Concat(iv, cip), nil
	case _AES_CTR:
		cipher.NewCTR(b, iv).XORKeyStream(cip, msg)
		return slices.Concat(iv, cip), nil
	case _AES_GCM:
		return seal(cipher.NewGCM(b))
	case _AES_OFB:
		cipher.NewOFB(b, iv).XORKeyStream(cip, msg)
		return slices.Concat(iv, cip), nil
	case _ChaCha20Poly1305:
		return seal(chacha20poly1305.New(x.key))
	case _XChaCha20Poly1305:
		return seal(chacha20poly1305.NewX(x.key))
	}
}

func (x *cipherArgs) Decrypt(cip []byte) ([]byte, error) {
	var b cipher.Block
	var n int
	var msg []byte
	switch x.cipherMode {
	case _AES_CBC, _AES_CFB, _AES_CTR, _AES_GCM, _AES_OFB:
		var err error
		if b, err = aes.NewCipher(x.key); err != nil {
			return nil, err
		}
		n = b.BlockSize()
		msg = make([]byte, len(cip[n:]))
	}

	var open = func(aead cipher.AEAD, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		n = aead.NonceSize()
		return aead.Open(nil, cip[:n], cip[n:], x.additionalData)
	}

	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CBC:
		cipher.NewCBCDecrypter(b, cip[:n]).CryptBlocks(msg, cip[n:])
		msg = pkcs5trimming(n, msg)
		return msg, nil
	case _AES_CFB:
		cipher.NewCFBDecrypter(b, cip[:n]).XORKeyStream(msg, cip[n:])
		return msg, nil
	case _AES_CTR:
		cipher.NewCTR(b, cip[:n]).XORKeyStream(msg, cip[n:])
		return msg, nil
	case _AES_GCM:
		return open(cipher.NewGCM(b))
	case _AES_OFB:
		cipher.NewOFB(b, cip[:n]).XORKeyStream(msg, cip[n:])
		return msg, nil
	case _ChaCha20Poly1305:
		return open(chacha20poly1305.New(x.key))
	case _XChaCha20Poly1305:
		return open(chacha20poly1305.NewX(x.key))
	}
}

func (x *cipherArgs) Validate() error { return validateCipher(x) }

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

type CipherStream interface {
	Cipher
	StreamWriter(w io.Writer) (io.Writer, error)
	StreamReader(r io.Reader) (io.Reader, error)
}

type stream struct {
	io.Writer
	io.Reader
	s cipher.Stream
}

func (x *cipherArgs) StreamWriter(w io.Writer) (io.Writer, error) {
	b, err := aes.NewCipher(x.key)
	if err != nil {
		return nil, err
	}
	iv := Nonce(b.BlockSize())
	if _, err = w.Write(iv); err != nil {
		return nil, err
	}
	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CFB:
		return stream{w, nil, cipher.NewCFBEncrypter(b, iv)}, nil
	case _AES_CTR:
		return stream{w, nil, cipher.NewCTR(b, iv)}, nil
	case _AES_OFB:
		return stream{w, nil, cipher.NewOFB(b, iv)}, nil
	}
}

func (x *cipherArgs) StreamReader(r io.Reader) (io.Reader, error) {
	b, err := aes.NewCipher(x.key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, b.BlockSize())
	if _, err = r.Read(iv); err != nil {
		return nil, err
	}
	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CFB:
		return stream{nil, r, cipher.NewCFBDecrypter(b, iv)}, nil
	case _AES_CTR:
		return stream{nil, r, cipher.NewCTR(b, iv)}, nil
	case _AES_OFB:
		return stream{nil, r, cipher.NewOFB(b, iv)}, nil
	}
}

func (x stream) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	x.s.XORKeyStream(buf, p)
	return x.Writer.Write(buf)
}

func (x stream) Read(p []byte) (int, error) {
	n, err := x.Reader.Read(p)
	buf := make([]byte, n)
	x.s.XORKeyStream(buf, p[:n])
	copy(p, buf)
	return n, err
}

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

func validateCipher(x Cipher) error {
	msg := []byte("good day")
	var cip, dec []byte
	var err error
	if cip, err = x.Encrypt(msg); err != nil {
		return err
	}
	if bytes.Equal(msg, cip) {
		return ErrorStr("invalid encrypt")
	}
	if dec, err = x.Decrypt(cip); err != nil {
		return err
	}
	if !bytes.Equal(msg, dec) {
		return ErrorStr("invalid decrypt")
	}
	return nil
}

func Nonce(n int) []byte { p := make([]byte, n, n); rand.Read(p); return p }

func pkcs5padding(n int, p []byte) []byte {
	m := n - (len(p) % n)
	return append(p, bytes.Repeat([]byte{byte(m)}, m)...)
}

func pkcs5trimming(_ int, p []byte) []byte {
	m := p[len(p)-1]
	return p[:len(p)-int(m)]
}
