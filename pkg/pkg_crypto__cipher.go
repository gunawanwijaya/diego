package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

type CipherStream interface {
	Cipher
	StreamWriter(w io.Writer) (io.Writer, error)
	StreamReader(r io.Reader) (io.Reader, error)
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
//
// ---------------------------------------------------------------------------------------------------------------------

func AES_CBC_IV(key, iv []byte) Cipher {
	b, err := aes.NewCipher(key)
	return cipherBlock{b, err, iv}
}
func AES_CBC(key []byte) Cipher { return AES_CBC_IV(key, nil) }

type cipherBlock struct {
	cipher.Block
	err error
	iv  []byte
}

func (x cipherBlock) Encrypt(msg []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var n, dst, iv = dstiv(x.Block.BlockSize(), x.iv)
		var msgPad = pkcs5padding(n, msg)
		var cip = make([]byte, len(msgPad))
		cipher.NewCBCEncrypter(x.Block, iv).CryptBlocks(cip, msgPad)
		return slices.Concat(dst, cip), nil
	}
}
func (x cipherBlock) Decrypt(cip []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var n, iv, cip = ivcip(x.Block.BlockSize(), x.iv, cip)
		var msg = make([]byte, len(cip))
		cipher.NewCBCDecrypter(x.Block, iv).CryptBlocks(msg, cip)
		return pkcs5trimming(n, msg), nil
	}
}
func (x cipherBlock) Validate() error { return errors.Join(x.err, validateCipher(x)) }

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

func AES_CTR_IV(key, iv []byte) CipherStream {
	b, err := aes.NewCipher(key)
	return cipherStream{b, err, iv, nil, nil}
}
func AES_CTR(key []byte) CipherStream { return AES_CTR_IV(key, nil) }

type cipherStream struct {
	cipher.Block
	err error
	iv  []byte

	io.Writer
	io.Reader
}

func (x cipherStream) Encrypt(msg []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var _, dst, iv = dstiv(x.Block.BlockSize(), x.iv)
		var cip = make([]byte, len(msg))
		cipher.NewCTR(x.Block, iv).XORKeyStream(cip, msg)
		return slices.Concat(dst, cip), nil
	}
}
func (x cipherStream) Decrypt(cip []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var _, iv, cip = ivcip(x.Block.BlockSize(), x.iv, cip)
		var msg = make([]byte, len(cip))
		cipher.NewCTR(x.Block, iv).XORKeyStream(msg, cip)
		return msg, nil
	}
}
func (x cipherStream) StreamWriter(w io.Writer) (io.Writer, error) {
	if x.Writer == nil {
		return nil, ErrorStr("invalid Writer")
	} else if len(x.iv) != x.Block.BlockSize() {
		return nil, ErrorStr("invalid iv")
	} else {
		x.Writer = w
		return x, nil
	}
}
func (x cipherStream) StreamReader(r io.Reader) (io.Reader, error) {
	if x.Reader == nil {
		return nil, ErrorStr("invalid Reader")
	} else if len(x.iv) != x.Block.BlockSize() {
		return nil, ErrorStr("invalid iv")
	} else {
		x.Reader = r
		return x, nil
	}
}
func (x cipherStream) Write(p []byte) (int, error) {
	if x.err != nil {
		return 0, x.err
	} else {
		buf := make([]byte, len(p))
		cipher.NewCTR(x.Block, x.iv).XORKeyStream(buf, p)
		return x.Writer.Write(buf)
	}
}
func (x cipherStream) Read(p []byte) (int, error) {
	if x.err != nil {
		return 0, x.err
	} else if x.Reader == nil {
		return 0, ErrorStr("invalid Reader")
	} else if len(x.iv) != x.Block.BlockSize() {
		return 0, ErrorStr("invalid iv")
	} else {
		n, err := x.Reader.Read(p)
		buf := make([]byte, n)
		cipher.NewCTR(x.Block, x.iv).XORKeyStream(buf, p[:n])
		copy(p, buf)
		return n, err
	}
}
func (x cipherStream) Validate() error { return errors.Join(x.err, validateCipher(x)) }

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

func AES_GCM_IVData(key, iv, add []byte) Cipher {
	if b, err := aes.NewCipher(key); err != nil {
		return cipherAEAD{nil, err, iv, add}
	} else {
		aead, err := cipher.NewGCM(b)
		return cipherAEAD{aead, err, iv, add}
	}
}
func ChaCha20Poly1305_IVData(key, iv, add []byte) Cipher {
	aead, err := chacha20poly1305.New(key)
	return cipherAEAD{aead, err, iv, add}
}
func XChaCha20Poly1305_IVData(key, iv, add []byte) Cipher {
	aead, err := chacha20poly1305.NewX(key)
	return cipherAEAD{aead, err, iv, add}
}

func AES_GCM(key []byte) Cipher                     { return AES_GCM_IV(key, nil) }
func AES_GCM_Data(key, add []byte) Cipher           { return AES_GCM_IVData(key, nil, add) }
func AES_GCM_IV(key, iv []byte) Cipher              { return AES_GCM_IVData(key, iv, nil) }
func ChaCha20Poly1305(key []byte) Cipher            { return ChaCha20Poly1305_IV(key, nil) }
func ChaCha20Poly1305_Data(key, add []byte) Cipher  { return ChaCha20Poly1305_IVData(key, nil, add) }
func ChaCha20Poly1305_IV(key, iv []byte) Cipher     { return ChaCha20Poly1305_IVData(key, iv, nil) }
func XChaCha20Poly1305(key []byte) Cipher           { return XChaCha20Poly1305_IV(key, nil) }
func XChaCha20Poly1305_Data(key, add []byte) Cipher { return XChaCha20Poly1305_IVData(key, nil, add) }
func XChaCha20Poly1305_IV(key, iv []byte) Cipher    { return XChaCha20Poly1305_IVData(key, iv, nil) }

type cipherAEAD struct {
	cipher.AEAD
	err                error
	iv, additionalData []byte
}

func (x cipherAEAD) Encrypt(msg []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var _, dst, iv = dstiv(x.AEAD.NonceSize(), x.iv)
		return x.AEAD.Seal(dst, iv, msg, x.additionalData), nil
	}
}
func (x cipherAEAD) Decrypt(cip []byte) ([]byte, error) {
	if x.err != nil {
		return nil, x.err
	} else {
		var _, iv, cip = ivcip(x.AEAD.NonceSize(), x.iv, cip)
		return x.AEAD.Open(nil, iv, cip, x.additionalData)
	}
}
func (x cipherAEAD) Validate() error { return errors.Join(x.err, validateCipher(x)) }

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
	return slices.Concat(p, bytes.Repeat([]byte{byte(m)}, m))
}

func pkcs5trimming(_ int, p []byte) []byte {
	m := p[len(p)-1]
	return p[:len(p)-int(m)]
}

func dstiv(n int, iv []byte) (int, []byte, []byte) {
	if len(iv) == n && n > 0 {
		return n, nil, iv
	} else {
		iv = Nonce(n)
		return n, iv, iv
	}
}

func ivcip(n int, iv []byte, cip []byte) (int, []byte, []byte) {
	if len(iv) == n && n > 0 {
		return n, iv, cip
	} else {
		return n, cip[:n], cip[n:]
	}
}
