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
func AES_CBC(key []byte) Cipher { return &cipherArgs{_AES_CBC, key, nil, nil} }

// AES_CFB
func AES_CFB(key []byte) CipherStream { return &cipherArgs{_AES_CFB, key, nil, nil} }

// AES_CTR
func AES_CTR(key []byte) CipherStream { return &cipherArgs{_AES_CTR, key, nil, nil} }

// AES_OFB
func AES_OFB(key []byte) CipherStream { return &cipherArgs{_AES_OFB, key, nil, nil} }

// AES_GCM
func AES_GCM(key []byte) Cipher { return &cipherArgs{_AES_GCM, key, nil, nil} }

// ChaCha20Poly1305
func ChaCha20Poly1305(key []byte) Cipher { return &cipherArgs{_c, key, nil, nil} }

// XChaCha20Poly1305
func XChaCha20Poly1305(key []byte) Cipher { return &cipherArgs{_xc, key, nil, nil} }

// AES_GCM_Data
func AES_GCM_Data(key, add []byte) Cipher { return &cipherArgs{_AES_GCM, key, nil, add} }

// ChaCha20Poly1305_Data
func ChaCha20Poly1305_Data(key, add []byte) Cipher { return &cipherArgs{_c, key, nil, add} }

// XChaCha20Poly1305_Data
func XChaCha20Poly1305_Data(key, add []byte) Cipher { return &cipherArgs{_xc, key, nil, add} }

// AES_CBC_IV
func AES_CBC_IV(key, iv []byte) Cipher { return &cipherArgs{_AES_CBC, key, iv, nil} }

// AES_CFB_IV
func AES_CFB_IV(key, iv []byte) CipherStream { return &cipherArgs{_AES_CFB, key, iv, nil} }

// AES_CTR_IV
func AES_CTR_IV(key, iv []byte) CipherStream { return &cipherArgs{_AES_CTR, key, iv, nil} }

// AES_OFB_IV
func AES_OFB_IV(key, iv []byte) CipherStream { return &cipherArgs{_AES_OFB, key, iv, nil} }

// AES_GCM_IV
func AES_GCM_IV(key, iv []byte) Cipher { return &cipherArgs{_AES_GCM, key, iv, nil} }

// ChaCha20Poly1305_IV
func ChaCha20Poly1305_IV(key, iv []byte) Cipher { return &cipherArgs{_c, key, iv, nil} }

// XChaCha20Poly1305_IV
func XChaCha20Poly1305_IV(key, iv []byte) Cipher { return &cipherArgs{_xc, key, iv, nil} }

// AES_GCM_IVData
func AES_GCM_IVData(key, iv, add []byte) Cipher { return &cipherArgs{_AES_GCM, key, iv, add} }

// ChaCha20Poly1305_IVData
func ChaCha20Poly1305_IVData(key, iv, add []byte) Cipher { return &cipherArgs{_c, key, iv, add} }

// XChaCha20Poly1305_IVData
func XChaCha20Poly1305_IVData(key, iv, add []byte) Cipher { return &cipherArgs{_xc, key, iv, add} }

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

	_c  = _ChaCha20Poly1305
	_xc = _XChaCha20Poly1305
)

type cipherArgs struct {
	cipherMode
	key, iv        []byte
	additionalData []byte
}

func (x *cipherArgs) Encrypt(msg []byte) ([]byte, error) {
	if len(msg) < 1 {
		return msg, ErrorStr("invalid encrypt")
	}
	var b cipher.Block
	var dst, iv []byte
	switch x.cipherMode {
	case _AES_CBC, _AES_CFB, _AES_CTR, _AES_GCM, _AES_OFB:
		var err error
		if b, err = aes.NewCipher(x.key); err != nil {
			return nil, err
		}
		if iv = Nonce(b.BlockSize()); len(x.iv) == b.BlockSize() {
			dst, iv = nil, x.iv
		} else {
			dst = iv
		}
	}

	var blk = func(dst []byte, block cipher.BlockMode) ([]byte, error) {
		var msgPad = pkcs5padding(b.BlockSize(), msg)
		var cip = make([]byte, len(msgPad))
		block.CryptBlocks(cip, msgPad)
		return slices.Concat(dst, cip), nil
	}
	var xor = func(dst []byte, stream cipher.Stream) ([]byte, error) {
		var cip = make([]byte, len(msg))
		stream.XORKeyStream(cip, msg)
		return slices.Concat(dst, cip), nil
	}
	var seal = func(aead cipher.AEAD, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		if n := aead.NonceSize(); len(x.iv) == n {
			return aead.Seal(nil, x.iv, msg, x.additionalData), nil
		} else {
			iv := Nonce(n)
			return aead.Seal(iv, iv, msg, x.additionalData), nil
		}
	}

	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CBC:
		return blk(dst, cipher.NewCBCEncrypter(b, iv))
	case _AES_CFB:
		return xor(dst, cipher.NewCFBEncrypter(b, iv))
	case _AES_CTR:
		return xor(dst, cipher.NewCTR(b, iv))
	case _AES_GCM:
		return seal(cipher.NewGCM(b))
	case _AES_OFB:
		return xor(dst, cipher.NewOFB(b, iv))
	case _ChaCha20Poly1305:
		return seal(chacha20poly1305.New(x.key))
	case _XChaCha20Poly1305:
		return seal(chacha20poly1305.NewX(x.key))
	}
}

func (x *cipherArgs) Decrypt(cip []byte) ([]byte, error) {
	var b cipher.Block
	var n int
	var iv []byte
	switch x.cipherMode {
	case _AES_CBC, _AES_CFB, _AES_CTR, _AES_GCM, _AES_OFB:
		var err error
		if b, err = aes.NewCipher(x.key); err != nil {
			return nil, err
		}
		if n = b.BlockSize(); len(x.iv) == n {
			n, iv = 0, x.iv
		} else {
			iv = cip[:n]
		}
	}

	var blk = func(n int, block cipher.BlockMode) ([]byte, error) {
		var msg = make([]byte, len(cip[n:]))
		block.CryptBlocks(msg, cip[n:])
		return pkcs5trimming(n, msg), nil
	}
	var xor = func(n int, stream cipher.Stream) ([]byte, error) {
		var msg = make([]byte, len(cip[n:]))
		stream.XORKeyStream(msg, cip[n:])
		return msg, nil
	}
	var open = func(aead cipher.AEAD, err error) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		if n := aead.NonceSize(); len(x.iv) == n {
			return aead.Open(nil, x.iv, cip, x.additionalData)
		} else {
			return aead.Open(nil, cip[:n], cip[n:], x.additionalData)
		}
	}

	switch x.cipherMode {
	default:
		return nil, ErrUnimplemented
	case _AES_CBC:
		return blk(n, cipher.NewCBCDecrypter(b, iv))
	case _AES_CFB:
		return xor(n, cipher.NewCFBDecrypter(b, iv))
	case _AES_CTR:
		return xor(n, cipher.NewCTR(b, iv))
	case _AES_GCM:
		return open(cipher.NewGCM(b))
	case _AES_OFB:
		return xor(n, cipher.NewOFB(b, iv))
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
	return slices.Concat(p, bytes.Repeat([]byte{byte(m)}, m))
}

func pkcs5trimming(_ int, p []byte) []byte {
	m := p[len(p)-1]
	return p[:len(p)-int(m)]
}
