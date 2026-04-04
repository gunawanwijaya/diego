package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"slices"
)

var AES aesArgs

type aesArgs struct {
	pkcs5
	iv
	aead
}

func (x aesArgs) CBC(key, iv []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return implCipher[aesArgs]{
		metadata: x,
		implEncrypt: func(msg []byte) ([]byte, error) {
			n, dst, niv := x.buildCache(block.BlockSize(), iv)
			msgPad := x.Padding(n, msg)
			cip := make([]byte, len(msgPad))
			cipher.NewCBCEncrypter(block, niv).CryptBlocks(cip, msgPad)
			return slices.Concat(dst, cip), nil
		},
		implDecrypt: func(cip []byte) ([]byte, error) {
			n, niv, cip := x.parseFromCiphertext(block.BlockSize(), iv, cip)
			msg := make([]byte, len(cip))
			cipher.NewCBCDecrypter(block, niv).CryptBlocks(msg, cip)
			return x.Trimming(n, msg), nil
		},
	}, nil
}

func (x aesArgs) CTR(key, iv []byte, r io.Reader, w io.Writer) (CipherStream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return struct {
		implCipher[aesArgs]
		implIOReader
		implIOWriter
	}{implCipher: implCipher[aesArgs]{
		metadata: x,
		implEncrypt: func(msg []byte) ([]byte, error) {
			_, dst, niv := x.buildCache(block.BlockSize(), iv)
			cip := make([]byte, len(msg))
			cipher.NewCTR(block, niv).XORKeyStream(cip, msg)
			return slices.Concat(dst, cip), nil
		},
		implDecrypt: func(cip []byte) ([]byte, error) {
			_, niv, cip := x.parseFromCiphertext(block.BlockSize(), iv, cip)
			msg := make([]byte, len(cip))
			cipher.NewCTR(block, niv).XORKeyStream(msg, cip)
			return msg, nil
		},
	},
		implIOReader: func(p []byte) (n int, err error) {
			if r == nil {
				return 0, ErrorStr("invalid Reader")
			} else if len(iv) != block.BlockSize() {
				return 0, ErrorStr("invalid iv")
			} else {
				n, err := r.Read(p)
				buf := make([]byte, n)
				cipher.NewCTR(block, iv).XORKeyStream(buf, p[:n])
				copy(p, buf)
				return n, err
			}
		},
		implIOWriter: func(p []byte) (n int, err error) {
			if w == nil {
				return 0, ErrorStr("invalid Writer")
			} else if len(iv) != block.BlockSize() {
				return 0, ErrorStr("invalid iv")
			} else {
				buf := make([]byte, len(p))
				cipher.NewCTR(block, iv).XORKeyStream(buf, p)
				return w.Write(buf)
			}
		},
	}, nil
}

func (x aesArgs) GCM(key, iv, add []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	z, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return x.Cipher(z, iv, add), nil
}
