package pkg

import "golang.org/x/crypto/chacha20poly1305"

func ChaCha20Poly1305(key, iv, add []byte) (Cipher, error) {
	z, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return (aead{}).Cipher(z, iv, add), nil
}

func XChaCha20Poly1305(key, iv, add []byte) (Cipher, error) {
	z, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return (aead{}).Cipher(z, iv, add), nil
}
