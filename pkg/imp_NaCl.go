package pkg

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
)

var NaCl naclArgs

type naclArgs struct{}

func (x naclArgs) SecretBox(key *[32]byte) Cipher {
	return implCipher[naclArgs]{
		metadata: x,
		implEncrypt: func(msg []byte) ([]byte, error) {
			nonce := (*[24]byte)(Nonce(24))
			return secretbox.Seal(nonce[:], msg, nonce, key), nil
		},
		implDecrypt: func(cip []byte) ([]byte, error) {
			if len(cip) > 24 {
				nonce := (*[24]byte)(cip[:24])
				if msg, ok := secretbox.Open(nil, cip[24:], nonce, key); ok {
					return msg, nil
				}
			}
			return nil, ErrorStr("nacl: invalid encrypt/decrypt")
		},
	}
}

func (naclArgs) Box(peersPublicKey, privateKey *[32]byte) Cipher {
	var sharedKey = new([32]byte)
	box.Precompute(sharedKey, peersPublicKey, privateKey)
	return NaCl.SecretBox(sharedKey)
}

func (naclArgs) GenerateBoxKey() (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

func (naclArgs) GenerateSignKey() (publicKey *[32]byte, privateKey *[64]byte, err error) {
	return sign.GenerateKey(rand.Reader)
}

func (x naclArgs) Signer(pub *[32]byte, key *[64]byte) Signer {
	return implSigner[naclArgs]{
		metadata:   x,
		implVerify: x.Verifier(pub).Verify,
		implSign: func(msg []byte) ([]byte, error) {
			return sign.Sign(nil, msg, key), nil
		},
	}
}

func (x naclArgs) Verifier(pub *[32]byte) Verifier {
	return implSigner[naclArgs]{
		metadata: x,
		implVerify: func(msg, sig []byte) error {
			msg0, ok := sign.Open(nil, sig, pub)
			if !ok || subtle.ConstantTimeCompare(msg0, msg) != 1 {
				return ErrorStr("invalid sig")
			}
			return nil
		},
		implSign: nil,
	}
}
