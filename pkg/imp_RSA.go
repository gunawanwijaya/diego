package pkg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
)

var RSA rsaArgs

type rsaArgs struct {
	OAEP     rsaOAEPArgs
	PKCS1v15 rsaPKCS1v15Args
	PSS      rsaPSSArgs
}

type rsaOAEPArgs struct{}

func (x rsaOAEPArgs) Decrypter(key *rsa.PrivateKey, hash crypto.Hash, label []byte) Cipher {
	return implCipher[rsaOAEPArgs]{
		metadata:    x,
		implEncrypt: x.Encrypter(&key.PublicKey, hash, label).Encrypt,
		implDecrypt: func(cip []byte) ([]byte, error) {
			return rsa.DecryptOAEP(hash.New(), rand.Reader, key, cip, label)
		},
	}
}

func (x rsaOAEPArgs) Encrypter(pub *rsa.PublicKey, hash crypto.Hash, label []byte) Encrypter {
	return implCipher[rsaOAEPArgs]{
		metadata: x,
		implEncrypt: func(msg []byte) ([]byte, error) {
			return rsa.EncryptOAEP(hash.New(), rand.Reader, pub, msg, label)
		},
		implDecrypt: nil,
	}
}

type rsaPKCS1v15Args struct {
	digest
	hash crypto.Hash
}

func (x rsaPKCS1v15Args) Signer(key *rsa.PrivateKey, hash crypto.Hash) Signer {
	x.hash = hash
	return implSigner[rsaPKCS1v15Args]{
		metadata:   x,
		implVerify: x.Verifier(&key.PublicKey, hash).Verify,
		implSign: func(msg []byte) ([]byte, error) {
			return rsa.SignPKCS1v15(rand.Reader, key, hash, x.Digest(hash, msg))
		},
	}
}

func (x rsaPKCS1v15Args) Verifier(pub *rsa.PublicKey, hash crypto.Hash) Verifier {
	x.hash = hash
	return implSigner[rsaPKCS1v15Args]{
		metadata: x,
		implVerify: func(msg, sig []byte) error {
			return rsa.VerifyPKCS1v15(pub, hash, x.Digest(hash, msg), sig)
		},
		implSign: nil,
	}
}

type rsaPSSArgs struct {
	digest
	hash crypto.Hash
}

func (x rsaPSSArgs) Signer(key *rsa.PrivateKey, hash crypto.Hash, opts *rsa.PSSOptions) Signer {
	if opts == nil {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	}
	x.hash = hash
	return implSigner[rsaPSSArgs]{
		metadata:   x,
		implVerify: x.Verifier(&key.PublicKey, hash, opts).Verify,
		implSign: func(msg []byte) ([]byte, error) {
			return rsa.SignPSS(rand.Reader, key, hash, x.Digest(hash, msg), opts)
		},
	}
}

func (x rsaPSSArgs) Verifier(pub *rsa.PublicKey, hash crypto.Hash, opts *rsa.PSSOptions) Verifier {
	if opts == nil {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	}
	x.hash = hash
	return implSigner[rsaPSSArgs]{
		metadata: x,
		implVerify: func(msg, sig []byte) error {
			return rsa.VerifyPSS(pub, hash, x.Digest(hash, msg), sig, opts)
		},
		implSign: nil,
	}
}

// GenerateKey generates a random RSA private key of the given bit size.
//
// If bits is less than 1024, [GenerateKey] returns an error. See the "[Minimum
// key size]" section for further details.
//
// Since Go 1.26, a secure source of random bytes is always used, and the Reader is
// ignored unless GODEBUG=cryptocustomrand=1 is set. This setting will be removed
// in a future Go release. Instead, use [testing/cryptotest.SetGlobalRandom].
//
// [Minimum key size]: https://pkg.go.dev/crypto/rsa#hdr-Minimum_key_size
func (rsaArgs) GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(random, bits)
}

type RSAPrivateKey = rsa.PrivateKey
type RSAPublicKey = rsa.PublicKey
