package pkg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

var Ed25519 ed25519Args

type ed25519Args struct {
	digest
	hash crypto.Hash
}

func (x ed25519Args) SignatureSize() int { return ed25519.SignatureSize }

func (x ed25519Args) Signer(pub ed25519.PublicKey, key ed25519.PrivateKey, opts *ed25519.Options) Signer {
	x.hash = Val(opts).Hash
	return implSigner[ed25519Args]{
		metadata:   x,
		implVerify: x.Verifier(pub, opts).Verify,
		implSign: func(msg []byte) ([]byte, error) {
			if len(key) != ed25519.PrivateKeySize {
				return nil, ErrorStr("invalid key")
			}
			if opts == nil {
				return ed25519.Sign(key, msg), nil
			}
			if opts.Hash == crypto.SHA512 {
				msg = x.Digest(opts.Hash, msg)
			} else {
				opts.Hash = 0
			}
			return key.Sign(rand.Reader, msg, opts)
		},
	}
}

func (x ed25519Args) Verifier(pub ed25519.PublicKey, opts *ed25519.Options) Verifier {
	x.hash = Val(opts).Hash
	return implSigner[ed25519Args]{
		metadata: x,
		implVerify: func(msg, sig []byte) error {
			if len(pub) != ed25519.PublicKeySize {
				return ErrorStr("invalid key")
			} else if len(sig) != ed25519.SignatureSize {
				return ErrorStr("invalid sig")
			}
			if opts == nil {
				return map[bool]error{false: ErrorStr("invalid sig")}[ed25519.Verify(pub, msg, sig)]
			}
			if opts.Hash == crypto.SHA512 {
				msg = x.Digest(opts.Hash, msg)
			} else {
				opts.Hash = 0
			}
			return ed25519.VerifyWithOptions(pub, msg, sig, opts)
		},
		implSign: nil,
	}
}

// GenerateKey generates a public/private key pair using entropy from random.
//
// If random is nil, a secure random source is used. (Before Go 1.26, a custom
// [crypto/rand.Reader] was used if set by the application. That behavior can be
// restored with GODEBUG=cryptocustomrand=1. This setting will be removed in a
// future Go release. Instead, use [testing/cryptotest.SetGlobalRandom].)
//
// The output of this function is deterministic, and equivalent to reading
// [SeedSize] bytes from random, and passing them to [NewKeyFromSeed].
func (ed25519Args) GenerateKey(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(random)
}

type Ed25519PrivateKey = ed25519.PrivateKey
type Ed25519PublicKey = ed25519.PublicKey
