package pkg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
)

var ECDSA ecdsaArgs

type ecdsaArgs struct {
	digest
	hash    crypto.Hash
	keySize int
}

func (x ecdsaArgs) Signer(key *ecdsa.PrivateKey, asn1Encoded bool) Signer {
	x.hash, x.keySize = x.info(key.Curve)
	return implSigner[ecdsaArgs]{
		metadata:   x,
		implVerify: x.Verifier(&key.PublicKey, asn1Encoded).Verify,
		implSign: func(msg []byte) ([]byte, error) {
			if asn1Encoded {
				return ecdsa.SignASN1(rand.Reader, key, x.Digest(x.hash, msg))
			}
			if r, s, err := ecdsa.Sign(rand.Reader, key, x.Digest(x.hash, msg)); err != nil {
				return nil, err
			} else {
				var sig = make([]byte, 2*x.keySize)
				_ = r.FillBytes(sig[:x.keySize])
				_ = s.FillBytes(sig[x.keySize:])
				return sig, nil
			}
		},
	}
}

func (x ecdsaArgs) Verifier(pub *ecdsa.PublicKey, asn1Encoded bool) Verifier {
	x.hash, x.keySize = x.info(pub.Curve)
	return implSigner[ecdsaArgs]{
		metadata: x,
		implVerify: func(msg []byte, sig []byte) error {
			if asn1Encoded && ecdsa.VerifyASN1(pub, x.Digest(x.hash, msg), sig) {
				return nil
			} else if !asn1Encoded && len(sig) == 2*x.keySize {
				var r = big.NewInt(0).SetBytes(sig[:x.keySize])
				var s = big.NewInt(0).SetBytes(sig[x.keySize:])
				if ecdsa.Verify(pub, x.Digest(x.hash, msg), r, s) {
					return nil
				}
			}
			return ErrorStr("invalid sig")
		},
		implSign: nil,
	}
}

func (ecdsaArgs) info(c elliptic.Curve) (crypto.Hash, int) {
	var v = map[elliptic.Curve]struct {
		crypto.Hash
		int
	}{
		elliptic.P256(): {crypto.SHA256, 32}, // = 256/8
		elliptic.P384(): {crypto.SHA384, 48}, // = 384/8
		elliptic.P521(): {crypto.SHA512, 66}, // = 521/8 + 1
	}[c]
	return v.Hash, v.int
}

// GenerateKey(elliptic.P256(), rand.Reader)
// GenerateKey generates a new ECDSA private key for the specified curve.
//
// Since Go 1.26, a secure source of random bytes is always used, and the Reader is
// ignored unless GODEBUG=cryptocustomrand=1 is set. This setting will be removed
// in a future Go release. Instead, use [testing/cryptotest.SetGlobalRandom].
func (ecdsaArgs) GenerateKey(c elliptic.Curve, r io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(c, r)
}

type ECDSAPrivateKey = ecdsa.PrivateKey
type ECDSAPublicKey = ecdsa.PublicKey
