package pkg

import (
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"hash"
)

var HMAC hmacArgs

func (x hmacArgs) Signer(h crypto.Hash, key []byte) Signer {
	x = hmacArgs{h, func() hash.Hash { return hmac.New(h.New, key) }}
	sign := func(msg []byte) ([]byte, error) {
		h := x.hmac()
		if _, err := h.Write(msg); err != nil {
			return nil, err
		}
		return h.Sum(nil), nil
	}
	return implSigner[hmacArgs]{
		metadata: x,
		implVerify: func(msg, sig []byte) error {
			if q, err := sign(msg); err != nil {
				return err
			} else if subtle.ConstantTimeCompare(q, sig) != 1 {
				return ErrorStr("invalid signature")
			}
			return nil
		},
		implSign: sign,
	}
}

type hmacArgs struct {
	hash crypto.Hash
	hmac func() hash.Hash
}
