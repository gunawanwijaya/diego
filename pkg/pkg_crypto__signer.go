package pkg

import (
	"crypto"
)

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Verifier
}

type Verifier interface {
	Validator
	Verify(msg []byte, sig []byte) error
}

var _ Signer = NopSigner{}

type NopSigner struct{}

func (NopSigner) Sign([]byte) ([]byte, error) { return nil, ErrUnimplemented }
func (NopSigner) Verify([]byte, []byte) error { return ErrUnimplemented }
func (NopSigner) Validate() error             { return ErrUnimplemented }

type implSigner[T any] struct {
	metadata T
	implVerify
	implSign
}

type implSign func(msg []byte) ([]byte, error)
type implVerify func(msg []byte, sig []byte) error

func (f implSign) Sign(msg []byte) ([]byte, error)       { return f(msg) }
func (f implVerify) Verify(msg []byte, sig []byte) error { return f(msg, sig) }
func (x implSigner[T]) Validate() error {
	if x.implVerify == nil {
		return ErrUnimplemented
	} else if x.implSign == nil {
		return nil
	} else if sig, err := x.Sign([]byte("test")); err != nil {
		return ErrorStr("invalid sign")
	} else if err := x.Verify([]byte("test"), sig); err != nil {
		return ErrorStr("invalid verify")
	}
	return nil
}

type digest struct{}

func (digest) Digest(h crypto.Hash, p []byte) []byte {
	hh := h.New()
	hh.Reset()
	hh.Write(p)
	return hh.Sum(nil)
}
