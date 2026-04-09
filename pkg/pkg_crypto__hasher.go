package pkg

import (
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"slices"
)

type Tagger interface {
	Tag(plain []byte) ([]byte, error)
	Validator
}

type Hasher interface {
	Compare(plain []byte, hash []byte) error
	Hash(plain []byte) ([]byte, error)
	Tagger
}

var _ Hasher = NopHasher{}

type NopHasher struct{}

func (NopHasher) Tag([]byte) ([]byte, error)   { return nil, ErrUnimplemented }
func (NopHasher) Hash([]byte) ([]byte, error)  { return nil, ErrUnimplemented }
func (NopHasher) Compare([]byte, []byte) error { return ErrUnimplemented }
func (NopHasher) Validate() error              { return ErrUnimplemented }

type KeyWrapper interface {
	Unwrap(wrappedKey []byte) ([]byte, error)
	Wrap(key []byte) ([]byte, error)
	Validator
}

type implKeyWrapper[T any] struct {
	metadata T
	implUnwrap
	implWrap
}

type implUnwrap func(wrappedKey []byte) ([]byte, error)
type implWrap func(key []byte) ([]byte, error)

func (f implUnwrap) Unwrap(wrappedKey []byte) ([]byte, error) { return f(wrappedKey) }
func (f implWrap) Wrap(key []byte) ([]byte, error)            { return f(key) }

func (x implKeyWrapper[T]) Validate() error {
	key := Nonce(32)
	if x.implUnwrap == nil || x.implWrap == nil {
		return ErrUnimplemented
	} else if wrappedKey, err := x.Wrap(key); err != nil {
		return err
	} else if subtle.ConstantTimeCompare(key, wrappedKey) == 1 {
		return ErrorStr("invalid key wrapper")
	} else if unwrappedKey, err := x.Unwrap(wrappedKey); err != nil {
		return err
	} else if subtle.ConstantTimeCompare(key, unwrappedKey) != 1 {
		return ErrorStr("invalid key wrapper")
	}
	return nil
}

var atob = base64.RawStdEncoding.Strict().DecodeString
var btoa = base64.RawStdEncoding.Strict().EncodeToString

type extendedTagger interface {
	Tagger
	encoding.TextMarshaler
	encoding.TextUnmarshaler
	recalculateSalt()
}

type implCompareHash struct {
	extendedTagger
}

func (x implCompareHash) Compare(plain []byte, hash []byte) error {
	errCompare := ErrorStr("invalid compare")
	if x.extendedTagger == nil {
		return errCompare
	} else if err := x.UnmarshalText(hash); err != nil {
		return errCompare
	} else if p, err := x.Hash(plain); err != nil {
		return errCompare
	} else if subtle.ConstantTimeCompare(p, hash) != 1 {
		return errCompare
	}
	return nil
}

func (x implCompareHash) Hash(plain []byte) ([]byte, error) {
	hash, err := x.MarshalText()
	if err != nil {
		return nil, err
	}
	tag, err := x.Tag(plain)
	if err != nil {
		return nil, err
	}
	x.recalculateSalt()
	return slices.Concat(hash, []byte(btoa(tag))), nil

}

type salt []byte

func (s *salt) recalculateSalt() { *s = Nonce(len(*s)) }
