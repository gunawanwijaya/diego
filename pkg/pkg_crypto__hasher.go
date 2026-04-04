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
