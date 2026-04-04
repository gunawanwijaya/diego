package pkg

import (
	"crypto"
	"crypto/pbkdf2"
	"strconv"
	"strings"
)

func PBKDF2(salt salt, iterations int, tagLength int, hash crypto.Hash) Hasher {
	return implCompareHash{extendedTagger: &pbkdf2Args{salt, iterations, tagLength, hash}}
}

func PBKDF2DefaultOpts(l int) (salt salt, iterations int, tagLength int, hash crypto.Hash) {
	salt = Nonce(16) //
	iterations = 10_000
	tagLength = l
	hash = crypto.SHA256
	return
}

type pbkdf2Args struct {
	salt
	iterations int
	tagLength  int
	hash       crypto.Hash
}

func (x *pbkdf2Args) Tag(plain []byte) ([]byte, error) {
	return pbkdf2.Key(x.hash.New, string(plain), x.salt, x.iterations, x.tagLength)
}

func (x pbkdf2Args) MarshalText() ([]byte, error) {
	if _, err := Validate(&x); err != nil {
		return nil, err
	}

	return []byte(Sprintf("$%s_%s$%d$%s$",
		"pbkdf2",
		strings.ReplaceAll(strings.ToLower(x.hash.String()), "-", ""),
		x.iterations, // t
		btoa(x.salt), // salt
	)), nil
}

func (x *pbkdf2Args) UnmarshalText(hash []byte) error {
	hashStr := string(hash)
	hashPart := strings.Split(strings.ReplaceAll(hashStr, "_", "$"), "$")
	if len(hashPart) != 6 {
		return Errorf("len(hashPart) != 6 (%d)", len(hashPart))
	}
	if len(hashPart[0]) > 0 {
		return ErrorStr("len(hashPart[0]) > 0")
	}
	if hashPart[1] != "pbkdf2" {
		return ErrorStr("hashPart[1] != pbkdf2")
	}

	y := &pbkdf2Args{}
	for _, v := range []crypto.Hash{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	} {
		if hashPart[2] == strings.ReplaceAll(strings.ToLower(v.String()), "-", "") {
			y.hash = v
			break
		}
	}
	if y.hash == 0 {
		return Errorf("invalid hash (%s)", hashPart[2])
	}
	var err error
	if y.iterations, err = strconv.Atoi(hashPart[3]); err != nil {
		return Errorf("unable to set iterations (%w)", err)
	}

	if y.salt, err = atob(hashPart[4]); err != nil {
		return Errorf("unable to set salt (%w)", err)
	}
	var tag []byte
	if tag, err = atob(hashPart[5]); err != nil {
		return Errorf("unable to set tag (%w)", err)
	}
	x.salt, y.tagLength = y.salt, len(tag)
	return y.Validate()
}

func (x *pbkdf2Args) Validate() error {
	if len(x.salt) < 8 {
		return ErrorStr("insecure salt length")
	}
	if x.iterations < 1 {
		return ErrorStr("invalid iterations")
	}
	if _, ok := map[crypto.Hash]struct{}{
		crypto.SHA1:   {},
		crypto.SHA224: {},
		crypto.SHA256: {},
		crypto.SHA384: {},
		crypto.SHA512: {},
	}[x.hash]; !ok {
		return ErrorStr("invalid hash")
	}
	return nil
}
