package pkg

import (
	"crypto"
	"crypto/hkdf"
	"strings"
)

func HKDF(salt salt, info []byte, tagLength int, hash crypto.Hash) Hasher {
	return implCompareHash{&hkdfArgs{salt, info, tagLength, hash}}
}

func HKDFDefaultOpts(l int, i []byte) (salt salt, info []byte, tagLength int, hash crypto.Hash) {
	salt = Nonce(16) //
	info = i
	tagLength = l
	hash = crypto.SHA256
	return
}

type hkdfArgs struct {
	salt
	info      []byte
	tagLength int
	hash      crypto.Hash
}

func (x *hkdfArgs) Tag(plain []byte) ([]byte, error) {
	return hkdf.Key(x.hash.New, plain, x.salt, string(x.info), x.tagLength)
}

func (x hkdfArgs) MarshalText() ([]byte, error) {
	if _, err := Validate(&x); err != nil {
		return nil, err
	}
	return []byte(Sprintf("$%s_%s$%s$%s$",
		"hkdf",
		strings.ReplaceAll(strings.ToLower(x.hash.String()), "-", ""),
		btoa(x.info),
		btoa(x.salt), // salt
	)), nil
}

func (x *hkdfArgs) UnmarshalText(hash []byte) error {
	hashStr := string(hash)
	hashPart := strings.Split(strings.ReplaceAll(hashStr, "_", "$"), "$")
	if len(hashPart) != 6 {
		return Errorf("len(hashPart) != 6 (%d)", len(hashPart))
	}
	if len(hashPart[0]) > 0 {
		return ErrorStr("len(hashPart[0]) > 0")
	}
	if hashPart[1] != "hkdf" {
		return ErrorStr("hashPart[1] != hkdf")
	}
	y := &hkdfArgs{}
	for v := crypto.Hash(1); v < crypto.Hash(20); v++ {
		if hashPart[2] == strings.ReplaceAll(strings.ToLower(v.String()), "-", "") {
			y.hash = v
			break
		}
	}
	if y.hash == 0 {
		return Errorf("invalid hash (%s)", hashPart[2])
	}

	var err error
	if y.info, err = atob(hashPart[3]); err != nil {
		return Errorf("unable to set info (%w)", err)
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

func (x *hkdfArgs) Validate() error {
	if len(x.salt) < 8 {
		return ErrorStr("insecure salt length")
	}
	return nil
}
