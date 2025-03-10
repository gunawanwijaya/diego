package pkg

import (
	"crypto"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
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

// ---------------------------------------------------------------------------------------------------------------------

// Argon2I
func Argon2I(salt []byte, iterations uint32, memorySizeKB uint32, parallelism uint8, tagLength uint32) Hasher {
	return &argon2Args{salt, parallelism, tagLength, memorySizeKB, iterations, [1]byte{_ARGON2_VERSION}, nil, nil, 1}
}

// Argon2ID
func Argon2ID(salt []byte, iterations uint32, memorySizeKB uint32, parallelism uint8, tagLength uint32) Hasher {
	return &argon2Args{salt, parallelism, tagLength, memorySizeKB, iterations, [1]byte{_ARGON2_VERSION}, nil, nil, 2}
}

func Argon2DefaultOpts(l uint32) (salt []byte, iterations uint32, memorySizeKB uint32, parallelism uint8, tagLength uint32) {
	salt = Nonce(16)       //
	iterations = 3         // 1|3
	memorySizeKB = 1 << 16 // 2^21|2^16
	parallelism = 4        //
	tagLength = l          //
	return
}

const (
	_ARGON2_VERSION byte = 19
)

type argon2Args struct {
	// _           []byte  // (P) Bytes  (0..2^32-1)    Password (or message) to be hashed

	salt           []byte  // (S) Bytes  (8..2^32-1)    Salt (16 bytes recommended for password hashing) // ( )
	parallelism    uint8   // (p) Number (1..2^24-1)    Degree of parallelism (i.e. number of threads)   // (p) Parallelism  -> threads
	tagLength      uint32  // (T) Number (4..2^32-1)    Desired number of returned bytes                 // ( ) TagLength    -> keyLen
	memorySizeKB   uint32  // (m) Number (8*p..2^32-1)  Amount of memory (in kibibytes) to use           // (m) MemorySizeKB -> memory
	iterations     uint32  // (t) Number (1..2^32-1)    Number of iterations to perform                  // (t) Iterations   -> time
	version        [1]byte // (v) Number (0x13)         The current version is 0x13 (19 decimal)         // (v)
	key            []byte  // (K) Bytes  (0..2^32-1)    Optional key (Errata: PDF says 0..32 bytes, RFC says 0..232 bytes)
	associatedData []byte  // (X) Bytes  (0..2^32-1)    Optional arbitrary extra data
	hashType       int     // (y) Number (0=Argon2d, 1=Argon2i, 2=Argon2id)

	// _           []byte  //     Bytes  (tagLength)    The resulting generated bytes, tagLength bytes long
}

func (x *argon2Args) Compare(plain []byte, hash []byte) error {
	return compareHash(plain, hash, x)
}

func (x *argon2Args) Hash(plain []byte) ([]byte, error) {
	hash, err := x.MarshalText()
	if err != nil {
		return nil, err
	}
	tag, err := x.Tag(plain)
	if err != nil {
		return nil, err
	}
	x.salt = Nonce(len(x.salt)) // replace old salt
	return slices.Concat(hash, []byte(btoa(tag))), nil
}

func (x *argon2Args) Tag(plain []byte) ([]byte, error) {
	switch x.hashType {
	default:
		return nil, ErrUnimplemented
	case 1:
		return argon2.Key(plain, x.salt, x.iterations, x.memorySizeKB, x.parallelism, x.tagLength), nil
	case 2:
		return argon2.IDKey(plain, x.salt, x.iterations, x.memorySizeKB, x.parallelism, x.tagLength), nil
	}
}

func (x argon2Args) MarshalText() ([]byte, error) {
	if _, err := Validate(&x); err != nil {
		return nil, err
	}

	return []byte(Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$",
		map[int]string{0: "argon2d", 1: "argon2i", 2: "argon2id"}[x.hashType],
		_ARGON2_VERSION, // v
		x.memorySizeKB,  // m
		x.iterations,    // t
		x.parallelism,   // p
		btoa(x.salt),    // salt
	)), nil
}

func (x *argon2Args) UnmarshalText(hash []byte) error {
	hashStr := string(hash)
	hashPart := strings.Split(strings.ReplaceAll(hashStr, ",", "$"), "$")
	if len(hashPart) != 8 {
		return Errorf("len(hashPart) != 8 (%d)", len(hashPart))
	}
	if len(hashPart[0]) > 0 {
		return ErrorStr("len(hashPart[0]) > 0")
	}

	ok, y := false, &argon2Args{}
	if y.hashType, ok = map[string]int{"argon2d": 0, "argon2i": 1, "argon2id": 2}[hashPart[1]]; !ok {
		return ErrorStr("unable to set hashType")
	}

	for _, v := range []string{hashPart[2], hashPart[3], hashPart[4], hashPart[5]} {
		var i int
		var err error
		if strings.HasPrefix(v, "v=") && y.version[0] < 1 {
			if i, err = strconv.Atoi(v[2:]); err != nil {
				return Errorf("unable to set version (%w)", err)
			}
			y.version = [1]byte{byte(i)}
		} else if strings.HasPrefix(v, "m=") && y.memorySizeKB < 1 {
			if i, err = strconv.Atoi(v[2:]); err != nil {
				return Errorf("unable to set memorySizeKB (%w)", err)
			}
			y.memorySizeKB = uint32(i)
		} else if strings.HasPrefix(v, "t=") && y.iterations < 1 {
			if i, err = strconv.Atoi(v[2:]); err != nil {
				return Errorf("unable to set iterations (%w)", err)
			}
			y.iterations = uint32(i)
		} else if strings.HasPrefix(v, "p=") && y.parallelism < 1 {
			if i, err = strconv.Atoi(v[2:]); err != nil {
				return Errorf("unable to set parallelism (%w)", err)
			}
			y.parallelism = uint8(i)
		}
	}
	if y.version[0] < 1 {
		return ErrorStr("unable to set version")
	} else if y.memorySizeKB < 1 {
		return ErrorStr("unable to set memorySizeKB")
	} else if y.iterations < 1 {
		return ErrorStr("unable to set iterations")
	} else if y.parallelism < 1 {
		return ErrorStr("unable to set parallelism")
	}

	var err error
	if y.salt, err = atob(hashPart[6]); err != nil {
		return Errorf("unable to set salt (%w)", err)
	}
	var tag []byte
	if tag, err = atob(hashPart[7]); err != nil {
		return Errorf("unable to set tag (%w)", err)
	}
	x.salt, y.tagLength = y.salt, uint32(len(tag))
	return y.Validate()
}

func (x *argon2Args) Validate() error {
	if x.hashType != 1 && x.hashType != 2 {
		return ErrorStr("x.HashType != 1 && x.HashType != 2")
	}
	if x.version[0] != _ARGON2_VERSION {
		return ErrorStr("x.version[0] != _ARGON2_VERSION")
	}
	if x.memorySizeKB < uint32(8*x.parallelism) {
		return ErrorStr("x.MemorySizeKB < 8*x.Parallelism")
	}
	if x.iterations < 1 {
		return ErrorStr("x.Iterations < 1")
	}
	if x.parallelism < 1 || x.parallelism >= 2^24 {
		return ErrorStr("x.Parallelism < 1 || x.Parallelism >= 2^24")
	}
	if len(x.salt) < 8 {
		return ErrorStr("len(x.Salt) < 8")
	}
	if x.tagLength < 4 {
		return ErrorStr("x.TagLength < 4")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------

// PBKDF2
func PBKDF2(salt []byte, iterations int, tagLength int, hash crypto.Hash) Hasher {
	return &pbkdf2Args{salt, iterations, tagLength, hash}
}

func PBKDF2DefaultOpts(l int) (salt []byte, iterations int, tagLength int, hash crypto.Hash) {
	salt = Nonce(16) //
	iterations = 10_000
	tagLength = l
	hash = crypto.SHA256
	return
}

type pbkdf2Args struct {
	salt       []byte
	iterations int
	tagLength  int
	hash       crypto.Hash
}

func (x *pbkdf2Args) Compare(plain []byte, hash []byte) error {
	return compareHash(plain, hash, x)
}

func (x *pbkdf2Args) Hash(plain []byte) ([]byte, error) {
	hash, err := x.MarshalText()
	if err != nil {
		return nil, err
	}
	tag, err := x.Tag(plain)
	if err != nil {
		return nil, err
	}
	x.salt = Nonce(len(x.salt)) // replace old salt
	return slices.Concat(hash, []byte(btoa(tag))), nil
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

// ---------------------------------------------------------------------------------------------------------------------

// HKDF
func HKDF(salt []byte, info []byte, tagLength int, hash crypto.Hash) Hasher {
	return &hkdfArgs{salt, info, tagLength, hash}
}

func HKDFDefaultOpts(l int, i []byte) (salt []byte, info []byte, tagLength int, hash crypto.Hash) {
	salt = Nonce(16) //
	info = i
	tagLength = l
	hash = crypto.SHA256
	return
}

type hkdfArgs struct {
	salt      []byte
	info      []byte
	tagLength int
	hash      crypto.Hash
}

func (x *hkdfArgs) Compare(plain []byte, hash []byte) error {
	return compareHash(plain, hash, x)
}

func (x *hkdfArgs) Hash(plain []byte) ([]byte, error) {
	hash, err := x.MarshalText()
	if err != nil {
		return nil, err
	}
	tag, err := x.Tag(plain)
	if err != nil {
		return nil, err
	}
	x.salt = Nonce(len(x.salt)) // replace old salt
	return slices.Concat(hash, []byte(btoa(tag))), nil
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

// ---------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------

var atob = base64.RawStdEncoding.Strict().DecodeString
var btoa = base64.RawStdEncoding.Strict().EncodeToString

func compareHash(plain []byte, hash []byte, x ...interface {
	Hasher
	encoding.TextUnmarshaler
}) error {
	for _, x := range x {
		if err := x.UnmarshalText(hash); err == nil {
			var p []byte
			if p, err = x.Hash(plain); err == nil {
				if subtle.ConstantTimeCompare(p, hash) == 1 {
					return nil
				}
			}
		}
	}
	return ErrorStr("invalid compare")
}
