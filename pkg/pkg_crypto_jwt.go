package pkg

import (
	"bytes"
	"crypto"
	"encoding/json"
	"math"
	"strconv"
	"time"
)

func NewJWT(claims json.RawMessage) *jwt {
	return &jwt{h: B64RawUrl(`{"alg":"none"}`), c: B64RawUrl(claims)}
}

type jwt struct{ h, c, s B64RawUrl }

func (x jwt) Claims() *json.Decoder { return json.NewDecoder(bytes.NewReader(x.c)) }

func (x *jwt) Sign(s Signer) error {
	if len(x.s) < 1 {
		if alg := jwtInfo(s); alg == "" {
			return ErrUnimplemented
		} else {
			x.h = B64RawUrl(`{"alg":"` + alg + `"}`)
		}
		if sig, err := s.Sign([]byte(jwt{x.h, x.c, nil}.String())); err != nil {
			return err
		} else {
			x.s = sig
		}
	}
	return nil
}

func (x jwt) String() string {
	if len(x.s) < 1 {
		return x.h.String() + "." + x.c.String()
	}
	return x.h.String() + "." + x.c.String() + "." + x.s.String()
}

func (x *jwt) UnmarshalText(p []byte) error {
	if ps := bytes.Split(p, []byte(".")); 2 <= len(ps) && len(ps) <= 3 {
		if err := x.h.UnmarshalText(ps[0]); err != nil {
			return err
		}
		if err := x.c.UnmarshalText(ps[1]); err != nil {
			return err
		}
		if len(ps) == 3 {
			if err := x.s.UnmarshalText(ps[2]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (x *jwt) Verify(v Verifier) error {
	if len(x.h) < 1 {
		return ErrUnimplemented
	}
	if len(x.c) < 1 {
		return ErrUnimplemented
	}
	if len(x.s) < 1 {
		return ErrUnimplemented
	}
	return v.Verify([]byte(jwt{x.h, x.c, nil}.String()), x.s)
}

func jwtInfo(v Verifier) string {
	switch s := v.(type) {
	default:
		return ""
	case ed25519Args:
		return "EdDSA"
	case ecdsaArgs:
		hash, _ := s.info(s.pub.Curve)
		alg := map[crypto.Hash]string{
			crypto.SHA256: "ES256",
			crypto.SHA384: "ES384",
			crypto.SHA512: "ES512",
		}[hash]
		return alg
	case hmacArgs:
		alg := map[crypto.Hash]string{
			crypto.SHA256: "HS256",
			crypto.SHA384: "HS384",
			crypto.SHA512: "HS512",
		}[s.h]
		return alg
	case rsaArgs:
		if s.mode < 2 || s.mode > 3 {
			return ""
		}
		alg := map[int]map[crypto.Hash]string{
			2: {
				crypto.SHA256: "RS256",
				crypto.SHA384: "RS384",
				crypto.SHA512: "RS512",
			},
			3: {
				crypto.SHA256: "PS256",
				crypto.SHA384: "PS384",
				crypto.SHA512: "PS512",
			},
		}[s.mode][s.hash]
		return alg
	}
}

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical use-case
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

// NewNumericDate constructs a new *NumericDate from a standard library time.Time struct.
// It will truncate the timestamp according to the precision specified in TimePrecision.
func NewNumericDate(t time.Time) *NumericDate {
	var TimePrecision = time.Second
	return &NumericDate{t.Truncate(TimePrecision)}
}

// newNumericDateFromSeconds creates a new *NumericDate out of a float64 representing a
// UNIX epoch with the float fraction representing non-integer seconds.
func newNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)
	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	// TimePrecision sets the precision of times and dates within this library. This
	// has an influence on the precision of times when comparing expiry or other
	// related time fields. Furthermore, it is also the precision of times when
	// serializing.
	//
	// For backwards compatibility the default precision is set to seconds, so that
	// no fractional timestamps are generated.
	var TimePrecision = time.Second
	var prec int
	if TimePrecision < time.Second {
		prec = int(math.Log10(float64(time.Second) / float64(TimePrecision)))
	}
	truncatedDate := date.Truncate(TimePrecision)

	// For very large timestamps, UnixNano would overflow an int64, but this
	// function requires nanosecond level precision, so we have to use the
	// following technique to get round the issue:
	//
	// 1. Take the normal unix timestamp to form the whole number part of the
	//    output,
	// 2. Take the result of the Nanosecond function, which returns the offset
	//    within the second of the particular unix time instance, to form the
	//    decimal part of the output
	// 3. Concatenate them to produce the final result
	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', prec, 64)

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and
// deserializes a [NumericDate] from a JSON representation, i.e. a
// [json.Number]. This number represents an UNIX epoch with either integer or
// non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)

	if err = json.Unmarshal(b, &number); err != nil {
		return Errorf("could not parse NumericData: %w", err)
	}

	if f, err = number.Float64(); err != nil {
		return Errorf("could not convert json number value to float: %w", err)
	}

	n := newNumericDateFromSeconds(f)
	*date = *n

	return nil
}

// ClaimStrings is basically just a slice of strings, but it can be either
// serialized from a string array or just a string. This type is necessary,
// since the "aud" claim can either be a single string or an array.
type ClaimStrings []string

func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value interface{}

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string

	switch v := value.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = ClaimStrings(v)
	case []interface{}:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return ErrUnimplemented
			}
			aud = append(aud, vs)
		}
	case nil:
		return nil
	default:
		return ErrUnimplemented
	}

	*s = aud

	return
}

func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	// MarshalSingleStringAsArray modifies the behavior of the ClaimStrings type,
	// especially its MarshalJSON function.
	//
	// If it is set to true (the default), it will always serialize the type as an
	// array of strings, even if it just contains one element, defaulting to the
	// behavior of the underlying []string. If it is set to false, it will serialize
	// to a single string, if it contains one element. Otherwise, it will serialize
	// to an array of strings.
	var MarshalSingleStringAsArray = true

	// This handles a special case in the JWT RFC. If the string array, e.g.
	// used by the "aud" field, only contains one element, it MAY be serialized
	// as a single string. This may or may not be desired based on the ecosystem
	// of other JWT library used, so we make it configurable by the variable
	// MarshalSingleStringAsArray.
	if len(s) == 1 && !MarshalSingleStringAsArray {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}
