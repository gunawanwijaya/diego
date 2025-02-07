package pkg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"slices"

	"gopkg.in/yaml.v3"
)

type KindOfPrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | *ecdh.PrivateKey
}

type KindOfPublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey | *ecdh.PublicKey
}

type KindOfAnyKey interface {
	[]byte | KindOfPrivateKey | KindOfPublicKey
}

// ---------------------------------------------------------------------------------------------------------------------

// JWKS
type JWKS []JWKish

func (x JWKS) MarshalJSON() ([]byte, error) {
	if x == nil {
		x = make(JWKS, 0)
	}
	return json.Marshal([]JWKish(x))
}
func (x *JWKS) UnmarshalJSON(p []byte) error {
	var v []jwk_field
	if err := json.Unmarshal(p, &v); err != nil {
		return err
	}
	var errs []error
	for _, e := range v {
		// var k JWKish
		if k, err := e.jwk(); err == nil && k != nil {
			if p, err = json.Marshal(e); err == nil {
				if err = json.Unmarshal(p, k); err == nil {
					*x = append(*x, k)
				}
			}
		} else {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		*x = []JWKish{}
		return err
	}
	return nil
}

type JWKish interface {
	As(v any) (ok bool)
	Bytes() []byte
	KID() string
	encoding.BinaryMarshaler
	json.Marshaler
	encoding.TextMarshaler
	yaml.Marshaler
	PublicKey() JWKish
	encoding.BinaryUnmarshaler
	json.Unmarshaler
	encoding.TextUnmarshaler
	yaml.Unmarshaler
	X5C() []*x509.Certificate
	X5T() []byte
	X5TS256() []byte
}

// ---------------------------------------------------------------------------------------------------------------------

// JWK
type JWK[T KindOfAnyKey] struct {
	Key T

	pub JWKish
	kid string
	x5c []*x509.Certificate
}

func NewJWK[T KindOfAnyKey](key T) *JWK[T] { return &JWK[T]{Key: key} }

func (x *JWK[T]) WithKID(kid string) *JWK[T] { x.kid = kid; return x }

func (x *JWK[T]) WithX5C(x5c ...*x509.Certificate) *JWK[T] { x.x5c = x5c; return x }

func (x *JWK[T]) WithPublicKey(pub JWKish) *JWK[T] {
	if x.PublicKey() == nil {
		x.pub = pub
	}
	return x
}

func (x JWK[T]) As(v any) bool {
	switch v := v.(type) {
	case *T:
		if ok := (nil != x.Key); ok {
			*v = x.Key
			return ok
		}
	}
	return false
}

func (x JWK[T]) PublicKey() JWKish {
	switch k := any(x.Key).(type) {
	default:
		return x.pub
	case *rsa.PrivateKey:
		return NewJWK(&k.PublicKey)
	case *ecdsa.PrivateKey:
		return NewJWK(&k.PublicKey)
	case ed25519.PrivateKey:
		return NewJWK(k.Public().(ed25519.PublicKey))
	case *ecdh.PrivateKey:
		return NewJWK(k.PublicKey())
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		return &x
	}
}

func (x JWK[T]) KID() string { return x.kid }

func (x JWK[T]) X5C() []*x509.Certificate { return x.x5c }

func (x JWK[T]) X5T() []byte {
	if len(x.x5c) > 0 {
		s := sha1.Sum(x.x5c[0].Raw)
		return s[:]
	}
	return nil
}

func (x JWK[T]) X5TS256() []byte {
	if len(x.x5c) > 0 {
		s := sha256.Sum256(x.x5c[0].Raw)
		return s[:]
	}
	return nil
}

func (x JWK[T]) MarshalJSON() ([]byte, error) {
	if x.Key == nil {
		return nil, ErrUnimplemented
	}
	var (
		v        jwk_field
		ecdsaPub = func(k *ecdsa.PublicKey) (p *elliptic.CurveParams, kty jwk_KTY, crv string, x, y []byte, err error) {
			if k.Curve == elliptic.P224() {
				err = ErrUnimplemented
				return
			}
			p = k.Curve.Params()
			l := uint(p.BitSize / 8)
			if p.BitSize%8 != 0 {
				l++
			}
			kty = jwk_KTY_EC
			crv = p.Name
			x = k.X.FillBytes(make([]byte, l))
			y = k.Y.FillBytes(make([]byte, l))
			return
		}
		ecdhPub = func(k *ecdh.PublicKey) (p *elliptic.CurveParams, kty jwk_KTY, crv string, x, y []byte, err error) {
			kc := k.Curve()
			if kc == ecdh.X25519() {
				kty = jwk_KTY_OKP
				crv = Sprintf("%s", k.Curve())
				x = k.Bytes()
				return
			}

			c, ok := map[ecdh.Curve]elliptic.Curve{
				ecdh.P256(): elliptic.P256(),
				ecdh.P384(): elliptic.P384(),
				ecdh.P521(): elliptic.P521(),
			}[kc]
			if !ok {
				err = ErrUnimplemented
				return
			}
			kx, ky := elliptic.Unmarshal(c, k.Bytes())
			if kx == nil || ky == nil {
				err = ErrUnimplemented
				return
			}
			return ecdsaPub(&ecdsa.PublicKey{Curve: c, X: kx, Y: ky})
		}
	)
	switch k := any(x.Key).(type) {
	case *rsa.PrivateKey:
		if _, err := Validate(k); err != nil {
			return nil, err
		}
		p := k.PublicKey
		v.KTY = jwk_KTY_RSA
		v.E = big.NewInt(int64(p.E)).Bytes()
		v.N = p.N.Bytes()
		v.D = k.D.Bytes()
		v.P = k.Primes[0].Bytes()
		v.Q = k.Primes[1].Bytes()
		v.DP = k.Precomputed.Dp.Bytes()
		v.DQ = k.Precomputed.Dq.Bytes()
		v.QI = k.Precomputed.Qinv.Bytes()
		if crt := k.Precomputed.CRTValues; len(crt) > 0 {
			v.OTH = make([]jwk_field_OTH, len(crt))
			for i := range len(crt) {
				v.OTH[i] = jwk_field_OTH{
					R: k.Primes[2+i].Bytes(),
					D: crt[i].Exp.Bytes(),
					T: crt[i].Coeff.Bytes(),
				}
			}
		}
	case *ecdsa.PrivateKey:
		var p *elliptic.CurveParams
		var err error
		if p, v.KTY, v.CRV, v.X, v.Y, err = ecdsaPub(&k.PublicKey); err != nil {
			return nil, err
		}
		f, _ := p.N.Float64()
		l := int(math.Ceil(math.Log2(f) / 8))
		v.D = k.D.FillBytes(make([]byte, l))
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, Errorf("invalid len (%d)", len(k))
		}
		n := ed25519.PrivateKeySize - ed25519.PublicKeySize
		v.KTY = jwk_KTY_OKP
		v.CRV = jwk_CRV_Ed25519
		v.X = B64RawUrl(k[n:])
		v.D = B64RawUrl(k[:n])
	case *ecdh.PrivateKey:
		var err error
		if _, v.KTY, v.CRV, v.X, v.Y, err = ecdhPub(k.PublicKey()); err != nil {
			return nil, err
		}
		v.D = k.Bytes()
	case *rsa.PublicKey:
		v.KTY = jwk_KTY_RSA
		v.E = big.NewInt(int64(k.E)).Bytes()
		v.N = k.N.Bytes()
	case *ecdsa.PublicKey:
		var err error
		if _, v.KTY, v.CRV, v.X, v.Y, err = ecdsaPub(k); err != nil {
			return nil, err
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, Errorf("invalid len (%d)", len(k))
		}
		v.KTY = jwk_KTY_OKP
		v.CRV = jwk_CRV_Ed25519
		v.X = B64RawUrl(k)
	case *ecdh.PublicKey:
		var err error
		if _, v.KTY, v.CRV, v.X, v.Y, err = ecdhPub(k); err != nil {
			return nil, err
		}
	case []byte:
		v.KTY = jwk_KTY_oct
		v.K = k
	default:
		return nil, ErrUnimplemented
	}
	v.KID = x.kid
	for i, c := range x.x5c {
		if v.X5C = append(v.X5C, c.Raw); i == 0 {
			p1, p2 := sha1.Sum(c.Raw), sha256.Sum256(c.Raw)
			v.X5T, v.X5TS256 = p1[:], p2[:]
		}
	}
	return json.Marshal(v)
}

func (x *JWK[T]) UnmarshalJSON(p []byte) error {
	var (
		v        jwk_field
		ecdsaPub = func(crv string, x, y B64RawUrl) (pub *ecdsa.PublicKey, err error) {
			c, ok := map[string]elliptic.Curve{
				elliptic.P256().Params().Name: elliptic.P256(),
				elliptic.P384().Params().Name: elliptic.P384(),
				elliptic.P521().Params().Name: elliptic.P521(),
			}[crv]
			if !ok {
				return nil, Errorf("invalid crv (%s)", crv)
			}

			return &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			}, nil
		}
		ecdhPub = func(crv string, x, y B64RawUrl) (pub *ecdh.PublicKey, err error) {
			var p *ecdsa.PublicKey
			if p, err = ecdsaPub(crv, x, y); err != nil {
				return nil, err
			}
			return p.ECDH()
		}
	)
	if err := json.Unmarshal(p, &v); err != nil {
		return err
	}
	switch k := any(x.Key).(type) {
	case *rsa.PrivateKey:
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_RSA:
			k = &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: new(big.Int).SetBytes(v.N),
					E: int(new(big.Int).SetBytes(v.E).Int64()),
				},
				D: new(big.Int).SetBytes(v.D),
				Primes: []*big.Int{
					new(big.Int).SetBytes(v.P),
					new(big.Int).SetBytes(v.Q),
				},
				Precomputed: rsa.PrecomputedValues{
					Dp:   new(big.Int).SetBytes(v.DP),
					Dq:   new(big.Int).SetBytes(v.DQ),
					Qinv: new(big.Int).SetBytes(v.QI),
				},
			}
			for _, v := range v.OTH {
				k.Primes = append(
					k.Primes, new(big.Int).SetBytes(v.R),
				)
				k.Precomputed.CRTValues = append(k.Precomputed.CRTValues, rsa.CRTValue{
					Exp:   new(big.Int).SetBytes(v.D),
					Coeff: new(big.Int).SetBytes(v.T),
					R:     new(big.Int).SetBytes(v.R),
				})
			}
			k.Precompute()
			if _, err := Validate(k); err != nil {
				return err
			}
		}
		x.Key = any(k).(T)
	case *ecdsa.PrivateKey:
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_EC:
			p, err := ecdsaPub(v.CRV, v.X, v.Y)
			if err != nil {
				return err
			}
			k = &ecdsa.PrivateKey{
				PublicKey: *p,
				D:         new(big.Int).SetBytes(v.D),
			}
		}
		x.Key = any(k).(T)
	case ed25519.PrivateKey:
		if v.KTY != jwk_KTY_OKP {
			return Errorf("invalid kty (%s)", v.KTY)
		}
		if v.CRV != jwk_CRV_Ed25519 {
			return Errorf("invalid crv (%s)", v.CRV)
		}
		if len(v.X) != ed25519.PublicKeySize {
			return Errorf("invalid len (%d)", len(v.X))
		}
		if len(v.X)+len(v.D) != ed25519.PrivateKeySize {
			return Errorf("invalid len (%d)", len(v.X)+len(v.D))
		}
		k = ed25519.PrivateKey(slices.Concat(v.D, v.X))
		x.Key = any(k).(T)
	case *ecdh.PrivateKey:
		var p *ecdh.PublicKey
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_OKP:
			if v.CRV != Sprintf("%s", ecdh.X25519()) {
				return Errorf("invalid crv (%s)", v.CRV)
			}
			var err error
			if k, err = ecdh.X25519().NewPrivateKey(v.D); err != nil {
				return err
			}
		case jwk_KTY_EC:
			var err error
			if p, err = ecdhPub(v.CRV, v.X, v.Y); err != nil {
				return err
			}
			if k, err = p.Curve().NewPrivateKey(v.D); err != nil {
				return err
			}
		}
		x.Key = any(k).(T)
	case *rsa.PublicKey:
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_RSA:
			k = &rsa.PublicKey{
				N: new(big.Int).SetBytes(v.N),
				E: int(new(big.Int).SetBytes(v.E).Int64()),
			}
		}
		x.Key = any(k).(T)
	case *ecdsa.PublicKey:
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_EC:
			var err error
			if k, err = ecdsaPub(v.CRV, v.X, v.Y); err != nil {
				return err
			}
		}
		x.Key = any(k).(T)
	case ed25519.PublicKey:
		if v.KTY != jwk_KTY_OKP {
			return Errorf("invalid kty (%s)", v.KTY)
		}
		if v.CRV != jwk_CRV_Ed25519 {
			return Errorf("invalid crv (%s)", v.CRV)
		}
		if len(v.X) != ed25519.PublicKeySize {
			return Errorf("invalid len (%d)", len(v.X))
		}
		k = ed25519.PublicKey(v.X)
		x.Key = any(k).(T)
	case *ecdh.PublicKey:
		switch v.KTY {
		default:
			return Errorf("invalid kty (%s)", v.KTY)
		case jwk_KTY_OKP:
			if v.CRV != Sprintf("%s", ecdh.X25519()) {
				return Errorf("invalid crv (%s)", v.CRV)
			}
			var err error
			if k, err = ecdh.X25519().NewPublicKey(v.X); err != nil {
				return err
			}
		case jwk_KTY_EC:
			var err error
			if k, err = ecdhPub(v.CRV, v.X, v.Y); err != nil {
				return err
			}
		}
		x.Key = any(k).(T)
	case []byte:
		if v.KTY != jwk_KTY_oct {
			return Errorf("invalid kty (%s)", v.KTY)
		}
		k = v.K
		x.Key = any(k).(T)
	default:
		_ = k
		return ErrUnimplemented
	}
	x.kid = v.KID
	for i, c := range v.X5C {
		if i == 0 {
			if p1 := sha1.Sum(c); len(v.X5T) > 0 && !bytes.Equal(v.X5T, p1[:]) {
				return Errorf("invalid x5t thumbprint %s", v.X5T)
			}
			if p2 := sha256.Sum256(c); len(v.X5TS256) > 0 && !bytes.Equal(v.X5TS256, p2[:]) {
				return Errorf("invalid x5t#s256 thumbprint %s", v.X5TS256)
			}
		}
		x5c, err := x509.ParseCertificate(c)
		if err != nil {
			return err
		}
		x.x5c = append(x.x5c, x5c)
	}
	return nil
}

func (x JWK[T]) MarshalBinary() ([]byte, error) {
	switch k := any(x.Key).(type) {
	default:
		return nil, ErrorStr("invalid dst")
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(k)
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case []byte:
		return k, nil
	}
}

func (x *JWK[T]) UnmarshalBinary(p []byte) error {
	var key any
	var pub any
	var ok bool
	var err error

	switch k := any(&x.Key).(type) {
	default:
		return ErrorStr("invalid dst")
	case **rsa.PrivateKey:
		if key, err = x509.ParsePKCS8PrivateKey(p); key == nil || err != nil {
			*k, err = x509.ParsePKCS1PrivateKey(p)
		} else if *k, ok = key.(*rsa.PrivateKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case **ecdsa.PrivateKey:
		if key, err = x509.ParsePKCS8PrivateKey(p); key == nil || err != nil {
			*k, err = x509.ParseECPrivateKey(p)
		} else if *k, ok = key.(*ecdsa.PrivateKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case *ed25519.PrivateKey:
		if key, err = x509.ParsePKCS8PrivateKey(p); key == nil || err != nil {
			//
		} else if *k, ok = key.(ed25519.PrivateKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case **ecdh.PrivateKey:
		if key, err = x509.ParsePKCS8PrivateKey(p); key == nil || err != nil {
			key, err = x509.ParseECPrivateKey(p)
		}
		if *k, ok = key.(*ecdh.PrivateKey); !ok {
			if tmp, ok := key.(*ecdsa.PrivateKey); !ok {
				err = Errorf("src [%T] dst [%T]", key, *k)
			} else {
				*k, err = tmp.ECDH()
			}
		}
	case **rsa.PublicKey:
		if pub, err = x509.ParsePKIXPublicKey(p); pub == nil || err != nil {
			pub, err = x509.ParsePKCS1PublicKey(p)
		} else if *k, ok = pub.(*rsa.PublicKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case **ecdsa.PublicKey:
		if pub, err = x509.ParsePKIXPublicKey(p); pub == nil || err != nil {
			//
		} else if *k, ok = pub.(*ecdsa.PublicKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case *ed25519.PublicKey:
		if pub, err = x509.ParsePKIXPublicKey(p); pub == nil || err != nil {
			//
		} else if *k, ok = pub.(ed25519.PublicKey); !ok {
			err = Errorf("src [%T] dst [%T]", key, *k)
		}
	case **ecdh.PublicKey:
		if pub, err = x509.ParsePKIXPublicKey(p); pub == nil || err != nil {
			//
		}
		if *k, ok = pub.(*ecdh.PublicKey); !ok {
			if tmp, ok := pub.(*ecdsa.PublicKey); !ok {
				err = Errorf("src [%T] dst [%T]", pub, *k)
			} else {
				*k, err = tmp.ECDH()
			}
		}
	case *[]byte:
		*k = p
	}
	return err
}

func (x JWK[T]) MarshalText() ([]byte, error) {
	if p, err := x.MarshalBinary(); err != nil {
		return nil, err
	} else {
		return []byte(B64Std(p).String()), nil
	}
}

func (x *JWK[T]) UnmarshalText(p []byte) error {
	if p, err := new(B64Std).z().DecodeString(string(p)); err != nil {
		return err
	} else {
		return x.UnmarshalBinary(p)
	}
}

func (x JWK[T]) MarshalYAML() (any, error) {
	if p, err := x.MarshalBinary(); err != nil {
		return nil, err
	} else {
		return B64Std(p).String(), nil
	}
}

func (x *JWK[T]) UnmarshalYAML(v *yaml.Node) error {
	if p, err := new(B64Std).z().DecodeString(v.Value); err != nil {
		return err
	} else {
		return x.UnmarshalBinary(p)
	}
}

func (x JWK[T]) Bytes() []byte {
	switch k := any(x.Key).(type) {
	default:
		return nil
	case *rsa.PrivateKey:
		return nil
	case *ecdsa.PrivateKey:
		if dh, err := k.ECDH(); err == nil && dh != nil {
			return dh.Bytes()
		}
		return nil
	case ed25519.PrivateKey:
		return k
	case *ecdh.PrivateKey:
		return k.Bytes()
	case *rsa.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if dh, err := k.ECDH(); err == nil && dh != nil {
			return dh.Bytes()
		}
		return nil
	case ed25519.PublicKey:
		return k
	case *ecdh.PublicKey:
		return k.Bytes()
	case []byte:
		return k
	}
}

// ---------------------------------------------------------------------------------------------------------------------

type jwk_field struct {
	KTY     jwk_KTY      `json:"kty"`                // (Key Type)
	USE     jwk_USE      `json:"use,omitempty"`      // (Public Key Use)
	KEYOPS  []jwk_KEYOPS `json:"key_ops,omitempty"`  // (Key Operations)
	ALG     jwk_ALG      `json:"alg,omitempty"`      // (Algorithm)
	KID     string       `json:"kid,omitempty"`      // (Key ID)
	X5U     string       `json:"x5u,omitempty"`      // (X.509 URL)
	X5C     []B64Std     `json:"x5c,omitempty"`      // (X.509 Certificate Chain)
	X5T     B64RawUrl    `json:"x5t,omitempty"`      // (X.509 Certificate Chain #1 SHA-1 Thumbprint)
	X5TS256 B64RawUrl    `json:"x5t#S256,omitempty"` // (X.509 Certificate Chain #1 SHA-256 Thumbprint)

	CRV string          `json:"crv,omitempty"` // EC		Public
	X   B64RawUrl       `json:"x,omitempty"`   // EC		Public
	Y   B64RawUrl       `json:"y,omitempty"`   // EC		Private
	D   B64RawUrl       `json:"d,omitempty"`   // EC & RSA	Private
	E   B64RawUrl       `json:"e,omitempty"`   // RSA		Public
	N   B64RawUrl       `json:"n,omitempty"`   // RSA		Public
	P   B64RawUrl       `json:"p,omitempty"`   // RSA		Private
	Q   B64RawUrl       `json:"q,omitempty"`   // RSA		Private
	DP  B64RawUrl       `json:"dp,omitempty"`  // RSA		Private
	DQ  B64RawUrl       `json:"dq,omitempty"`  // RSA		Private
	QI  B64RawUrl       `json:"qi,omitempty"`  // RSA		Private
	OTH []jwk_field_OTH `json:"oth,omitempty"` // RSA		Private

	K B64RawUrl `json:"k,omitempty"` // oct
}

type jwk_field_OTH struct {
	R B64RawUrl `json:"r,omitempty"` // RSA		Private
	D B64RawUrl `json:"d,omitempty"` // RSA		Private
	T B64RawUrl `json:"t,omitempty"` // RSA		Private
}

func (x jwk_field) jwk() (JWKish, error) {
	var k JWKish
	switch x.KTY {
	default:
		return nil, Errorf("invalid kty (%s)", x.KTY)
	case jwk_KTY_EC:
		if len(x.D) > 0 {
			k = NewJWK((*ecdsa.PrivateKey)(nil))
		} else {
			k = NewJWK((*ecdsa.PublicKey)(nil))
		}
	case jwk_KTY_RSA:
		if len(x.D) > 0 {
			k = NewJWK((*rsa.PrivateKey)(nil))
		} else {
			k = NewJWK((*rsa.PublicKey)(nil))
		}
	case jwk_KTY_OKP:
		switch x.CRV {
		default:
			return nil, Errorf("invalid crv (%s)", x.CRV)
		case jwk_CRV_Ed25519:
			if len(x.D) > 0 {
				k = NewJWK(ed25519.PrivateKey(nil))
			} else {
				k = NewJWK(ed25519.PublicKey(nil))
			}
		case Sprintf("%s", ecdh.X25519()):
			if len(x.D) > 0 {
				k = NewJWK((*ecdh.PrivateKey)(nil))
			} else {
				k = NewJWK((*ecdh.PublicKey)(nil))
			}
		}
	case jwk_KTY_oct:
		k = NewJWK([]byte(nil))
	}
	if k != nil {
		if p, err := json.Marshal(x); err == nil && len(p) > 2 {
			if err = k.UnmarshalJSON(p); err == nil {
				return k, nil
			}
		}
	}
	return nil, ErrUnimplemented
}

// ---------------------------------------------------------------------------------------------------------------------

type jwk_KTY string
type jwk_USE string
type jwk_KEYOPS string
type jwk_ALG string

const (
	jwk_CRV_Ed25519 string = "Ed25519"

	jwk_KTY_EC  jwk_KTY = "EC"
	jwk_KTY_RSA jwk_KTY = "RSA"
	jwk_KTY_OKP jwk_KTY = "OKP"
	jwk_KTY_oct jwk_KTY = "oct"

	jwk_USE_enc jwk_USE = "enc"
	jwk_USE_sig jwk_USE = "sig"

	jwk_KEYOPS_sign       jwk_KEYOPS = "sign"
	jwk_KEYOPS_verify     jwk_KEYOPS = "verify"
	jwk_KEYOPS_encrypt    jwk_KEYOPS = "encrypt"
	jwk_KEYOPS_decrypt    jwk_KEYOPS = "decrypt"
	jwk_KEYOPS_wrapKey    jwk_KEYOPS = "wrapKey"
	jwk_KEYOPS_unwrapKey  jwk_KEYOPS = "unwrapKey"
	jwk_KEYOPS_deriveKey  jwk_KEYOPS = "deriveKey"
	jwk_KEYOPS_deriveBits jwk_KEYOPS = "deriveBits"
)

// ---------------------------------------------------------------------------------------------------------------------

// B64RawUrl
type B64RawUrl []byte

func (B64RawUrl) z() *base64.Encoding { return base64.RawURLEncoding.Strict() }

func (x B64RawUrl) String() string { return x.z().EncodeToString(x) }

func (x B64RawUrl) MarshalJSON() ([]byte, error) { return []byte(`"` + x.String() + `"`), nil }

func (x B64RawUrl) MarshalYAML() (any, error) { return x.String(), nil }

func (x *B64RawUrl) UnmarshalJSON(p []byte) error {
	err := error(ErrUnimplemented)
	if l := len(p); l > 2 && p[0] == '"' && p[l-1] == '"' {
		*x, err = x.z().DecodeString(string(p[1 : l-1]))
	}
	return err
}
func (x *B64RawUrl) UnmarshalText(p []byte) error {
	err := error(ErrUnimplemented)
	if l := len(p); l > 0 {
		*x, err = x.z().DecodeString(string(p[1 : l-1]))
	}
	return err
}

// ---------------------------------------------------------------------------------------------------------------------

// B64Std
type B64Std []byte

func (B64Std) z() *base64.Encoding { return base64.StdEncoding.Strict() }

func (x B64Std) String() string { return x.z().EncodeToString(x) }

func (x B64Std) MarshalJSON() ([]byte, error) { return []byte(`"` + x.String() + `"`), nil }

func (x B64Std) MarshalYAML() (any, error) { return x.String(), nil }

func (x *B64Std) UnmarshalJSON(p []byte) error {
	err := error(ErrUnimplemented)
	if l := len(p); l > 2 && p[0] == '"' && p[l-1] == '"' {
		*x, err = x.z().DecodeString(string(p[1 : l-1]))
	}
	return err
}

func (x *B64Std) UnmarshalText(p []byte) error {
	err := error(ErrUnimplemented)
	if l := len(p); l > 0 {
		*x, err = x.z().DecodeString(string(p[1 : l-1]))
	}
	return err
}
