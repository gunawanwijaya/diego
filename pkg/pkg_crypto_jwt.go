package pkg

import (
	"bytes"
	"crypto"
	"encoding/json"

	"time"
)

type JWTClaims map[string]json.RawMessage

// Issuer get `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
func (x JWTClaims) Issuer() (iss string) { _ = x.Decode("iss", &iss); return iss }

// Subject get `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
func (x JWTClaims) Subject() (sub string) { _ = x.Decode("sub", &sub); return sub }

// Audience get `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
func (x JWTClaims) Audience() (aud []string) { _ = x.Decode("aud", &aud); return aud }

// ExpiresAt get `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
func (x JWTClaims) ExpiresAt() (exp time.Time) { _ = x.Decode("exp", &exp); return exp }

// NotBefore get `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
func (x JWTClaims) NotBefore() (nbf time.Time) { _ = x.Decode("nbf", &nbf); return nbf }

// IssuedAt get `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
func (x JWTClaims) IssuedAt() (iat time.Time) { _ = x.Decode("iat", &iat); return iat }

// ID get `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
func (x JWTClaims) ID() (jti string) { _ = x.Decode("jti", &jti); return jti }

// WithIssuer set `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
func (x JWTClaims) WithIssuer(iss string) JWTClaims { return x.With("iss", iss) }

// WithSubject set `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
func (x JWTClaims) WithSubject(sub string) JWTClaims { return x.With("sub", sub) }

// WithAudience set `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
func (x JWTClaims) WithAudience(aud ...string) JWTClaims { return x.With("aud", aud) }

// WithExpiresAt set `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
func (x JWTClaims) WithExpiresAt(exp time.Time) JWTClaims { return x.With("exp", exp) }

// WithNotBefore set `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
func (x JWTClaims) WithNotBefore(nbf time.Time) JWTClaims { return x.With("nbf", nbf) }

// WithIssuedAt set `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
func (x JWTClaims) WithIssuedAt(iat time.Time) JWTClaims { return x.With("iat", iat) }

// WithID set `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
func (x JWTClaims) WithID(jti string) JWTClaims { return x.With("jti", jti) }

func (x JWTClaims) Decode(k string, v any) error {
	p := x[k]
	switch k {
	case "aud":
		if l := len(p); l > 2 && p[0] == '"' && p[l-1] == '"' {
			p = append([]byte{'['}, append(p, ']')...)
		}
	case "exp", "nbf", "iat":
		if l := len(p); l > 2 && p[0] != '"' && p[l-1] != '"' {
			if n, err := json.Number(p).Int64(); err == nil && n > 0 {
				if p, err = time.Unix(n, 0).MarshalJSON(); err != nil {
					//
				}
			}
		}
	}
	return json.NewDecoder(bytes.NewReader(p)).Decode(v)
}

func (x JWTClaims) With(k string, v any) JWTClaims {
	if _, ok := x[k]; ok || x == nil {
		return x
	}
	switch k {
	case "aud":
		switch v0 := v.(type) {
		case []string:
			if len(v0) == 1 {
				v = v0[0]
			}
		}
	case "exp", "nbf", "iat":
		switch v0 := v.(type) {
		case time.Time:
			if !v0.IsZero() {
				v = v0.Unix()
			}
		}
	}
	if p, err := json.Marshal(v); err == nil && len(p) > 0 {
		x[k] = p
	}
	return x
}

// func (x JWTClaims) String() string { p, _ := json.Marshal(x); return string(p) }

func (x JWTClaims) Sign(s Signer) (*JWT, error) {
	jwtInfo := func(v Verifier) string {
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
	var hdr []byte
	if alg := jwtInfo(s); alg == "" {
		return nil, ErrUnimplemented
	} else {
		hdr = []byte(`{"alg":"` + alg + `"}`)
	}
	sig, err := s.Sign([]byte(JWT{hdr, x, nil}.String()))
	if err != nil {
		return nil, err
	}
	return &JWT{hdr, x, sig}, nil
}

func (x JWT) Verify(v Verifier, opts ...func(c JWTClaims) error) (JWTClaims, error) {
	if len(x.h) < 1 {
		return nil, ErrUnimplemented
	}
	if len(x.c) < 1 {
		return nil, ErrUnimplemented
	}
	if len(x.s) < 1 {
		return nil, ErrUnimplemented
	}
	if err := v.Verify([]byte(JWT{x.h, x.c, nil}.String()), x.s); err != nil {
		return nil, err
	}
	for _, opt := range opts {
		if opt != nil {
			if err := opt(x.c); err != nil {
				return nil, err
			}
		}
	}
	return x.c, nil
}

type JWT struct {
	h B64RawUrl
	c JWTClaims
	s B64RawUrl
}

func (x JWT) String() string {
	var s string
	if p, err := json.Marshal(x.c); err == nil && len(p) > 0 {
		s += x.h.String() + "." + B64RawUrl(p).String()
		if len(x.s) > 0 {
			s += "." + x.s.String()
		}
	}
	return s
}

func (x *JWT) UnmarshalText(p []byte) error {
	if ps := bytes.Split(p, []byte(".")); 2 <= len(ps) && len(ps) <= 3 {
		if err := x.h.UnmarshalText(ps[0]); err != nil {
			return err
		}
		var c B64RawUrl
		if err := c.UnmarshalText(ps[1]); err != nil {
			return err
		}
		if err := json.Unmarshal(c, &x.c); err != nil {
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

func (JWT) WithIssuer(iss string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.Issuer() != iss {
			return ErrorStr("invalid iss")
		}
		return nil
	}
}

func (JWT) WithSubject(sub string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.Subject() != sub {
			return ErrorStr("invalid sub")
		}
		return nil
	}
}

func (JWT) WithAudience(aud ...string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		for _, v1 := range aud {
			for _, v2 := range c.Audience() {
				if v1 == v2 {
					return nil
				}
			}
		}
		return ErrorStr("invalid aud")
	}
}

func (JWT) WithExpiresAt(exp time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.ExpiresAt().IsZero() || c.ExpiresAt().After(exp) {
			return ErrorStr("invalid exp")
		}
		return nil
	}
}

func (JWT) WithNotBefore(nbf time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.NotBefore().IsZero() || c.NotBefore().Before(nbf) {
			return ErrorStr("invalid nbf")
		}
		return nil
	}
}

func (JWT) WithIssuedAt(iat time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.IssuedAt().IsZero() || c.IssuedAt().Before(iat) {
			return ErrorStr("invalid iat")
		}
		return nil
	}
}

func (JWT) WithID(jti string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.ID() != jti {
			return ErrorStr("invalid jti")
		}
		return nil
	}
}
