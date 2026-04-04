package pkg

import (
	"bytes"
	"crypto"
	"encoding"
	"encoding/json"
	"slices"
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
		case implSigner[ed25519Args]:
			return "EdDSA"
		case implSigner[ecdsaArgs]:
			return map[crypto.Hash]string{
				crypto.SHA256: "ES256",
				crypto.SHA384: "ES384",
				crypto.SHA512: "ES512",
			}[s.metadata.hash]
		case implSigner[hmacArgs]:
			return map[crypto.Hash]string{
				crypto.SHA256: "HS256",
				crypto.SHA384: "HS384",
				crypto.SHA512: "HS512",
			}[s.metadata.hash]
		case implSigner[rsaPKCS1v15Args]:
			return map[crypto.Hash]string{
				crypto.SHA256: "RS256",
				crypto.SHA384: "RS384",
				crypto.SHA512: "RS512",
			}[s.metadata.hash]
		case implSigner[rsaPSSArgs]:
			return map[crypto.Hash]string{
				crypto.SHA256: "PS256",
				crypto.SHA384: "PS384",
				crypto.SHA512: "PS512",
			}[s.metadata.hash]
		}
		return ""
	}
	var header B64RawUrl
	if alg := jwtInfo(s); alg == "" {
		return nil, ErrUnimplemented
	} else {
		header = B64RawUrl(`{"alg":"` + alg + `"}`)
	}
	signature, err := s.Sign(JWT{header: header, claims: x}.presign())
	if err != nil {
		return nil, err
	}
	return &JWT{header, x, signature}, nil
}

var _ interface {
	Stringer
	encoding.TextUnmarshaler
} = (*JWT)(nil)

type JWT struct {
	header    B64RawUrl
	claims    JWTClaims
	signature B64RawUrl
}

func (x JWT) VerifierFromClaims(fn func(c JWTClaims) Verifier) Verifier {
	return fn(x.claims)
}

func (x JWT) Verify(v Verifier, opts ...func(c JWTClaims) error) (JWTClaims, error) {
	if len(x.header) < 1 {
		return nil, ErrUnimplemented
	}
	if len(x.claims) < 1 {
		return nil, ErrUnimplemented
	}
	if len(x.signature) < 1 {
		return nil, ErrUnimplemented
	}
	if v == nil {
		return nil, ErrUnimplemented
	}
	if err := v.Verify(x.presign(), x.signature); err != nil {
		return nil, err
	}
	for _, opt := range opts {
		if opt != nil {
			if err := opt(x.claims); err != nil {
				return nil, err
			}
		}
	}
	return x.claims, nil
}

func (x JWT) presign() []byte {
	if len(x.header) < 1 || len(x.claims) < 1 {
		return nil
	}
	claims, _ := json.Marshal(x.claims)
	return []byte(x.header.String() + "." + B64RawUrl(claims).String())
}

func (x JWT) String() string {
	if len(x.presign()) < 1 {
		return ""
	}
	return string(x.presign()) + "." + x.signature.String()
}

func (x *JWT) UnmarshalText(p []byte) error {
	var c B64RawUrl
	ps := bytes.Split(p, []byte("."))

	if len(ps) != 3 {
		return ErrorStr("invalid JWT format")
	} else if err := x.header.UnmarshalText(ps[0]); err != nil {
		return err
	} else if !bytes.HasPrefix(x.header, []byte("{")) || !bytes.HasSuffix(x.header, []byte("}")) {
		return ErrorStr("invalid JWT header")
	} else if err := c.UnmarshalText(ps[1]); err != nil {
		return err
	} else if !bytes.HasPrefix(c, []byte("{")) || !bytes.HasSuffix(c, []byte("}")) {
		return ErrorStr("invalid JWT claims format")
	} else if err := json.Unmarshal(c, &x.claims); err != nil {
		return err
	} else if err := x.signature.UnmarshalText(ps[2]); err != nil {
		return err
	}
	return nil
}

func (JWT) CheckIssuer(iss string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.Issuer() != iss {
			return ErrorStr("invalid iss")
		}
		return nil
	}
}

func (JWT) CheckSubject(sub string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.Subject() != sub {
			return ErrorStr("invalid sub")
		}
		return nil
	}
}

func (JWT) CheckAudience(aud ...string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		for _, v := range aud {
			if slices.Contains(c.Audience(), v) {
				return nil
			}
		}
		return ErrorStr("invalid aud")
	}
}

func (JWT) CheckExpiresAt(exp time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if !c.ExpiresAt().IsZero() && exp.After(c.ExpiresAt()) {
			return ErrorStr("invalid exp")
		}
		return nil
	}
}

func (JWT) CheckNotBefore(nbf time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if !c.NotBefore().IsZero() && nbf.Before(c.NotBefore()) {
			return ErrorStr("invalid nbf")
		}
		return nil
	}
}

func (JWT) CheckIssuedAt(iat time.Time) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if !c.IssuedAt().IsZero() && iat.Before(c.IssuedAt()) {
			return ErrorStr("invalid iat")
		}
		return nil
	}
}

func (JWT) CheckID(jti string) func(c JWTClaims) error {
	return func(c JWTClaims) error {
		if c.ID() != jti {
			return ErrorStr("invalid jti")
		}
		return nil
	}
}
