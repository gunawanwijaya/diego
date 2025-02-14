package pkg_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/gunawanwijaya/diego/pkg"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
	"gopkg.in/yaml.v3"
)

func TestRatchet(t *testing.T) {
	var a, b = new(pkg.RatchetA), new(pkg.RatchetB)
	a.IdentityKey = pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
	a.EphemeralKey = pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
	b.IdentityKey = pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
	b.SignedPreKey = pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
	b.OneTimePreKey = pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
	pkg.Must(a.X3DH(b.IdentityKey.PublicKey(), b.SignedPreKey.PublicKey(), b.OneTimePreKey.PublicKey()))
	pkg.Must(b.X3DH(a.IdentityKey.PublicKey(), a.EphemeralKey.PublicKey()))

	a.Remote(b.PublicKey())
	{
		msg := []byte("good day sir!")
		cip := pkg.Must1(a.Send(msg))
		dec := pkg.Must1(b.Recv(cip))
		require.Equal(t, msg, dec)
	}
	{
		msg := []byte("good day to you too sir!")
		cip := pkg.Must1(b.Send(msg))
		dec := pkg.Must1(a.Recv(cip))
		require.Equal(t, msg, dec)
	}
	{
		msg := []byte("well, a very fine day")
		cip := pkg.Must1(b.Send(msg))
		dec := pkg.Must1(a.Recv(cip))
		require.Equal(t, msg, dec)
	}
	{
		msg := []byte("yes indeed")
		cip := pkg.Must1(b.Send(msg))
		dec := pkg.Must1(a.Recv(cip))
		require.Equal(t, msg, dec)
	}
	{
		msg := []byte("good day sir!")
		cip := pkg.Must1(a.Send(msg))
		dec := pkg.Must1(b.Recv(cip))
		require.Equal(t, msg, dec)
	}
}

func TestCrypto__Cipher(t *testing.T) {
	l := 32
	key32 := pkg.Nonce(l)
	msg := []byte("good day")

	c := pkg.Must1(pkg.Validate(pkg.AES_CBC(key32)))
	cip := pkg.Must1(c.Encrypt(msg))
	dec := pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	{
		c := pkg.Must1(pkg.Validate(pkg.AES_CBC_IV(key32, pkg.Nonce(16))))
		cip := pkg.Must1(c.Encrypt(msg))
		dec := pkg.Must1(c.Decrypt(cip))
		require.Equal(t, msg, dec)
	}

	c = pkg.Must1(pkg.Validate(pkg.AES_CTR(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.AES_GCM(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.ChaCha20Poly1305(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.XChaCha20Poly1305(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.NaClBox(pkg.Must2(box.GenerateKey(rand.Reader)))))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

}

func TestCrypto__Hasher(t *testing.T) {
	key := []byte("mypassword")

	h := pkg.Must1(pkg.Validate(pkg.Argon2ID(pkg.Argon2DefaultOpts(32))))
	tag1 := pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag1))
	tag2 := pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag2))
	require.NotEqual(t, tag1, tag2, "tag1=%s tag2=%s", tag1, tag2)

	h = pkg.Must1(pkg.Validate(pkg.Argon2I(pkg.Argon2DefaultOpts(32))))
	tag1 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag1))
	tag2 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag2))
	require.NotEqual(t, tag1, tag2, "tag1=%s tag2=%s", tag1, tag2)

	h = pkg.Must1(pkg.Validate(pkg.PBKDF2(pkg.PBKDF2DefaultOpts(32))))
	tag1 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag1))
	tag2 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag2))
	require.NotEqual(t, tag1, tag2, "tag1=%s tag2=%s", tag1, tag2)

	h = pkg.Must1(pkg.Validate(pkg.HKDF(pkg.HKDFDefaultOpts(32, nil))))
	tag1 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag1))
	tag2 = pkg.Must1(h.Hash(key))
	require.NoError(t, h.Compare(key, tag2))
	require.NotEqual(t, tag1, tag2, "tag1=%s tag2=%s", tag1, tag2)

	salt := pkg.Nonce(32)
	h1 := pkg.Must1(pkg.Validate(pkg.HKDF(salt, nil, 32, crypto.SHA256)))
	h2 := pkg.Must1(pkg.Validate(pkg.HKDF(salt, nil, 32, crypto.SHA256)))
	tag1 = pkg.Must1(h1.Tag(key))
	tag2 = pkg.Must1(h2.Tag(key))
	require.Equal(t, tag1, tag2)
}

func TestCrypto__Signer(t *testing.T) {
	key1024 := pkg.Must1(rsa.GenerateKey(rand.Reader, 1024))
	key2048 := pkg.Must1(rsa.GenerateKey(rand.Reader, 2048))
	keyP256 := pkg.Must1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	msg := []byte("good day")

	{
		k := pkg.Nonce(64)
		s := pkg.Must1(pkg.Validate(pkg.HMAC(crypto.SHA256, k)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(s.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PSS(key2048, crypto.SHA384, nil)))
		v := pkg.Must1(pkg.Validate(pkg.PSSVerify(&key2048.PublicKey, crypto.SHA384, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PSS(key2048, crypto.SHA256, nil)))
		v := pkg.Must1(pkg.Validate(pkg.PSSVerify(&key2048.PublicKey, crypto.SHA256, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PSS(key1024, crypto.SHA384, nil)))
		v := pkg.Must1(pkg.Validate(pkg.PSSVerify(&key1024.PublicKey, crypto.SHA384, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PSS(key2048, crypto.SHA512_256, nil)))
		v := pkg.Must1(pkg.Validate(pkg.PSSVerify(&key2048.PublicKey, crypto.SHA512_256, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PKCS1v15(key1024, crypto.SHA512)))
		v := pkg.Must1(pkg.Validate(pkg.PKCS1v15EncryptVerify(&key1024.PublicKey, crypto.SHA512)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PKCS1v15(key2048, crypto.SHA256)))
		v := pkg.Must1(pkg.Validate(pkg.PKCS1v15EncryptVerify(&key2048.PublicKey, crypto.SHA256)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PKCS1v15(key1024, crypto.SHA384)))
		v := pkg.Must1(pkg.Validate(pkg.PKCS1v15EncryptVerify(&key1024.PublicKey, crypto.SHA384)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.PKCS1v15(key2048, crypto.SHA512)))
		v := pkg.Must1(pkg.Validate(pkg.PKCS1v15EncryptVerify(&key2048.PublicKey, crypto.SHA512)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.ECDSASign(keyP256, false)))
		v := pkg.Must1(pkg.Validate(pkg.ECDSAVerify(&keyP256.PublicKey, false)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.ECDSASign(keyP256, true)))
		v := pkg.Must1(pkg.Validate(pkg.ECDSAVerify(&keyP256.PublicKey, true)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		pub, key := pkg.Must2(ed25519.GenerateKey(rand.Reader))
		s := pkg.Must1(pkg.Validate(pkg.Ed25519Sign(pub, key, nil)))
		v := pkg.Must1(pkg.Validate(pkg.Ed25519Verify(pub, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		pub, key := pkg.Must2(sign.GenerateKey(rand.Reader))
		s := pkg.Must1(pkg.Validate(pkg.NaClSign(pub, key)))
		v := pkg.Must1(pkg.Validate(pkg.NaClVerify(pub)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
}

func TestCrypto_JWT(t *testing.T) {
	key2048 := pkg.Must1(rsa.GenerateKey(rand.Reader, 2048))
	keyP256 := pkg.Must1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	claims := make(pkg.JWTClaims).
		WithIssuer("1234567890").
		WithSubject("1234567890").
		WithAudience("1234567890").
		WithExpiresAt(time.Unix(1516239022, 0)).
		WithNotBefore(time.Unix(1516239022, 0)).
		WithIssuedAt(time.Unix(1516239022, 0)).
		WithID("1234567890").
		With("name", "John Doe")
	{
		h := pkg.HMAC(crypto.SHA256, []byte("your-256-bit-secret"))
		jwt := pkg.Must1(claims.Sign(h))
		q := pkg.Must1(jwt.Verify(h))
		require.Equal(t, "1234567890", q.Subject())
		require.Equal(t, int64(1516239022), q.IssuedAt().Unix())
		var name string
		pkg.Must(q.Decode("name", &name))
		require.Equal(t, "John Doe", name)
		var str = jwt.String()
		// t.Log(jwt.String())

		qq, err := jwt.Verify(h, jwt.WithIssuer("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithSubject("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithAudience("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithExpiresAt(time.Unix(1316239022, 0)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithNotBefore(time.Unix(1716239022, 0)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithIssuedAt(time.Unix(1716239022, 0)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(h, jwt.WithID("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		jwt = new(pkg.JWT)
		pkg.Must(jwt.UnmarshalText([]byte(str)))
		qq = pkg.Must1(jwt.Verify(h))
		pkg.Must(qq.Decode("name", &name))
		require.Equal(t, "John Doe", name)
		require.Equal(t, "1234567890", qq.Subject())
		require.Equal(t, int64(1516239022), qq.IssuedAt().Unix())

	}
	{
		r := pkg.ECDSASign(keyP256, false)
		jwt := pkg.Must1(claims.Sign(r))
		q := pkg.Must1(jwt.Verify(r))
		require.Equal(t, "1234567890", q.Subject())
		require.Equal(t, int64(1516239022), q.IssuedAt().Unix())
		var name string
		pkg.Must(q.Decode("name", &name))
		require.Equal(t, "John Doe", name)
		// t.Log(jwt.String())
	}
	{
		r := pkg.PKCS1v15(key2048, crypto.SHA256)
		jwt := pkg.Must1(claims.Sign(r))
		q := pkg.Must1(jwt.Verify(r))
		require.Equal(t, "1234567890", q.Subject())
		require.Equal(t, int64(1516239022), q.IssuedAt().Unix())
		var name string
		pkg.Must(q.Decode("name", &name))
		require.Equal(t, "John Doe", name)
		// t.Log(jwt.String())
	}
	{
		r := pkg.PSS(key2048, crypto.SHA256, nil)
		jwt := pkg.Must1(claims.Sign(r))
		q := pkg.Must1(jwt.Verify(r))
		require.Equal(t, "1234567890", q.Subject())
		require.Equal(t, int64(1516239022), q.IssuedAt().Unix())
		var name string
		pkg.Must(q.Decode("name", &name))
		require.Equal(t, "John Doe", name)
		// t.Log(jwt.String())
	}

}

func TestCrypto_JWK(t *testing.T) {
	var err error
	var p []byte
	const bits = 2048

	{
		key := pkg.Nonce(32)
		pub1, key1 := pkg.Must2(ed25519.GenerateKey(rand.Reader))
		key2 := pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader))
		pub2 := key2.PublicKey()
		key3 := pkg.Must1(ecdh.P521().GenerateKey(rand.Reader))
		pub3 := key3.PublicKey()
		key4 := pkg.Must1(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
		pub4 := &key4.PublicKey
		key5 := pkg.Must1(rsa.GenerateKey(rand.Reader, bits))
		pub5 := &key5.PublicKey

		jwks := pkg.JWKS{
			pkg.NewJWK(key).WithKID("key"),
			pkg.NewJWK(key1).WithKID("key1"), pkg.NewJWK(pub1).WithKID("pub1"),
			pkg.NewJWK(key2).WithKID("key2"), pkg.NewJWK(pub2).WithKID("pub2"),
			pkg.NewJWK(key3).WithKID("key3"), pkg.NewJWK(pub3).WithKID("pub3"),
			pkg.NewJWK(key4).WithKID("key4"), pkg.NewJWK(pub4).WithKID("pub4"),
			pkg.NewJWK(key5).WithKID("key5"), pkg.NewJWK(pub5).WithKID("pub5"),
		}
		p = pkg.Must1(json.Marshal(jwks))
		var jwksTmp pkg.JWKS
		pkg.Must(json.Unmarshal(p, &jwksTmp))
		require.JSONEq(t, string(p), string(pkg.Must1(json.Marshal(jwksTmp))))

	}

	{
		sym := pkg.NewJWK(pkg.Nonce(32))

		symTmp := pkg.NewJWK([]byte(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(sym)), &symTmp))
		require.Equal(t, sym.Key, symTmp.Key, "sym=(%s) symTmp=(%s)", sym.Key, symTmp.Key)
		symTmp = pkg.NewJWK([]byte(nil))
		pkg.Must(symTmp.UnmarshalBinary(pkg.Must1(sym.MarshalBinary())))
		require.Equal(t, sym.Key, symTmp.Key, "sym=(%s) symTmp=(%s)", sym.Key, symTmp.Key)
		symTmp = pkg.NewJWK([]byte(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(sym)), &symTmp))
		require.Equal(t, sym.Key, symTmp.Key, "sym=(%s) symTmp=(%s)", sym.Key, symTmp.Key)
	}

	{
		pub_, prv_ := pkg.Must2(ed25519.GenerateKey(rand.Reader))
		pub, prv := pkg.NewJWK(pub_), pkg.NewJWK(prv_)

		prvTmp := pkg.NewJWK(ed25519.PrivateKey(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK(ed25519.PrivateKey(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK(ed25519.PrivateKey(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK(ed25519.PublicKey(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK(ed25519.PublicKey(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK(ed25519.PublicKey(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(ecdh.X25519().GenerateKey(rand.Reader)))
		pub := pkg.NewJWK(prv.Key.PublicKey())

		prvTmp := pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)

		pubTmp := pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)

		prv = pkg.NewJWK(pkg.Must1(ecdh.P521().GenerateKey(rand.Reader)))
		pub = pkg.NewJWK(prv.Key.PublicKey())

		prvTmp = pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdh.PrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)

		pubTmp = pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdh.PublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(ecdsa.GenerateKey(elliptic.P224(), rand.Reader)))
		pub := pkg.NewJWK(&prv.Key.PublicKey)

		func() { _, err = json.Marshal(prv); require.ErrorIs(t, err, pkg.ErrUnimplemented) }()
		func() { _, err = json.Marshal(pub); require.ErrorIs(t, err, pkg.ErrUnimplemented) }()

		prv = pkg.NewJWK(pkg.Must1(ecdsa.GenerateKey(elliptic.P521(), rand.Reader)))
		pub = pkg.NewJWK(&prv.Key.PublicKey)

		prvTmp := pkg.NewJWK((*ecdsa.PrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdsa.PrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*ecdsa.PrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK((*ecdsa.PublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdsa.PublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*ecdsa.PublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(rsa.GenerateKey(rand.Reader, bits)))
		pub := pkg.NewJWK(&prv.Key.PublicKey)

		prvTmp := pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)

		prv = pkg.NewJWK(pkg.Must1(rsa.GenerateMultiPrimeKey(rand.Reader, 4, bits)))
		pub = pkg.NewJWK(&prv.Key.PublicKey)

		prvTmp = pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*rsa.PrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp = pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*rsa.PublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
	}
}

func TestContentNegotiate(t *testing.T) {
	cn := pkg.ContentNegotiate{}
	pkg.Must(cn.UnmarshalText([]byte("*/*;q=0.8,text/html,application/xhtml+xml,application/xml;q=0.9")))
	require.Equal(t, 4, len(cn))
	require.Equal(t, "application/xhtml+xml", cn[0].Content)
	require.Equal(t, "text/html", cn[1].Content)
	require.Equal(t, "application/xml", cn[2].Content)
	require.Equal(t, "*/*", cn[3].Content)
}
