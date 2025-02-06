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
	"io"
	"testing"

	"github.com/gunawanwijaya/diego/pkg"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
	"gopkg.in/yaml.v3"
)

func TestCrypto__Cipher(t *testing.T) {
	l := 32
	key32 := make([]byte, l)
	n := pkg.Must1(io.ReadFull(rand.Reader, key32))
	require.Equal(t, l, n)

	msg := []byte("good day")

	c := pkg.Must1(pkg.Validate(pkg.AES_CBC(key32)))
	cip := pkg.Must1(c.Encrypt(msg))
	dec := pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.AES_CFB(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.AES_CTR(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.AES_GCM(key32)))
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.AES_OFB(key32)))
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
}

func TestCrypto__Signer(t *testing.T) {
	key1024 := pkg.Must1(rsa.GenerateKey(rand.Reader, 1024))
	key2048 := pkg.Must1(rsa.GenerateKey(rand.Reader, 2048))
	keyP256 := pkg.Must1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	msg := []byte("good day")
	{
		s := pkg.Must1(pkg.Validate(pkg.PSS(key1024, crypto.SHA512, nil)))
		v := pkg.Must1(pkg.Validate(pkg.PSSVerify(&key1024.PublicKey, crypto.SHA512, nil)))
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
		s := pkg.Must1(pkg.Validate(pkg.ECDSASign(keyP256)))
		v := pkg.Must1(pkg.Validate(pkg.ECDSAVerify(&keyP256.PublicKey)))
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
