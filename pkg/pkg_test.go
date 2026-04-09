package pkg_test

import (
	"bytes"
	"crypto"

	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"os"
	"testing"
	"time"

	"github.com/gunawanwijaya/diego/pkg"
	"github.com/status-im/doubleratchet"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCertificate(t *testing.T) {
	{
		f := pkg.Must1(os.Open("./ec_private.key"))
		defer f.Close()
		s := pkg.Must1(f.Stat())
		n := int(s.Size())
		p := make([]byte, n)
		require.Equal(t, n, pkg.Must1(f.Read(p)))

		var key pkg.JWK[*pkg.ECDSAPrivateKey]
		pkg.Must(key.UnmarshalBinary(p))
	}

	{
		f := pkg.Must1(os.Open("./my.key"))
		n := int(pkg.Must1(f.Stat()).Size())
		p := make([]byte, n)
		require.Equal(t, n, pkg.Must1(f.Read(p)))
		f.Close()

		var jwk = new(pkg.JWK[*pkg.ECDSAPrivateKey])
		pkg.Must(jwk.UnmarshalText(p))
		var key = jwk.Key

		f = pkg.Must1(os.Open("./my.crt"))
		n = int(pkg.Must1(f.Stat()).Size())
		p = make([]byte, n)
		require.Equal(t, n, pkg.Must1(f.Read(p)))
		f.Close()

		var q = make([]byte, len(p))
		_ = copy(q, p)
		var match = func(t string) []byte {
			var o []byte
			for b := new(pem.Block); b != nil; {
				b, q = pem.Decode(q)
				if b != nil && b.Type == t {
					o = append(o, b.Bytes...)
				}
			}
			if len(o) > 0 {
				return o
			} else {
				return p
			}
		}

		crts := pkg.Must1(x509.ParseCertificates(match("CERTIFICATE")))
		require.Equal(t, 1, len(crts))
		var crt *x509.Certificate = crts[0]
		require.True(t, key.PublicKey.Equal(crt.PublicKey))
		jwk = jwk.WithX5C(crts...)
		// t.Log(pkg.B64RawUrl(jwk.X5T()))
		// t.Log(pkg.B64RawUrl(jwk.X5TS256()))

		var pool = x509.NewCertPool()
		pool.AddCert(crt)
		chains := pkg.Must1(crt.Verify(x509.VerifyOptions{Roots: pool}))
		require.Equal(t, 1, len(chains))
		require.Equal(t, 1, len(chains[0]))
		require.Equal(t, crt, chains[0][0])
	}
}

func TestDoubleRatchet(t *testing.T) {
	curve := ecdh.X25519()
	kp_A := pkg.Must1(doubleratchet.DefaultCrypto{}.GenerateDH())
	kp_B := pkg.Must1(doubleratchet.DefaultCrypto{}.GenerateDH())

	id_A := &pkg.Identity{
		IdentityKey:   pkg.Must1(curve.NewPrivateKey(kp_A.PrivateKey())),
		SignedPreKey:  pkg.Must1(curve.GenerateKey(rand.Reader)),
		OneTimePreKey: []*ecdh.PrivateKey{pkg.Must1(curve.GenerateKey(rand.Reader))},
	}
	id_B := &pkg.Identity{
		IdentityKey:   pkg.Must1(curve.NewPrivateKey(kp_B.PrivateKey())),
		SignedPreKey:  pkg.Must1(curve.GenerateKey(rand.Reader)),
		OneTimePreKey: []*ecdh.PrivateKey{pkg.Must1(curve.GenerateKey(rand.Reader))},
	}

	aEK := pkg.Must1(curve.GenerateKey(rand.Reader))

	for _, sk := range [][2][]byte{
		{
			pkg.Must1(id_A.ECDH(id_B.IdentityKey.PublicKey())),
			pkg.Must1(id_B.ECDH(id_A.IdentityKey.PublicKey())),
		},
		{
			pkg.Must1(id_A.ECTwoDH_A(id_B.IdentityKey.PublicKey(), id_B.SignedPreKey.PublicKey(), aEK)),
			pkg.Must1(id_B.ECTwoDH_B(id_A.IdentityKey.PublicKey(), aEK.PublicKey())),
		},
		{
			pkg.Must1(id_A.EC2DH_A(id_B.IdentityKey.PublicKey(), id_B.SignedPreKey.PublicKey(), aEK)),
			pkg.Must1(id_B.EC2DH_B(id_A.IdentityKey.PublicKey(), aEK.PublicKey())),
		},
		{
			pkg.Must1(id_A.EC3DH_A(id_B.IdentityKey.PublicKey(), id_B.SignedPreKey.PublicKey(), aEK)),
			pkg.Must1(id_B.EC3DH_B(id_A.IdentityKey.PublicKey(), aEK.PublicKey())),
		},
		{
			pkg.Must1(id_A.ECX3DH_A(id_B.IdentityKey.PublicKey(), id_B.SignedPreKey.PublicKey(), id_B.OneTimePreKey[0].PublicKey(), aEK)),
			pkg.Must1(id_B.ECX3DH_B(id_A.IdentityKey.PublicKey(), aEK.PublicKey(), id_B.OneTimePreKey[0].PublicKey())),
		},
	} {
		require.Equal(t, sk[0], sk[1])
		sessStorage := doubleratchet.SessionStorage(nil)
		keysStorage := &doubleratchet.KeysStorageInMemory{}
		sess_A := pkg.Must1(doubleratchet.New([]byte("sess-a"), sk[0], kp_A, sessStorage, doubleratchet.WithKeysStorage(keysStorage)))
		sess_B := pkg.Must1(doubleratchet.NewWithRemoteKey([]byte("sess-b"), sk[1], kp_A.PublicKey(), sessStorage, doubleratchet.WithKeysStorage(keysStorage)))

		msg := []byte("hello bob")
		enc := pkg.Must1(sess_A.RatchetEncrypt(msg, nil))
		dec := pkg.Must1(sess_B.RatchetDecrypt(enc, nil))
		require.Equal(t, msg, dec)
		require.NotNil(t, pkg.Ok1(pkg.Must2(keysStorage.Get(enc.Header.DH, uint(enc.Header.N)))))

		msg = []byte("hello to you too alice")
		enc = pkg.Must1(sess_B.RatchetEncrypt(msg, nil))
		dec = pkg.Must1(sess_A.RatchetDecrypt(enc, nil))
		require.Equal(t, msg, dec)
		require.NotNil(t, pkg.Ok1(pkg.Must2(keysStorage.Get(enc.Header.DH, uint(enc.Header.N)))))
	}
}

func TestCrypto__CipherMLKEM(t *testing.T) {
	// given this scenario:
	// 01. client have decapsKey & know server encapsKey
	// 02. client generate cip_A & store sk_A0
	// 03. client request to server with params cip_A & ek_B (ek_B is optional and retrievable from db)
	// 04. server validate should ek_B is valid, generate cip_B & store sk_B0
	// 05. server generate sk_A1 by decaps cip_A
	// 06. server generate sk_C0 by xoring sk_B0 & sk_A1
	// 07. server response with cip_B
	// 08. client generate sk_B1 by decaps cip_B
	// 09. server generate sk_C1 by xoring sk_B1 & sk_A0
	// 10. sk_A0 & sk_A1 is now symmetric
	decap_A := pkg.Must1(mlkem.GenerateKey1024())
	decap_B := pkg.Must1(mlkem.GenerateKey1024())
	var encap_A, encap_B crypto.Encapsulator
	switch ek_A := decap_A.Encapsulator().Bytes(); len(ek_A) {
	case mlkem.EncapsulationKeySize1024:
		encap_A = pkg.Must1(mlkem.NewEncapsulationKey1024(ek_A))
	case mlkem.EncapsulationKeySize768:
		encap_A = pkg.Must1(mlkem.NewEncapsulationKey768(ek_A))
	default:
		t.FailNow()
	}
	switch ek_B := decap_B.Encapsulator().Bytes(); len(ek_B) {
	case mlkem.EncapsulationKeySize1024:
		encap_B = pkg.Must1(mlkem.NewEncapsulationKey1024(ek_B))
	case mlkem.EncapsulationKeySize768:
		encap_B = pkg.Must1(mlkem.NewEncapsulationKey768(ek_B))
	default:
		t.FailNow()
	}

	const n = mlkem.SharedKeySize
	sk_C0, sk_C1 := new([n]byte)[:], new([n]byte)[:]

	sk_A0, cip_A := encap_A.Encapsulate()          // 02
	sk_B0, cip_B := encap_B.Encapsulate()          // 04
	sk_A1 := pkg.Must1(decap_A.Decapsulate(cip_A)) // 05
	sk_B1 := pkg.Must1(decap_B.Decapsulate(cip_B)) // 08
	for i := range n {                             // xor loop
		sk_C0[i] = sk_B0[i] ^ sk_A1[i] // 06
		sk_C1[i] = sk_B1[i] ^ sk_A0[i] // 09
	}

	require.Equal(t, n, len(sk_A0))
	require.Equal(t, n, len(sk_A1))
	require.Equal(t, sk_A0, sk_A1)
	require.Equal(t, n, len(sk_B0))
	require.Equal(t, n, len(sk_B1))
	require.Equal(t, sk_B0, sk_B1)
	require.Equal(t, sk_C0, sk_C1)
	require.NotEqual(t, sk_C0, sk_A0)
	require.NotEqual(t, sk_C0, sk_B0)
	require.NotEqual(t, sk_C1, sk_A1)
	require.NotEqual(t, sk_C1, sk_B1)
}

func TestCrypto__KeyWrap(t *testing.T) {
	s := []byte{130, 225, 9, 214, 88, 153, 91, 219, 39, 98, 91, 41, 18, 249, 179, 244}
	p := []byte("password")
	k := []byte{176, 191, 186, 56, 30, 139, 159, 27, 124, 71, 9, 144, 183, 12, 89, 174, 222, 0, 54, 99, 136, 66, 69, 75, 27, 170, 65, 161, 186, 47, 156, 235}
	w := pkg.Must1(pkg.PBKDF2(s, 100_000, 32, crypto.SHA256).Tag(p))
	kwA := pkg.Must1(pkg.AES.KeyWrap(w))

	wkA := pkg.Must1(kwA.Wrap(k))

	o := []byte{115, 80, 209, 64, 224, 95, 86, 29, 186, 118, 182, 108, 176, 121, 242, 101, 191, 170, 139, 130, 192, 96, 76, 93, 109, 63, 208, 54, 16, 187, 117, 202, 217, 83, 118, 234, 114, 226, 11, 174}
	require.Equal(t, wkA, o)
	require.Equal(t, pkg.Must1(kwA.Unwrap(wkA)), k)
}

func TestCrypto__Cipher(t *testing.T) {
	l := 32
	key32 := pkg.Nonce(l)
	msg := []byte("good day")
	iv := pkg.Nonce(16)

	c := pkg.Must1(pkg.AES.CBC(key32, iv))
	pkg.Must(c.Validate())
	cip := pkg.Must1(c.Encrypt(msg))
	dec := pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	{
		buf := new(bytes.Buffer)
		cs := pkg.Must1(pkg.AES.CTR(key32, iv, buf, buf))
		pkg.Must(cs.Validate())
		cip = pkg.Must1(cs.Encrypt(msg))
		dec = pkg.Must1(cs.Decrypt(cip))
		require.Equal(t, msg, dec)
		pkg.Must1(cs.Write(msg))
		dec = pkg.Must1(io.ReadAll(cs))
		require.Equal(t, msg, dec)
	}

	c = pkg.Must1(pkg.AES.GCM(key32, iv, nil))
	pkg.Must(c.Validate())
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.ChaCha20Poly1305(key32, iv, nil))
	pkg.Must(c.Validate())
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.XChaCha20Poly1305(key32, iv, nil))
	pkg.Must(c.Validate())
	cip = pkg.Must1(c.Encrypt(msg))
	dec = pkg.Must1(c.Decrypt(cip))
	require.Equal(t, msg, dec)

	c = pkg.Must1(pkg.Validate(pkg.NaCl.Box(pkg.Must2(pkg.NaCl.GenerateBoxKey()))))
	pkg.Must(c.Validate())
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
	key2048 := pkg.Must1(pkg.RSA.GenerateKey(rand.Reader, 2048))
	keyP256 := pkg.Must1(pkg.ECDSA.GenerateKey(elliptic.P256(), rand.Reader))

	msg := []byte("good day")

	{
		k := pkg.Nonce(64)
		s := pkg.Must1(pkg.Validate(pkg.HMAC.Signer(crypto.SHA256, k)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(s.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Signer(key2048, crypto.SHA384, nil)))
		v := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Verifier(&key2048.PublicKey, crypto.SHA384, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Signer(key2048, crypto.SHA256, nil)))
		v := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Verifier(&key2048.PublicKey, crypto.SHA256, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Signer(key2048, crypto.SHA512_256, nil)))
		v := pkg.Must1(pkg.Validate(pkg.RSA.PSS.Verifier(&key2048.PublicKey, crypto.SHA512_256, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.RSA.PKCS1v15.Signer(key2048, crypto.SHA256)))
		v := pkg.Must1(pkg.Validate(pkg.RSA.PKCS1v15.Verifier(&key2048.PublicKey, crypto.SHA256)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.RSA.PKCS1v15.Signer(key2048, crypto.SHA512)))
		v := pkg.Must1(pkg.Validate(pkg.RSA.PKCS1v15.Verifier(&key2048.PublicKey, crypto.SHA512)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.ECDSA.Signer(keyP256, false)))
		v := pkg.Must1(pkg.Validate(pkg.ECDSA.Verifier(&keyP256.PublicKey, false)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		s := pkg.Must1(pkg.Validate(pkg.ECDSA.Signer(keyP256, true)))
		v := pkg.Must1(pkg.Validate(pkg.ECDSA.Verifier(&keyP256.PublicKey, true)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
	}
	{
		pub, key := pkg.Must2(pkg.Ed25519.GenerateKey(rand.Reader))
		s := pkg.Must1(pkg.Validate(pkg.Ed25519.Signer(pub, key, nil)))
		v := pkg.Must1(pkg.Validate(pkg.Ed25519.Verifier(pub, nil)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))
		// t.Logf("[%d] [%d]", len(pub), len(key))
	}
	{
		pub, key := pkg.Must2(pkg.NaCl.GenerateSignKey())
		s := pkg.Must1(pkg.Validate(pkg.NaCl.Signer(pub, key)))
		v := pkg.Must1(pkg.Validate(pkg.NaCl.Verifier(pub)))
		sig := pkg.Must1(s.Sign(msg))
		pkg.Must(v.Verify(msg, sig))

		var pub0 pkg.Ed25519PublicKey = pub[:]
		var key0 pkg.Ed25519PrivateKey = key[:]
		s0 := pkg.Must1(pkg.Validate(pkg.Ed25519.Signer(pub0, key0, nil)))
		v0 := pkg.Must1(pkg.Validate(pkg.Ed25519.Verifier(pub0, nil)))
		n := pkg.Ed25519.SignatureSize()
		sig0 := pkg.Must1(s0.Sign(msg))
		require.Equal(t, len(sig[:n]), len(sig0))
		require.Equal(t, sig[:n], pkg.Must1(s0.Sign(msg)))
		pkg.Must(v0.Verify(msg, sig[:n]))
	}
}

func TestCrypto_JWT(t *testing.T) {
	ts := time.Unix(1516239022, 0)
	tsBefore, tsAfter := ts.Add(-time.Hour), ts.Add(time.Hour)

	claims := make(pkg.JWTClaims).
		// WithIssuer("1234567890").
		WithSubject("1234567890").
		WithAudience("1234567890").
		WithIssuedAt(ts).
		WithNotBefore(tsBefore).
		WithExpiresAt(tsAfter).
		WithID("1234567890").
		With("name", "John Doe")

	checkIntegrity := func(jwt *pkg.JWT, claims pkg.JWTClaims, s pkg.Signer) {
		q := pkg.Must1(jwt.Verify(s))
		// require.Equal(t, claims.Issuer(), q.Issuer())
		require.Equal(t, claims.Subject(), q.Subject())
		require.Equal(t, claims.Audience(), q.Audience())
		require.Equal(t, claims.IssuedAt().Unix(), q.IssuedAt().Unix())
		require.Equal(t, claims.NotBefore().Unix(), q.NotBefore().Unix())
		require.Equal(t, claims.ExpiresAt().Unix(), q.ExpiresAt().Unix())
		require.Equal(t, claims.ID(), q.ID())
		var qName, cName string
		pkg.Must(claims.Decode("name", &cName))
		pkg.Must(q.Decode("name", &qName))
		require.Equal(t, cName, qName)

		qq, err := jwt.Verify(s, jwt.CheckIssuer("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckSubject("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckAudience("abc"))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckExpiresAt(tsAfter.Add(time.Hour)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckNotBefore(tsBefore.Add(-time.Hour)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckIssuedAt(ts.Add(-time.Hour)))
		require.Error(t, err)
		require.Nil(t, qq)

		qq, err = jwt.Verify(s, jwt.CheckID("abc"))
		require.Error(t, err)
		require.Nil(t, qq)
	}

	key2048 := pkg.Must1(pkg.RSA.GenerateKey(rand.Reader, 2048))
	keyP256 := pkg.Must1(pkg.ECDSA.GenerateKey(elliptic.P256(), rand.Reader))
	edPub, edKey := pkg.Must2(pkg.Ed25519.GenerateKey(rand.Reader))
	// t.Logf("edPub: %s\n", pkg.Must1(pkg.NewJWK(edPub).MarshalJSON()))
	// t.Logf("edKey: %s\n", pkg.Must1(pkg.NewJWK(edKey).MarshalJSON()))
	const (
		hs256 uint = iota
		es256
		rs256
		ps256
		ed25519
	)
	signerMap := map[uint]pkg.Signer{
		hs256:   pkg.HMAC.Signer(crypto.SHA256, pkg.Nonce(32)),
		es256:   pkg.ECDSA.Signer(keyP256, false),
		rs256:   pkg.RSA.PKCS1v15.Signer(key2048, crypto.SHA256),
		ps256:   pkg.RSA.PSS.Signer(key2048, crypto.SHA256, nil),
		ed25519: pkg.Ed25519.Signer(edPub, edKey, nil),
	}

	for kid, s := range signerMap {
		claims := maps.Clone(claims).With("kid", kid)
		jwt := pkg.Must1(claims.Sign(s))
		checkIntegrity(jwt, claims, s)

		// t.Log(kid, jwt.String())
		newJwt := new(pkg.JWT)
		pkg.Must(newJwt.UnmarshalText([]byte(jwt.String())))
		checkIntegrity(newJwt, claims, s)
	}
}

func TestCrypto_JWK(t *testing.T) {
	var err error
	var p []byte
	const bits = 2048

	{
		key := pkg.Nonce(32)
		pub1, key1 := pkg.Must2(pkg.Ed25519.GenerateKey(rand.Reader))
		key2 := pkg.Must1(pkg.Curve.X25519().GenerateKey(rand.Reader))
		pub2 := key2.PublicKey()
		key3 := pkg.Must1(pkg.Curve.P521().GenerateKey(rand.Reader))
		pub3 := key3.PublicKey()
		key4 := pkg.Must1(pkg.ECDSA.GenerateKey(elliptic.P521(), rand.Reader))
		pub4 := &key4.PublicKey
		key5 := pkg.Must1(pkg.RSA.GenerateKey(rand.Reader, bits))
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
		pub_, prv_ := pkg.Must2(pkg.Ed25519.GenerateKey(rand.Reader))
		pub, prv := pkg.NewJWK(pub_), pkg.NewJWK(prv_)

		prvTmp := pkg.NewJWK(pkg.Ed25519PrivateKey(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK(pkg.Ed25519PrivateKey(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK(pkg.Ed25519PrivateKey(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.Equal(t, prv.Key, prvTmp.Key, "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK(pkg.Ed25519PublicKey(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK(pkg.Ed25519PublicKey(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK(pkg.Ed25519PublicKey(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.Equal(t, pub.Key, pubTmp.Key, "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(pkg.Curve.X25519().GenerateKey(rand.Reader)))
		pub := pkg.NewJWK(prv.Key.PublicKey())

		prvTmp := pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)

		pubTmp := pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)

		prv = pkg.NewJWK(pkg.Must1(pkg.Curve.P521().GenerateKey(rand.Reader)))
		pub = pkg.NewJWK(prv.Key.PublicKey())

		prvTmp = pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDHPrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv, prvTmp.Key)

		pubTmp = pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDHPublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(pkg.ECDSA.GenerateKey(elliptic.P224(), rand.Reader)))
		pub := pkg.NewJWK(&prv.Key.PublicKey)

		func() { _, err = json.Marshal(prv); require.ErrorIs(t, err, pkg.ErrUnimplemented) }()
		func() { _, err = json.Marshal(pub); require.ErrorIs(t, err, pkg.ErrUnimplemented) }()

		prv = pkg.NewJWK(pkg.Must1(pkg.ECDSA.GenerateKey(elliptic.P521(), rand.Reader)))
		pub = pkg.NewJWK(&prv.Key.PublicKey)

		prvTmp := pkg.NewJWK((*pkg.ECDSAPrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDSAPrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.ECDSAPrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK((*pkg.ECDSAPublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDSAPublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.ECDSAPublicKey)(nil))
		pkg.Must(pubTmp.UnmarshalBinary(pkg.Must1(pub.MarshalBinary())))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
	}
	{
		prv := pkg.NewJWK(pkg.Must1(pkg.RSA.GenerateKey(rand.Reader, bits)))
		pub := pkg.NewJWK(&prv.Key.PublicKey)

		prvTmp := pkg.NewJWK((*pkg.RSAPrivateKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.RSAPrivateKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(prv)), &prvTmp))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)
		prvTmp = pkg.NewJWK((*pkg.RSAPrivateKey)(nil))
		pkg.Must(prvTmp.UnmarshalBinary(pkg.Must1(prv.MarshalBinary())))
		require.True(t, prv.Key.Equal(prvTmp.Key), "prv=(%s) prvTmp=(%s)", prv.Key, prvTmp.Key)

		pubTmp := pkg.NewJWK((*pkg.RSAPublicKey)(nil))
		pkg.Must(json.Unmarshal(pkg.Must1(json.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.RSAPublicKey)(nil))
		pkg.Must(yaml.Unmarshal(pkg.Must1(yaml.Marshal(pub)), &pubTmp))
		require.True(t, pub.Key.Equal(pubTmp.Key), "pub=(%s) pubTmp=(%s)", pub.Key, pubTmp.Key)
		pubTmp = pkg.NewJWK((*pkg.RSAPublicKey)(nil))
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
