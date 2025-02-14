package pkg

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"slices"
)

type Ratchet struct {
	state []byte
	key   *ecdh.PrivateKey
	pub   *ecdh.PublicKey
}

func (x *Ratchet) PublicKey() *ecdh.PublicKey { return x.key.PublicKey() }

func (x *Ratchet) Remote(pub *ecdh.PublicKey) { x.pub = pub }

func (x *Ratchet) Next(key []byte) ([]byte, []byte, error) {
	if len(x.state) < 1 || len(key) < 1 {
		return nil, nil, ErrUnimplemented
	}
	rsLen, ivLen := len(x.state), 16
	l := rsLen + rsLen + ivLen
	p, err := HKDF(nil, nil, l, crypto.SHA256).Tag(slices.Concat(x.state, key))
	if err != nil {
		return nil, nil, err
	}
	x.state = p[:rsLen]
	return p[rsLen : 2*rsLen], p[2*rsLen:], nil
}

func (x *Ratchet) Send(msg []byte) ([]byte, error) {
	if x.pub == nil || len(msg) < 1 {
		return nil, ErrUnimplemented
	}
	nk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p, err := nk.ECDH(x.pub)
	if err != nil {
		return nil, err
	}
	key, iv, err := x.Next(p)
	if err != nil {
		return nil, err
	}
	cip, err := AES_CBC_IV(key, iv).Encrypt(msg)
	if err != nil {
		return nil, err
	}
	x.key = nk
	return slices.Concat(nk.PublicKey().Bytes(), cip), nil
}

func (x *Ratchet) Recv(cip []byte) ([]byte, error) {
	if x.key == nil || len(cip) <= 32 {
		return nil, ErrUnimplemented
	}
	np, err := ecdh.X25519().NewPublicKey(cip[:32])
	if err != nil {
		return nil, err
	}
	p, err := x.key.ECDH(np)
	if err != nil {
		return nil, err
	}
	key, iv, err := x.Next(p)
	if err != nil {
		return nil, err
	}
	msg, err := AES_CBC_IV(key, iv).Decrypt(cip[32:])
	if err != nil {
		return nil, err
	}
	x.pub = np
	return msg, nil
}

type RatchetA struct {
	*Ratchet
	IdentityKey  *ecdh.PrivateKey
	EphemeralKey *ecdh.PrivateKey
}

func (a *RatchetA) X3DH(IKB, SPKB, OPKB *ecdh.PublicKey) error {
	d1, err := a.IdentityKey.ECDH(SPKB)
	if err != nil {
		return err
	}
	d2, err := a.EphemeralKey.ECDH(IKB)
	if err != nil {
		return err
	}
	d3, err := a.EphemeralKey.ECDH(SPKB)
	if err != nil {
		return err
	}
	d4, err := a.EphemeralKey.ECDH(OPKB)
	if err != nil {
		return err
	}
	state, err := HKDF(nil, nil, 32, crypto.SHA256).Tag(slices.Concat(d1, d2, d3, d4))
	if err != nil {
		return err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	a.Ratchet = &Ratchet{state: state, key: key}
	return err
}

type RatchetB struct {
	*Ratchet
	IdentityKey   *ecdh.PrivateKey
	SignedPreKey  *ecdh.PrivateKey
	OneTimePreKey *ecdh.PrivateKey
}

func (b *RatchetB) X3DH(IKA, EKA *ecdh.PublicKey) error {
	d1, err := b.SignedPreKey.ECDH(IKA)
	if err != nil {
		return err
	}
	d2, err := b.IdentityKey.ECDH(EKA)
	if err != nil {
		return err
	}
	d3, err := b.SignedPreKey.ECDH(EKA)
	if err != nil {
		return err
	}
	d4, err := b.OneTimePreKey.ECDH(EKA)
	if err != nil {
		return err
	}
	state, err := HKDF(nil, nil, 32, crypto.SHA256).Tag(slices.Concat(d1, d2, d3, d4))
	if err != nil {
		return err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	b.Ratchet = &Ratchet{state: state, key: key}
	return err
}
