package pkg

import (
	"crypto"
	"crypto/ecdh"
	"slices"
)

// Identity naively implement https://blog.jauhar.dev/blog/2025/07/30/x3dh-making-sense-of-signals-key-exchange
type Identity struct {
	IdentityKey   *ecdh.PrivateKey
	SignedPreKey  *ecdh.PrivateKey
	OneTimePreKey []*ecdh.PrivateKey
}

func (*Identity) hkdf(p ...[]byte) ([]byte, error) {
	return HKDF(nil, nil, 32, crypto.SHA256).Tag(slices.Concat(p...))
}

func (a *Identity) ECDH(b *ecdh.PublicKey) ([]byte, error) {
	return a.IdentityKey.ECDH(b)
}

func (a *Identity) ECTwoDH_A(bIK, bSPK *ecdh.PublicKey, aEK *ecdh.PrivateKey) ([]byte, error) {
	dh1, err := aEK.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	dh2, err := a.IdentityKey.ECDH(bIK)
	if err != nil {
		return nil, err
	}
	return a.hkdf(dh1, dh2)
}

func (b *Identity) ECTwoDH_B(aIK, aEK *ecdh.PublicKey) ([]byte, error) {
	dh1, err := b.SignedPreKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	dh2, err := b.IdentityKey.ECDH(aIK)
	if err != nil {
		return nil, err
	}
	return b.hkdf(dh1, dh2)
}

func (a *Identity) EC2DH_A(bIK, bSPK *ecdh.PublicKey, aEK *ecdh.PrivateKey) ([]byte, error) {
	dh1, err := a.IdentityKey.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	dh2, err := aEK.ECDH(bIK)
	if err != nil {
		return nil, err
	}
	return a.hkdf(dh1, dh2)
}

func (b *Identity) EC2DH_B(aIK, aEK *ecdh.PublicKey) ([]byte, error) {
	dh1, err := b.SignedPreKey.ECDH(aIK)
	if err != nil {
		return nil, err
	}
	dh2, err := b.IdentityKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	return b.hkdf(dh1, dh2)
}

func (a *Identity) EC3DH_A(bIK, bSPK *ecdh.PublicKey, aEK *ecdh.PrivateKey) ([]byte, error) {
	dh1, err := a.IdentityKey.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	dh2, err := aEK.ECDH(bIK)
	if err != nil {
		return nil, err
	}
	dh3, err := aEK.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	return a.hkdf(dh1, dh2, dh3)
}

func (b *Identity) EC3DH_B(aIK, aEK *ecdh.PublicKey) ([]byte, error) {
	dh1, err := b.SignedPreKey.ECDH(aIK)
	if err != nil {
		return nil, err
	}
	dh2, err := b.IdentityKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	dh3, err := b.SignedPreKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	return b.hkdf(dh1, dh2, dh3)
}

func (a *Identity) ECX3DH_A(bIK, bSPK, bOPK *ecdh.PublicKey, aEK *ecdh.PrivateKey) ([]byte, error) {
	dh1, err := a.IdentityKey.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	dh2, err := aEK.ECDH(bIK)
	if err != nil {
		return nil, err
	}
	dh3, err := aEK.ECDH(bSPK)
	if err != nil {
		return nil, err
	}
	dh4, err := aEK.ECDH(bOPK)
	if err != nil {
		return nil, err
	}
	return a.hkdf(dh1, dh2, dh3, dh4)
}

func (b *Identity) ECX3DH_B(aIK, aEK, bOPK *ecdh.PublicKey) ([]byte, error) {
	dh1, err := b.SignedPreKey.ECDH(aIK)
	if err != nil {
		return nil, err
	}
	dh2, err := b.IdentityKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	dh3, err := b.SignedPreKey.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	var opk *ecdh.PrivateKey
	for _, v := range b.OneTimePreKey {
		if bOPK.Equal(v.PublicKey()) {
			opk = v
			break
		}
	}
	if opk == nil {
		return nil, ErrorStr("invalid one-time pre key")
	}
	dh4, err := opk.ECDH(aEK)
	if err != nil {
		return nil, err
	}
	return b.hkdf(dh1, dh2, dh3, dh4)
}
