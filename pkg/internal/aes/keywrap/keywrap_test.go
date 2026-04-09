package keywrap_test

import (
	"crypto"
	"crypto/aes"
	"testing"

	"github.com/gunawanwijaya/diego/pkg"
	"github.com/gunawanwijaya/diego/pkg/internal/aes/keywrap"
	"github.com/stretchr/testify/require"
)

func TestCrypto__KeyWrap(t *testing.T) {
	salt := []byte{130, 225, 9, 214, 88, 153, 91, 219, 39, 98, 91, 41, 18, 249, 179, 244}
	wrapper := pkg.Must1(pkg.PBKDF2(salt, 100_000, 32, crypto.SHA256).Tag([]byte("password")))
	block := pkg.Must1(aes.NewCipher(wrapper))

	key := []byte{176, 191, 186, 56, 30, 139, 159, 27, 124, 71, 9, 144, 183, 12, 89, 174, 222, 0, 54, 99, 136, 66, 69, 75, 27, 170, 65, 161, 186, 47, 156, 235}
	wkA := pkg.Must1(keywrap.WrapA(wrapper, key))
	wkB := pkg.Must1(keywrap.WrapB(block, key))

	o := []byte{115, 80, 209, 64, 224, 95, 86, 29, 186, 118, 182, 108, 176, 121, 242, 101, 191, 170, 139, 130, 192, 96, 76, 93, 109, 63, 208, 54, 16, 187, 117, 202, 217, 83, 118, 234, 114, 226, 11, 174}
	require.Equal(t, wkA, wkB)
	require.Equal(t, wkA, o)
	require.Equal(t, wkB, o)
	require.Equal(t, pkg.Must1(keywrap.UnwrapA(wrapper, wkA)), key)
	require.Equal(t, pkg.Must1(keywrap.UnwrapB(block, wkB)), key)
}
