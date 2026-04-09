// MIT License

// Copyright (c) 2017 Nick Ball

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package keywrap_test

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	. "github.com/gunawanwijaya/diego/pkg/internal/aes/keywrap"
	"github.com/stretchr/testify/assert"
)

type input struct {
	Case     string
	Kek      string
	Data     string
	Expected string
}

func TestWrapRfc3394Vectors(t *testing.T) {
	vectors := []input{
		{
			Case:     "4.1 Wrap 128 bits of Key Data with a 128-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F",
			Data:     "00112233445566778899AABBCCDDEEFF",
			Expected: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			Case:     "4.2 Wrap 128 bits of Key Data with a 192-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F1011121314151617",
			Data:     "00112233445566778899AABBCCDDEEFF",
			Expected: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			Case:     "4.3 Wrap 128 bits of Key Data with a 256-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Data:     "00112233445566778899AABBCCDDEEFF",
			Expected: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			Case:     "4.4 Wrap 192 bits of Key Data with a 192-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F1011121314151617",
			Data:     "00112233445566778899AABBCCDDEEFF0001020304050607",
			Expected: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			Case:     "4.5 Wrap 192 bits of Key Data with a 256-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Data:     "00112233445566778899AABBCCDDEEFF0001020304050607",
			Expected: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			Case:     "4.6 Wrap 256 bits of Key Data with a 256-bit KEK",
			Kek:      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			Data:     "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			Expected: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}

	for _, v := range vectors {
		kek := mustHexDecode(v.Kek)
		data := mustHexDecode(v.Data)
		exp := mustHexDecode(v.Expected)

		cipher, err := aes.NewCipher(kek)
		if !assert.NoError(t, err, "NewCipher should not fail!") {
			continue
		}

		actual, err := WrapB(cipher, data)
		if !assert.NoError(t, err, "Wrap should not throw error with valid input") {
			continue
		}
		if !assert.Equal(t, exp, actual, "Wrap Mismatch: Actual wrapped ciphertext should equal expected for test case '%s'", v.Case) {
			continue
		}

		actualUnwrapped, err := UnwrapB(cipher, actual)
		if !assert.NoError(t, err, "Unwrap should not throw error with valid input") {
			continue
		}
		if !assert.Equal(t, data, actualUnwrapped, "Unwrap Mismatch: Actual unwrapped ciphertext should equal the original data for test case '%s'", v.Case) {
			continue
		}
	}
}

func mustHexDecode(s string) (b []byte) {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
