package cryptopals_test

import (
	"encoding/base64"
	"fmt"
	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/algos/xor"
	"testing"

	"github.com/mathieubrun/cryptopals/algos/aes"
	"github.com/mathieubrun/cryptopals/algos/aes_attacks"

	"github.com/stretchr/testify/assert"
)

func Test_Set3(t *testing.T) {
	for idx, expected := range aes.CBCPaddingOracleCipherBytes {
		t.Run(fmt.Sprintf("Challenge 17 : The CBC padding oracle %d", idx), func(t *testing.T) {
			// given
			aesKey := algos.GenerateRandomBytes(16)
			cipherGenerator := aes.MakeCBCPaddingOracle(aesKey, idx)
			paddingOracle := func(cipherBytes []byte, iv []byte) bool {
				return aes.CheckCBCPadding(cipherBytes, aesKey, iv)
			}

			// when
			result, err := aes_attacks.AesCBCPadding(cipherGenerator, paddingOracle)

			// then
			assert.NoError(t, err)
			assert.Equal(t, expected, string(result))
		})
	}

	t.Run("Challenge 18 : Implement CTR, the stream cipher mode", func(t *testing.T) {
		// given
		expected := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
		blockSize := 16
		cipherBytes, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
		nonce := uint64(0)
		makeBytes := aes.MakeStreamFunc([]byte("YELLOW SUBMARINE"), nonce)

		// when
		plainBytes := make([]byte, len(cipherBytes))
		for b := 0; b <= len(cipherBytes)/16; b++ {
			keyMaterial := makeBytes()

			start := b*blockSize
			end := start + blockSize
			if len(cipherBytes) < end {
				end = len(cipherBytes)
			}

			copy(plainBytes[start:end], xor.Xor(cipherBytes[start:end], keyMaterial))
		}

		// then
		assert.Equal(t, expected, string(plainBytes))
	})
}
