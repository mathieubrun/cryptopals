package cryptopals_test

import (
	"fmt"
	"github.com/mathieubrun/cryptopals/algos"
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
}
