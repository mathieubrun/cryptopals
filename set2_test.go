package cryptopals_test

import (
	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Set2(t *testing.T) {

	t.Run("Challenge 9 : Implement PKCS#7 padding", func(t *testing.T) {
		// given
		input := "YELLOW SUBMARINE"
		expected := "YELLOW SUBMARINE\x04\x04\x04\x04"

		// when
		result := algos.PKCSPad([]byte(input), 20)

		// then
		assert.Equal(t, expected, string(result))
	})

	t.Run("Challenge 10 : Implement CBC mode", func(t *testing.T) {
		// given
		input, err := utils.ReadBase64File("data/set2_challenge10.txt")
		key := []byte("YELLOW SUBMARINE")
		iv := []byte{0,0,0,0,0}
		expected := "I'm back and I'm ringin' the bell \nA"

		// when
		result := algos.DecryptCBC(input, key, iv, 16)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expected, string(result)[:36])
	})
}
