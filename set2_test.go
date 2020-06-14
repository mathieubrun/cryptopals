package cryptopals_test

import (
	"github.com/mathieubrun/cryptopals/algos"
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
}
