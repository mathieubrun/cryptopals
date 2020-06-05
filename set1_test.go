package cryptopals_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Set1(t *testing.T) {

	t.Run("Challenge 1 : Convert hex to base64", func(t *testing.T) {
		// given
		hexStr := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

		// when
		bytes, _ := hex.DecodeString(hexStr)
		result := base64.StdEncoding.EncodeToString(bytes)

		// then
		assert.Equal(t, expected, result)
	})
}
