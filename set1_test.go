package cryptopals_test

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/utils"
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

	t.Run("Challenge 2 : Fixed XOR", func(t *testing.T) {
		// given
		input, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
		key, _ := hex.DecodeString("686974207468652062756c6c277320657965")
		expected, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")

		// when
		result := algos.Xor(input, key)

		// then
		assert.Equal(t, expected, result)
	})

	t.Run("Challenge 3 : Single-byte XOR cipher", func(t *testing.T) {
		// given
		input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		expected := "Cooking MC's like a pound of bacon"
		expectedKey := []byte{0x58}

		// when
		result := algos.GuessSingleByteXorCipher(input)

		// then
		assert.Equal(t, expectedKey, result.Key)
		assert.Equal(t, expected, string(result.Plain))
	})

	t.Run("Challenge 4 : Detect single-character XOR", func(t *testing.T) {
		// given
		inputs, err := utils.ReadLines("data/set1_challenge4.txt")
		expected := "Now that the party is jumping\n"
		expectedKey := []byte{0x35}

		// when
		result := algos.GuessLineEncodedWithSingleByteXorCipher(inputs)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, result.Key)
		assert.Equal(t, expected, string(result.Plain))
	})

	t.Run("Challenge 5 : Implement repeating-key XOR", func(t *testing.T) {
		// given
		input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
		key := []byte("ICE")
		expected, _ := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

		// when
		result := algos.Xor(input, key)

		// then
		assert.Equal(t, expected, result)
	})

	t.Run("Challenge 6 : Break repeating-key XOR", func(t *testing.T) {
		// given
		input, err := utils.ReadBase64File("data/set1_challenge6.txt")
		expectedKey := []byte("Terminator X: Bring the noise")
		expected := "I'm back and I'm ringin' the bell"

		// when
		result := algos.GuessRepeatingKeyXor(input)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, result.Key)
		assert.Equal(t, expected, string(result.Plain)[:33])
	})

	t.Run("Challenge 7 : AES in ECB mode", func(t *testing.T) {
		// given
		input, err := utils.ReadBase64File("data/set1_challenge7.txt")
		key := []byte("YELLOW SUBMARINE")
		expected := "I'm back and I'm ringin' the bell"

		// when
		result := algos.DecryptECB(input, key, 16)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expected, string(result)[:33])
	})

	t.Run("Challenge 8 : Detect AES in ECB mode", func(t *testing.T) {
		// given
		input, err := utils.ReadLines("data/set1_challenge8.txt")
		expectedLine := 132

		// when
		result := algos.DetectECB(input)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expectedLine, result.LineNumber)
	})
}
