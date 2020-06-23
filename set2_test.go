package cryptopals_test

import (
	"testing"

	"github.com/mathieubrun/cryptopals/algos/aes"
	"github.com/mathieubrun/cryptopals/algos/aes_attacks"

	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/utils"

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
		iv := []byte{0, 0, 0, 0, 0}
		expected := "I'm back and I'm ringin' the bell \nA"

		// when
		result, _ := aes.DecryptCBC(input, key, iv, 16)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expected, string(result)[:36])
	})

	t.Run("Challenge 11 : An ECB/CBC detection oracle", func(t *testing.T) {
		// given
		fourBlocks := []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

		// simplier to ask to oracle to g
		ecb := aes.EncryptionOracle(fourBlocks, true)
		cbc := aes.EncryptionOracle(fourBlocks, false)

		// when
		resultECB := aes_attacks.IsECB(ecb)
		resultCBC := aes_attacks.IsECB(cbc)

		// then
		assert.Equal(t, resultCBC, false)
		assert.Equal(t, resultECB, true)
	})

	t.Run("Challenge 12 : Byte-at-a-time ECB decryption (Simple)", func(t *testing.T) {
		// given
		fourBlocks := []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
		expectedBlockSize := 16
		expectedHiddenTextSize := 138
		expectedPaddingSize := 6
		expectedHiddenText := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
		randomKey := algos.GenerateRandomBytes(16)
		oracle := aes.MakeECBEncryptionOracle(randomKey, nil, expectedBlockSize)

		// when
		blockSize := aes_attacks.DetectBlockSize(oracle)
		paddingSize := aes_attacks.DetectPaddingLength(0, blockSize, oracle)
		hiddenTextSize := aes_attacks.DetectHiddenTextLength(0, paddingSize, blockSize, oracle)
		isECB := aes_attacks.IsECB(oracle(fourBlocks))
		hiddenText := aes_attacks.DetectHiddenText(0, hiddenTextSize, paddingSize, blockSize, oracle)

		// then
		assert.Equal(t, expectedBlockSize, blockSize)
		assert.Equal(t, expectedPaddingSize, paddingSize)
		assert.Equal(t, expectedHiddenTextSize, hiddenTextSize)
		assert.Equal(t, expectedHiddenText, string(hiddenText))
		assert.Equal(t, true, isECB)
	})

	t.Run("Challenge 13 : ECB cut-and-paste", func(t *testing.T) {
		// given
		encryptedProfile := aes_attacks.EncryptProfile("test@example.com")

		// when
		profile, err := aes_attacks.DecryptProfile(encryptedProfile)
		fakeProfile := aes_attacks.ECBCutAndPaste()
		fakeProfileDecrypted, err := aes_attacks.DecryptProfile(fakeProfile)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "test@example.com", profile.Email)
		assert.Equal(t, "admin", fakeProfileDecrypted.Role)
	})

	t.Run("Challenge 14 : Byte-at-a-time ECB decryption (Harder)", func(t *testing.T) {
		// given
		fourBlocks := []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
		expectedPrefixSize := 21
		expectedBlockSize := 16
		expectedHiddenTextSize := 138
		expectedPaddingSize := 6
		expectedHiddenText := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
		randomKey := algos.GenerateRandomBytes(16)
		randomPrefix := algos.GenerateRandomBytes(expectedPrefixSize)
		oracle := aes.MakeECBEncryptionOracle(randomKey, randomPrefix, expectedBlockSize)

		// when
		blockSize := aes_attacks.DetectBlockSize(oracle)
		prefixLength := aes_attacks.DetectPrefixLength(blockSize, oracle)
		paddingSize := aes_attacks.DetectPaddingLength(prefixLength, blockSize, oracle)
		hiddenTextSize := aes_attacks.DetectHiddenTextLength(prefixLength, paddingSize, blockSize, oracle)
		isECB := aes_attacks.IsECB(oracle(fourBlocks))
		hiddenText := aes_attacks.DetectHiddenText(prefixLength, hiddenTextSize, paddingSize, blockSize, oracle)

		// then
		assert.Equal(t, expectedBlockSize, blockSize)
		assert.Equal(t, expectedPaddingSize, paddingSize)
		assert.Equal(t, expectedPrefixSize, prefixLength)
		assert.Equal(t, expectedHiddenTextSize, hiddenTextSize)
		assert.Equal(t, expectedHiddenText, string(hiddenText))
		assert.Equal(t, true, isECB)
	})

	t.Run("Challenge 15 : PKCS#7 padding validation", func(t *testing.T) {
		// given
		validPadding := []byte("ICE ICE BABY\x04\x04\x04\x04")
		expectedResult := []byte("ICE ICE BABY")
		invalidPadding := []byte("ICE ICE BABY\x05\x05\x05\x05")

		// when
		valid, _ := algos.RemovePKCSPad(validPadding)
		_, err := algos.RemovePKCSPad(invalidPadding)

		// then
		assert.Error(t, err)
		assert.Equal(t, expectedResult, valid)
	})
}
