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
		iv := []byte{0, 0, 0, 0, 0}
		expected := "I'm back and I'm ringin' the bell \nA"

		// when
		result := algos.DecryptCBC(input, key, iv, 16)

		// then
		assert.NoError(t, err)
		assert.Equal(t, expected, string(result)[:36])
	})

	t.Run("Challenge 11 : An ECB/CBC detection oracle", func(t *testing.T) {
		// given
		fourBlocks := []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

		// simplier to ask to oracle to g
		ecb := algos.EncryptionOracle(fourBlocks, true)
		cbc := algos.EncryptionOracle(fourBlocks, false)

		// when
		resultECB := algos.IsECB(ecb)
		resultCBC := algos.IsECB(cbc)

		// then
		assert.Equal(t, resultCBC, false)
		assert.Equal(t, resultECB, true)
	})

	t.Run("Challenge 12 : Byte-at-a-time ECB decryption (Simple)", func(t *testing.T) {
		// given
		fourBlocks := []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
		expectedBlockSize := 16
		expectedHiddenTextSize := 144
		expectedHiddenText := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01\x02\x03\x04\x05\x06"

		// when
		hiddenTextSize := algos.DetectPaddedHiddenTextLength()
		blockSize := algos.DetectBlockSize()
		isECB := algos.IsECB(algos.ECBEncryptionOracle(fourBlocks))
		hiddenText := algos.GetHiddenText(hiddenTextSize, blockSize)

		// then
		assert.Equal(t, expectedBlockSize, blockSize)
		assert.Equal(t, expectedHiddenTextSize, hiddenTextSize)
		assert.Equal(t, expectedHiddenText, string(hiddenText))
		assert.Equal(t, true, isECB)
	})

	t.Run("Challenge 13 : ECB cut-and-paste", func(t *testing.T) {
		// given
		encryptedProfile := algos.EncryptProfile("test@example.com")

		// when
		profile, err := algos.DecryptProfile(encryptedProfile)
		fakeProfile := algos.ECBCutAndPaste()
		fakeProfileDecrypted, err := algos.DecryptProfile(fakeProfile)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "test@example.com", profile.Email)
		assert.Equal(t, "admin", fakeProfileDecrypted.Role)
	})
}
