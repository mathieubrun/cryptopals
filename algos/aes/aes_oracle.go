package aes

import (
	"encoding/base64"
	"github.com/mathieubrun/cryptopals/algos"
	"math/rand"
)

func MakeECBEncryptionOracle(aesKey []byte, prefix []byte, blockSize int) func(plainBytes []byte) []byte {
	return func(plainBytes []byte) []byte {
		suffix, _ := base64.StdEncoding.DecodeString(
			"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
				"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
				"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
				"YnkK")

		plainBytes = append(prefix, plainBytes...)
		plainBytes = append(plainBytes, suffix...)

		return EncryptECB(plainBytes, aesKey, blockSize)
	}
}

func EncryptionOracle(plainBytes []byte, ecb bool) []byte {
	// TODO: optimize
	plainBytes = append(algos.GenerateRandomBytes(rand.Intn(10)), plainBytes...)
	plainBytes = append(plainBytes, algos.GenerateRandomBytes(rand.Intn(10))...)
	plainBytes = algos.PKCSPad(plainBytes, len(plainBytes)+len(plainBytes)%16)

	key := algos.GenerateRandomBytes(16)
	if ecb {
		return EncryptECB(plainBytes, key, 16)
	}

	iv := algos.GenerateRandomBytes(16)
	return EncryptCBC(plainBytes, key, iv, 16)
}