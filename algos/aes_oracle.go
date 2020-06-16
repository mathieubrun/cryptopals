package algos

import (
	"math/rand"
)

func EncryptionOracle(plainBytes []byte, ecb bool) []byte {
	// TODO: optimize
	plainBytes = append(generateRandomBytes(rand.Intn(10)), plainBytes...)
	plainBytes = append(plainBytes, generateRandomBytes(rand.Intn(10))...)
	plainBytes = PKCSPad(plainBytes, len(plainBytes)+len(plainBytes)%16)

	key := generateRandomBytes(16)
	if ecb {
		return EncryptECB(plainBytes, key, 16)
	}

	iv := generateRandomBytes(16)
	return EncryptCBC(plainBytes, key, iv, 16)
}
