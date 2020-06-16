package algos

import (
	"crypto/aes"
)

func DecryptCBC(cipherBytes []byte, key []byte, iv []byte, size int) []byte {
	previous := iv
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		plainBlock := DecryptECB(cipherBytes[start:start+size], key, size)
		copy(plainBytes[start:start+size], Xor(plainBlock, previous))
		previous = cipherBytes[start : start+size]
	}

	return plainBytes
}

func EncryptCBC(plainBytes []byte, key []byte, iv []byte, size int) []byte {
	previous := iv
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		previous = EncryptECB(Xor(plainBytes[start:start+size], previous), key, size)
		copy(cipherBytes[start:start+size], previous)
	}

	return cipherBytes
}

func DecryptECB(cipherBytes []byte, key []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		cipher.Decrypt(plainBytes[start:start+size], cipherBytes[start:start+size])
	}

	return plainBytes
}

func EncryptECB(plainBytes []byte, key []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		cipher.Encrypt(cipherBytes[start:start+size], plainBytes[start:start+size])
	}

	return cipherBytes
}

