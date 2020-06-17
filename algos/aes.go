package algos

import (
	"crypto/aes"
)

func EncryptECB(plainBytes []byte, key []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	plainBytes = PKCSPadToBlockSize(plainBytes, size)
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		cipher.Encrypt(cipherBytes[start:start+size], plainBytes[start:start+size])
	}

	return cipherBytes
}

func DecryptECB(cipherBytes []byte, key []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		cipher.Decrypt(plainBytes[start:start+size], cipherBytes[start:start+size])
	}

	padCount := int(plainBytes[len(plainBytes)-1])
	return plainBytes[:len(plainBytes)-padCount]
}

func EncryptCBC(plainBytes []byte, key []byte, iv []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	previous := iv
	plainBytes = PKCSPadToBlockSize(plainBytes, size)
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		cipher.Encrypt(cipherBytes[start:start+size], Xor(plainBytes[start:start+size], previous))
		previous = cipherBytes[start:start+size]
	}

	return cipherBytes
}

func DecryptCBC(cipherBytes []byte, key []byte, iv []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	previous := iv
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		cipher.Decrypt(plainBytes[start:start+size], cipherBytes[start:start+size])
		XorInPlace(plainBytes[start:start+size], previous)
		previous = cipherBytes[start : start+size]
	}

	padCount := int(plainBytes[len(plainBytes)-1])
	return plainBytes[:len(plainBytes)-padCount]
}
