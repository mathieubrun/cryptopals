package aes

import (
	"crypto/aes"
	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/algos/xor"
)

func EncryptECB(plainBytes []byte, key []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	plainBytes = algos.PKCSPadToBlockSize(plainBytes, size)
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		cipher.Encrypt(cipherBytes[start:start+size], plainBytes[start:start+size])
	}

	return cipherBytes
}

func DecryptECB(cipherBytes []byte, key []byte, size int) ([]byte, error) {
	cipher, _ := aes.NewCipher(key)
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		cipher.Decrypt(plainBytes[start:start+size], cipherBytes[start:start+size])
	}

	plain, err := algos.RemovePKCSPad(plainBytes)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func EncryptCBC(plainBytes []byte, key []byte, iv []byte, size int) []byte {
	cipher, _ := aes.NewCipher(key)
	previous := iv
	plainBytes = algos.PKCSPadToBlockSize(plainBytes, size)
	cipherBytes := make([]byte, len(plainBytes))

	for start := 0; start < len(plainBytes); start += size {
		cipher.Encrypt(cipherBytes[start:start+size], xor.Xor(plainBytes[start:start+size], previous))
		previous = cipherBytes[start : start+size]
	}

	return cipherBytes
}

func DecryptCBC(cipherBytes []byte, key []byte, iv []byte, size int) ([]byte, error) {
	cipher, _ := aes.NewCipher(key)
	previous := iv
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		cipher.Decrypt(plainBytes[start:start+size], cipherBytes[start:start+size])
		xor.XorInPlace(plainBytes[start:start+size], previous)
		previous = cipherBytes[start : start+size]
	}

	plain, err := algos.RemovePKCSPad(plainBytes)
	if err != nil {
		return nil, err
	}

	return plain, nil
}
