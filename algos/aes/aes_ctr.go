package aes

import (
	"crypto/aes"
	"encoding/binary"
)

func MakeStreamFunc(aesKey []byte, nonce uint64) func() []byte {
	blockSize := 16
	ctr := uint64(0)
	cipher, _ := aes.NewCipher(aesKey)

	return func() []byte {
		plainBlock := make([]byte, blockSize)
		binary.LittleEndian.PutUint64(plainBlock[:8], nonce)
		binary.LittleEndian.PutUint64(plainBlock[8:], ctr)
		ctr++

		cipherBlock := make([]byte, 16)
		cipher.Encrypt(cipherBlock, plainBlock)

		return cipherBlock
	}
}
