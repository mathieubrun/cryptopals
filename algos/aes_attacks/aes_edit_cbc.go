package aes_attacks

import (
	"github.com/mathieubrun/cryptopals/algos/xor"
	"strings"
)

func EditCBC(blockSize int, editBytes []byte, oracle func(plainBytes []byte) []byte) []byte {

	start := 48
	end := start + len(editBytes)
	attackText := []byte(strings.Repeat("a", blockSize * 4))

	// when
	cipherBytes := oracle(attackText)
	editedBytes := cipherBytes[:]
	copy(editedBytes[start:end], xor.Xor(cipherBytes[start:end], []byte(strings.Repeat("a", len(editBytes)))))
	copy(editedBytes[start:end], xor.Xor(cipherBytes[start:end], editBytes))

	return editedBytes
}
