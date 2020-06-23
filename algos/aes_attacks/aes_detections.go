package aes_attacks

import (
	"bytes"
	"github.com/mathieubrun/cryptopals/algos"
	"math"
)

func DetectHiddenText(prefixLen int, hiddenTextLen int, paddingLen int, blockSize int, oracle func(plainBytes []byte) []byte) []byte {

	prefixPaddingLen := getPrefixPaddingLen(prefixLen, blockSize)

	hiddenTextWithPaddingLen := hiddenTextLen + paddingLen

	discoveredBytes := make([]byte, hiddenTextWithPaddingLen)

	// bytes can be discovered by padding known bytes before unknown bytes
	// and adding padding bytes after prefix
	attackBytes := make([]byte, hiddenTextWithPaddingLen+prefixPaddingLen)

	offset := prefixLen + prefixPaddingLen

	for byteToDiscover := 0; byteToDiscover < hiddenTextWithPaddingLen; byteToDiscover++ {

		attackedByteIndex := len(attackBytes) - byteToDiscover - 1

		// get cypher bytes with 1 byte missing
		expectedBytesWithHiddenText := oracle(attackBytes[:attackedByteIndex])
		expectedBytes := expectedBytesWithHiddenText[offset : offset+hiddenTextLen]

		for i := byte(0); i < math.MaxUint8; i++ {

			// change last byte
			attackBytes[len(attackBytes)-1] = i

			candidatesBytesWithHiddenText := oracle(attackBytes)
			candidatesBytes := candidatesBytesWithHiddenText[offset : offset+hiddenTextLen]

			if bytes.Equal(expectedBytes, candidatesBytes) {
				discoveredBytes[byteToDiscover] = i
				if attackedByteIndex > 1 {
					copy(attackBytes[attackedByteIndex-1:], discoveredBytes)
				}
				break
			}
		}
	}

	return discoveredBytes[:hiddenTextLen]
}

func DetectHiddenTextLength(prefixLen int, paddingLen int, blockSize int, oracle func(plainBytes []byte) []byte) int {
	attackBytes := make([]byte, getPrefixPaddingLen(prefixLen, blockSize))

	// feed them to the oracle
	targetBytes := oracle(attackBytes)

	return len(targetBytes) - len(attackBytes) - paddingLen - prefixLen
}

func DetectPrefixLength(blockSize int, oracle func(plainBytes []byte) []byte) int {
	prefixPadding := 0
	identicalBlockCount := 5
	firstIdenticalBlockIndex, identicalBlockFound := 0, 1

	for p := 0; identicalBlockFound != identicalBlockCount; p++ {
		// generate identical bytes
		attackBytes := make([]byte, blockSize*identicalBlockCount+p)

		// feed them to the oracle
		targetBytes := oracle(attackBytes)
		cipherBytesLen := len(targetBytes)

		// find identical blocks in response
		firstIdenticalBlockIndex, identicalBlockFound = countIdentialBlocks(blockSize, cipherBytesLen, targetBytes)
		prefixPadding = p
	}

	return firstIdenticalBlockIndex*blockSize - prefixPadding
}

func DetectPaddingLength(prefixLen int, blockSize int, oracle func(plainBytes []byte) []byte) int {
	offset := getPrefixPaddingLen(prefixLen, blockSize)

	size := 0
	first := oracle(algos.GenerateRandomBytes(size + offset))
	second := oracle(algos.GenerateRandomBytes(size + offset))

	for len(second) == len(first) {
		size++
		second = oracle(algos.GenerateRandomBytes(size + offset))
	}

	return size
}

func DetectBlockSize(oracle func(plainBytes []byte) []byte) int {
	length := 1
	first := oracle(algos.GenerateRandomBytes(length))
	second := oracle(algos.GenerateRandomBytes(length))

	for len(second) == len(first) {
		length++
		second = oracle(algos.GenerateRandomBytes(length))
	}

	return len(second) - len(first)
}

func getPrefixPaddingLen(prefixLen int, blockSize int) int {
	return (blockSize - prefixLen%blockSize) % blockSize
}

func countIdentialBlocks(blockSize int, cipherBytesLen int, targetBytes []byte) (int, int) {
	firstIdenticalBlockIndex := 0
	identicalBlockFound := 0

	for i := 1; i < cipherBytesLen/blockSize; i++ {
		if algos.Hamming(targetBytes[i*blockSize-blockSize:i*blockSize], targetBytes[i*blockSize:i*blockSize+blockSize]) == 0 {
			firstIdenticalBlockIndex = i
			identicalBlockFound++
		}
	}

	return firstIdenticalBlockIndex - identicalBlockFound, identicalBlockFound + 1
}
