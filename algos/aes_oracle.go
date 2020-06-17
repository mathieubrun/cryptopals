package algos

import (
	"bytes"
	"encoding/base64"
	"math"
	"math/rand"
)

var aesKey = generateRandomBytes(16)

func GetHiddenText(hiddenTextLength int, blockSize int) []byte {

	blockCount := hiddenTextLength / blockSize

	// bytes can be discovered by padding known bytes before unknown bytes
	discoveredBytes := make([]byte, hiddenTextLength)
	paddingBytes := make([]byte, hiddenTextLength)

	for attackedBlock := 0; attackedBlock < blockCount; attackedBlock++ {
		for attackedByte := 0; attackedByte < blockSize; attackedByte++ {

			startOfBlock := attackedBlock * blockSize
			attackedBytePosition := hiddenTextLength - startOfBlock - attackedByte

			// get cypher bytes with 1 byte missing
			expectedBytesWithHiddenText := ECBEncryptionOracle(paddingBytes[:attackedBytePosition-1])
			expectedBytes := expectedBytesWithHiddenText[:hiddenTextLength]

			for i := byte(1); i < math.MaxUint8; i++ {

				// change last byte of padding
				paddingBytes[hiddenTextLength-1] = i

				candidatesBytesWithHiddenText := ECBEncryptionOracle(paddingBytes)
				candidatesBytes := candidatesBytesWithHiddenText[:hiddenTextLength]

				if bytes.Equal(expectedBytes, candidatesBytes) {
					discoveredBytes[startOfBlock+attackedByte] = i
					start := attackedBytePosition - 2
					if start > 0 {
						copy(paddingBytes[start:], discoveredBytes)
					}
					break
				}
			}
		}
	}

	return discoveredBytes
}

func DetectPaddedHiddenTextLength() int {
	blockSize := DetectBlockSize()

	return len(ECBEncryptionOracle(make([]byte, blockSize))) - blockSize
}

func DetectBlockSize() int {
	length := 1
	first := ECBEncryptionOracle(generateRandomBytes(length))
	second := ECBEncryptionOracle(generateRandomBytes(length))

	for len(second) == len(first) {
		length++
		second = ECBEncryptionOracle(generateRandomBytes(length))
	}

	return len(second) - len(first)
}

func ECBEncryptionOracle(plainBytes []byte) []byte {
	suffix, _ := base64.StdEncoding.DecodeString(
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
			"YnkK")

	plainBytes = append(plainBytes, suffix...)

	return EncryptECB(plainBytes, aesKey, 16)
}

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
