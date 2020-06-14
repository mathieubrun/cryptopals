package algos

import (
	"crypto/aes"
	"sort"
)

func DecryptCBC(cipherBytes []byte, key []byte, iv []byte, size int) []byte {
	previous := iv
	plainBytes := make([]byte, len(cipherBytes))

	for start := 0; start < len(cipherBytes); start += size {
		plainBlock := DecryptECB(cipherBytes[start:start+size], key, size)
		copy(plainBytes[start:start+size], Xor(plainBlock, previous))
		previous = cipherBytes[start:start+size]
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

type ecbCandidate struct {
	LineNumber      int
	Input           []byte
	KeySize         int
	DuplicateBlocks int
}

func DetectECB(inputs [][]byte) ecbCandidate {
	var candidates []ecbCandidate

	// aes can use 3 keysizes
	for _, keySize := range []int{16, 24, 32} {
		for line, input := range inputs {

			// assume ciphertext length is multiple of keysize
			if len(input)%keySize == 0 {

				candidate := ecbCandidate{
					line,
					input,
					keySize,
					0,
				}

				chunks := chunk(input, keySize)

				// compare blocks
				for i, chunk1 := range chunks {
					for j, chunk2 := range chunks {

						// once
						if j <= i {
							continue
						}

						// if hamming distance is 0, blocks are the same
						if hamming(chunk1, chunk2) == 0 {
							candidate.DuplicateBlocks++
						}
					}
				}

				candidates = append(candidates, candidate)
			}
		}
	}

	return findBestECBCandidate(candidates)
}

func findBestECBCandidate(candidates []ecbCandidate) ecbCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		// smaller deviation from English character frequency is better
		return candidates[i].DuplicateBlocks > candidates[j].DuplicateBlocks
	})

	return candidates[0]
}
