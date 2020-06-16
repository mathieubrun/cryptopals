package algos

import (
	"sort"
)

func DetectECBOrCBC(cipherbytes []byte) string {

	candidate := DetectECB([][]byte{cipherbytes})

	if candidate.DuplicateBlocks > 0 {
		return "ECB"
	}

	return "CBC"
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
