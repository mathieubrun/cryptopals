package algos

import (
	"math"
	"sort"
)

func Xor(input []byte, key []byte) (result []byte) {
	inputLength := len(input)
	keyLength := len(key)

	result = make([]byte, inputLength)

	for i := 0; i < inputLength; i++ {
		result[i] = input[i] ^ key[i%keyLength]
	}

	return result
}

func GuessRepeatingKeyXor(input []byte) xorCandidate {

	candidatesToTry := 6
	keySizeCandidates := getKeySizeCandidates(input)
	candidates := make([]xorCandidate, candidatesToTry)

	// You could proceed perhaps with the smallest 2-3 KEYSIZE values.
	for i, size := range keySizeCandidates[:candidatesToTry] {

		keySize := size.keySize

		// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
		blocks := chunk(input, keySize)

		// Now transpose the blocks: make a block that is the first byte of every block,
		// and a block that is the second byte of every block, and so on.
		transposed := transpose(blocks)

		// Solve each block as if it was single-character XOR. You already have code to do this.
		// For each block, the single-byte XOR key that produces the best looking histogram
		// is the repeating-key XOR key byte for that block.
		// Put them together and you have the key.
		key := make([]byte, keySize)

		for i, _ := range key {
			key[i] = GuessSingleByteXorCipher(transposed[i]).Key[0]
		}

		candidates[i] = createCandidate(input, key)
	}

	return findBestCandidate(candidates)
}

func GuessLineEncodedWithSingleByteXorCipher(inputs [][]byte) xorCandidate {
	candidates := make([]xorCandidate, len(inputs))

	for i, input := range inputs {
		candidates[i] = GuessSingleByteXorCipher(input)
	}

	return findBestCandidate(candidates)
}

func GuessSingleByteXorCipher(input []byte) xorCandidate {
	candidates := make([]xorCandidate, math.MaxUint8)

	for i := range candidates {
		candidates[i] = createCandidate(input, []byte{byte(i)})
	}

	return findBestCandidate(candidates)
}

type keySizeCandidate struct {
	keySize      int
	editDistance float64
}

type xorCandidate struct {
	Input              []byte
	Key                []byte
	Plain              []byte
	characterFrequency map[byte]float64
	l2Norm             float64
}

func createCandidate(input []byte, key []byte) xorCandidate {
	plain := Xor(input, key)

	frequency := getByteFrequency(plain)

	return xorCandidate{
		input,
		key,
		plain,
		frequency,
		computeL2Norm(characterFrequency, frequency),
	}
}

func findBestCandidate(candidates []xorCandidate) xorCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		// smaller deviation from English character frequency is better
		return candidates[i].l2Norm < candidates[j].l2Norm
	})

	return candidates[0]
}

func getKeySizeCandidates(input []byte) []keySizeCandidate {
	var keySizeScores []keySizeCandidate

	// Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
	// For each KEYSIZE,
	for keySize := 2; keySize < 41; keySize++ {

		// take the first KEYSIZE worth of bytes,
		// and the second KEYSIZE worth of bytes,
		// Or take 4 KEYSIZE blocks instead of 2 and average the distances.

		blocksToCompare := 4
		keyBytesBlocks := chunk(input, keySize)[:blocksToCompare]
		editDistance := float64(0)

		// and find the edit distance between them.
		// Normalize this result by dividing by KEYSIZE.
		for i := 0; i < blocksToCompare; i += 2 {
			editDistance += float64(hamming(keyBytesBlocks[i], keyBytesBlocks[i+1])) / float64(keySize)
		}

		keySizeScores = append(keySizeScores, keySizeCandidate{
			keySize,
			editDistance / (float64(blocksToCompare) / float64(2)),
		})
	}

	// The KEYSIZE with the smallest normalized edit distance is probably the key.
	sort.Slice(keySizeScores, func(i, j int) bool {
		return keySizeScores[i].editDistance < keySizeScores[j].editDistance
	})

	return keySizeScores
}
