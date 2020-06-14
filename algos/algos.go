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

func Hamming(b1 []byte, b2 []byte) int {

	setBitCount := 0
	for i, b := range b1 {
		xor := b ^ b2[i]

		for xor > 0 {
			setBitCount += int(xor & byte(1))
			xor >>= 1
		}
	}

	return setBitCount
}

type keySizeCandidate struct {
	keySize int
	score   float64
}

func GuessRepeatingKeyXor(input []byte) xorCandidate {

	candidatesToTry := 6
	keySizeCandidates := getKeySizeCandidates(input)
	candidates := make([]xorCandidate, candidatesToTry)

	for i, size := range keySizeCandidates[:candidatesToTry] {

		// You could proceed perhaps with the smallest 2-3 KEYSIZE values.
		// Or take 4 KEYSIZE blocks instead of 2 and average the distances.
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

func getKeySizeCandidates(input []byte) []keySizeCandidate {
	var keySizeScores []keySizeCandidate

	// Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
	// For each KEYSIZE,
	for keySize := 2; keySize < 41; keySize++ {

		// take the first KEYSIZE worth of bytes,
		b1 := input[0*keySize : 1*keySize]

		// and the second KEYSIZE worth of bytes,
		b2 := input[1*keySize : 2*keySize]

		b3 := input[2*keySize : 3*keySize]
		b4 := input[3*keySize : 4*keySize]

		// and find the edit distance between them.
		// Normalize this result by dividing by KEYSIZE.
		keySizeScores = append(keySizeScores, keySizeCandidate{
			keySize,
			(float64(Hamming(b1, b2))/float64(keySize) + float64(Hamming(b3, b4))/float64(keySize)) / 2,
		})
	}

	// The KEYSIZE with the smallest normalized edit distance is probably the key.
	sort.Slice(keySizeScores, func(i, j int) bool {
		return keySizeScores[i].score < keySizeScores[j].score
	})

	return keySizeScores
}

func transpose(blocks [][]byte) [][]byte {
	transposed := make([][]byte, len(blocks[0]))

	for i, _ := range transposed {
		transposed[i] = make([]byte, len(blocks))

		for j, block := range blocks {
			transposed[i][j] = block[i]
		}
	}

	return transposed
}

func chunk(input []byte, size int) [][]byte {
	chunks := len(input) / size
	result := make([][]byte, chunks)

	for i := 0; i < chunks; i++ {
		result[i] = input[i*size : (i+1)*size]
	}

	return result
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

type xorCandidate struct {
	Input              []byte
	Key                []byte
	Plain              []byte
	characterFrequency map[byte]float64
	l2Norm             float64
}

func findBestCandidate(candidates []xorCandidate) xorCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		// smaller deviation from English character frequency is better
		return candidates[i].l2Norm < candidates[j].l2Norm
	})

	return candidates[0]
}

func computeL2Norm(v1 map[byte]float64, v2 map[byte]float64) (result float64) {
	for k, v := range v1 {
		result += math.Pow(v2[k]-v, 2)
	}

	return math.Sqrt(result)
}

func getByteFrequency(input []byte) map[byte]float64 {
	result := make(map[byte]float64, len(characterFrequency))

	// ensure all characters are present in frequency distribution
	for k := range characterFrequency {
		result[k] = 0
	}

	occurrence := 1 / float64(len(input))
	for _, v := range input {
		if _, found := characterFrequency[v]; found {
			result[v] += occurrence
		}
	}

	return result
}
