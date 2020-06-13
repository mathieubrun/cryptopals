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

func GuessLineEncodedWithSingleByteXorCipher(inputs [][]byte) singleByteXorCandidate {
	candidates := make([]singleByteXorCandidate, len(inputs))

	for i, input := range inputs {
		candidates[i] = GuessSingleByteXorCipher(input)
	}

	return findBestCandidate(candidates)
}

func GuessSingleByteXorCipher(input []byte) singleByteXorCandidate {
	candidates := make([]singleByteXorCandidate, math.MaxUint8)

	for i := range candidates {
		plain := Xor(input, []byte{byte(i)})

		frequency := getByteFrequency(plain)

		candidates[i] = singleByteXorCandidate{
			input,
			byte(i),
			plain,
			frequency,
			computeL2Norm(characterFrequency, frequency),
		}
	}

	return findBestCandidate(candidates)
}

type singleByteXorCandidate struct {
	Input              []byte
	Key                byte
	Plain              []byte
	characterFrequency map[byte]float64
	l2Norm             float64
}

func findBestCandidate(candidates []singleByteXorCandidate) singleByteXorCandidate {
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

	occurrence := 1 / float64(len(result))
	for _, v := range input {
		if _, found := characterFrequency[v]; found {
			result[v] += occurrence
		}
	}

	return result
}
