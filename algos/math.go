package algos

import (
	"math"
)

func hamming(b1 []byte, b2 []byte) int {

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
