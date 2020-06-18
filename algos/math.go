package algos

import (
	"crypto/rand"
	"math"
)

func GenerateRandomBytes(count int) []byte {
	bytes := make([]byte, count)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil
	}
	return bytes
}

func hamming(b1 []byte, b2 []byte) int {

	setBitCount := 0
	for i, v := range b1 {
		xor := v ^ b2[i]

		for xor > 0 {
			setBitCount += int(xor & byte(1))
			xor >>= 1
		}
	}

	return setBitCount
}

func computeDistanceBetweenVectors(v1 []float64, v2 []float64) (result float64) {
	for i, v := range v1 {
		d := v2[i] - v
		result += d * d
	}

	return math.Sqrt(result)
}

func getByteFrequency(input []byte) []float64 {
	result := make([]float64, math.MaxUint8+1)

	occurrence := 1 / float64(len(input))
	for _, v := range input {
		result[v] += occurrence
	}

	return result
}
