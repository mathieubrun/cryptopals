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

func FindSingleByteXorKey(input []byte) (key byte) {
	scores := make([]score, math.MaxUint8)

	for i, _ := range scores {
		plain := Xor(input, []byte{byte(i)})

		frequency := getByteFrequency(plain)

		scores[i] = score{
			input,
			frequency,
			calculateL2Norm(characterFrequency, frequency),
			byte(i),
		}
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score < scores[j].score
	})

	return scores[0].key
}

type score struct {
	input     []byte
	frequency map[byte]float64
	score     float64
	key       byte
}

func calculateL2Norm(v1 map[byte]float64, v2 map[byte]float64) (result float64) {

	for k, v := range v1 {
		result += math.Pow(v2[k]-v, 2)
	}

	return math.Sqrt(result)
}

func getByteFrequency(input []byte) map[byte]float64 {

	result := make(map[byte]float64, len(characterFrequency))
	for k, _ := range characterFrequency {
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
