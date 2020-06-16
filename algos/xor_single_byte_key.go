package algos

import (
	"math"
	"sort"
)

func GuessLineEncodedWithSingleByteXorCipher(inputs [][]byte) xorKeyCandidate {
	candidates := make([]xorKeyCandidate, len(inputs))

	for i, input := range inputs {
		candidates[i] = GuessSingleByteXorCipher(input)
	}

	return findBestXorCandidate(candidates)
}

func GuessSingleByteXorCipher(input []byte) xorKeyCandidate {
	candidates := make([]xorKeyCandidate, math.MaxUint8)

	for i := range candidates {
		candidates[i] = newCandidateForKey(input, []byte{byte(i)})
	}

	return findBestXorCandidate(candidates)
}

type xorKeyCandidate struct {
	Input     []byte
	Key       []byte
	Plain     []byte
	deviation float64
}

func newCandidateForKey(input []byte, key []byte) xorKeyCandidate {
	plain := Xor(input, key)

	frequency := getByteFrequency(plain)

	return xorKeyCandidate{
		input,
		key,
		plain,
		computeDistanceBetweenVectors(characterFrequency, frequency),
	}
}

func findBestXorCandidate(candidates []xorKeyCandidate) xorKeyCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		// smaller deviation from English character frequency is better
		return candidates[i].deviation < candidates[j].deviation
	})

	return candidates[0]
}
