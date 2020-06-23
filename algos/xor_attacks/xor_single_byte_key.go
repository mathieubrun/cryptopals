package xor_attacks

import (
	"github.com/mathieubrun/cryptopals/algos"
	"github.com/mathieubrun/cryptopals/algos/xor"
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
	plain := xor.Xor(input, key)

	frequency := algos.GetByteFrequency(plain)

	return xorKeyCandidate{
		input,
		key,
		plain,
		algos.ComputeDistanceBetweenVectors(algos.CharacterFrequency, frequency),
	}
}

func findBestXorCandidate(candidates []xorKeyCandidate) xorKeyCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		// smaller deviation from English character frequency is better
		return candidates[i].deviation < candidates[j].deviation
	})

	return candidates[0]
}
