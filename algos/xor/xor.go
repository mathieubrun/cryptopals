package xor

func Xor(input []byte, key []byte) (result []byte) {
	inputLength := len(input)
	keyLength := len(key)

	result = make([]byte, inputLength)

	for i := 0; i < inputLength; i++ {
		result[i] = input[i] ^ key[i%keyLength]
	}

	return result
}

func XorInPlace(input []byte, key []byte) {
	inputLength := len(input)
	keyLength := len(key)

	for i := 0; i < inputLength; i++ {
		input[i] = input[i] ^ key[i%keyLength]
	}
}
