package algos

func Xor(input []byte, key []byte) []byte {
	length := len(input)
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = input[i] ^ key[i]
	}

	return result
}
