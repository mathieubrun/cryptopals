package algos

func PKCSPad(input []byte, size int) []byte {
	padLen := size - len(input)
	padding := make([]byte, padLen)

	for i := 0; i < padLen; i++ {
		padding[i] = byte(padLen)
	}

	return append(input, padding...)
}
