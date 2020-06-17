package algos

func PKCSPadToBlockSize(input []byte, blockSize int) []byte {
	return PKCSPad(input, len(input)+blockSize-len(input)%blockSize)
}

func PKCSPad(input []byte, size int) []byte {
	padLen := size - len(input)
	padding := make([]byte, padLen)

	for i := 0; i < padLen; i++ {
		padding[i] = byte(padLen)
	}

	return append(input, padding...)
}
