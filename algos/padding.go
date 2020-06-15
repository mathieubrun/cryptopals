package algos

func PKCSPadToBlockSize(input []byte, blockSize int) []byte {
	remainder := len(input)%blockSize
	if remainder > 0 {
		return PKCSPad(input, len(input)+blockSize-len(input)%blockSize)
	}
	return PKCSPad(input, len(input))

}

func PKCSPad(input []byte, size int) []byte {
	padLen := size - len(input)
	padding := make([]byte, padLen)

	for i := 0; i < padLen; i++ {
		padding[i] = byte(padLen)
	}

	return append(input, padding...)
}
