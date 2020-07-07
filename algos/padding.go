package algos

import "fmt"

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

func RemovePKCSPad(input []byte, size int) ([]byte, error) {
	len := len(input)
	padCount := int(input[len-1])
	if padCount <= 0 || padCount > size {
		return nil, fmt.Errorf("invalid padding")
	}

	for _, b := range input[len-padCount:] {
		if b != input[len-1] {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return input[:len-padCount], nil
}
