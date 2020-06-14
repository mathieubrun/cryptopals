package algos

func transpose(blocks [][]byte) [][]byte {
	transposed := make([][]byte, len(blocks[0]))

	for i, _ := range transposed {
		transposed[i] = make([]byte, len(blocks))

		for j, block := range blocks {
			transposed[i][j] = block[i]
		}
	}

	return transposed
}

func chunk(input []byte, size int) [][]byte {
	chunks := len(input) / size
	result := make([][]byte, chunks)

	for i := 0; i < chunks; i++ {
		result[i] = input[i*size : (i+1)*size]
	}

	return result
}
