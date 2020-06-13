package utils

import (
	"bufio"
	"encoding/hex"
	"os"
)

func ReadLines(path string) ([][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		bytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return nil, err
		}

		lines = append(lines, bytes)
	}
	return lines, scanner.Err()
}
