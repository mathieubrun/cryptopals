package utils

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"os"
)

func ReadLinesAsBytes(path string) ([][]byte, error) {
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

func ReadBase64File(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines += scanner.Text()
	}

	scanErr := scanner.Err()
	if scanErr != nil {
		return nil, scanErr
	}

	decoded, err := base64.StdEncoding.DecodeString(lines)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}
