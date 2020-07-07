package aes

import (
	"encoding/base64"
	"fmt"
	"github.com/mathieubrun/cryptopals/algos"
	"math/rand"
	"strings"
)

var CBCPaddingOracleCipherBytes = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func MakeCBCPaddingOracle(aesKey []byte, num int) func() (cipherBytes []byte, iv []byte) {
	blockSize := 16

	return func() (cipherBytes []byte, iv []byte) {
		plainBytes := []byte(CBCPaddingOracleCipherBytes[num])

		iv = algos.GenerateRandomBytes(blockSize)
		cipherBytes = EncryptCBC(plainBytes, aesKey, iv, blockSize)

		return cipherBytes, iv
	}
}

func CheckCBCPadding(cipherBytes []byte, key []byte, iv []byte) bool {
	blockSize := 16

	_, err := DecryptCBC(cipherBytes, key, iv, blockSize)
	return err == nil
}

func MakeECBEncryptionOracle(aesKey []byte, prefix []byte) func(plainBytes []byte) []byte {
	blockSize := 16

	return func(plainBytes []byte) []byte {
		suffix, _ := base64.StdEncoding.DecodeString(
			"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
				"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
				"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
				"YnkK")

		plainBytes = append(prefix, plainBytes...)
		plainBytes = append(plainBytes, suffix...)

		return EncryptECB(plainBytes, aesKey, blockSize)
	}
}

func MakeCBCEncryptionOracle(aesKey []byte, iv []byte, blockSize int) func(plainBytes []byte) []byte {
	return func(plainBytes []byte) []byte {
		plainText := fmt.Sprintf("comment1=cooking%%20MCs;userdata=%s;comment2=%%20like%%20a%%20pound%%20of%%20bacon", strings.Replace(strings.Replace(string(plainBytes), "=", "", -1), ";", "", -1))

		return EncryptCBC([]byte(plainText), aesKey, iv, blockSize)
	}
}

func EncryptionOracle(plainBytes []byte, ecb bool) []byte {
	// TODO: optimize
	plainBytes = append(algos.GenerateRandomBytes(rand.Intn(10)), plainBytes...)
	plainBytes = append(plainBytes, algos.GenerateRandomBytes(rand.Intn(10))...)
	plainBytes = algos.PKCSPad(plainBytes, len(plainBytes)+len(plainBytes)%16)

	key := algos.GenerateRandomBytes(16)
	if ecb {
		return EncryptECB(plainBytes, key, 16)
	}

	iv := algos.GenerateRandomBytes(16)
	return EncryptCBC(plainBytes, key, iv, 16)
}
