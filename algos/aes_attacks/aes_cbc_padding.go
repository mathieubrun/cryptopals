package aes_attacks

import (
	"github.com/mathieubrun/cryptopals/algos"
	"math"
)

func AesCBCPadding(oracle func() (cipherBytes []byte, iv []byte), checkPadding func(cipherBytes []byte, iv []byte) bool) ([]byte, error) {
	blockSize := 16

	cipherBytes, iv := oracle()
	intermediateStateBytes := make([]byte, len(cipherBytes))
	plainBytes := make([]byte, len(cipherBytes))
	allCipher := append(iv, cipherBytes...)

	// block discovery starting from the end
	for blockToDiscover := 0; blockToDiscover < len(cipherBytes) / blockSize; blockToDiscover++ {

		// a copy of the base arrays is needed, for later modification
		attackingBytes := append(iv, cipherBytes...)
		blockToDiscoverEnd := len(cipherBytes) - blockToDiscover * blockSize
		blockToDiscoverStart := blockToDiscoverEnd - blockSize

		// byte discovery also starting from the end
		for b := 15; b >= 0; b-- {

			byteToDiscover := blockToDiscoverStart + b
			attackPaddingLen := blockSize - b
			attackedBlock := attackingBytes[blockToDiscoverStart:blockToDiscoverEnd]

			// create a mask to forge valid padding values
			// for padding length 1 is is not useful
			// for length 2 and more, there is a need to create valid padding for testing bytes :
			// to test for padding length 2, the last byte must be 2
			// to test for padding length 3, the last 2 bytes must be 3 3
			for i := attackPaddingLen; i > 0; i-- {
				attackedBlock[blockSize - i] = intermediateStateBytes[blockToDiscoverStart+(blockSize-i)] ^ byte(attackPaddingLen)
			}

			// safety net
			found := false

			// try all bytes for the targeted byte
			for i := byte(0); i <= math.MaxUint8; i++ {
				attackingBytes[byteToDiscover] = i

				valid := checkPadding(attackingBytes[blockSize:blockToDiscoverEnd+blockSize], attackingBytes[:blockSize])
				if valid && byteToDiscover%blockSize > 0 {
					// change previous byte to be sure we don't accidentally hit
					// another correct padding value, for example while checking
					// padding 1 : x x 2 1 and x x 2 2 are correct
					attackingBytes[byteToDiscover-1] = i + 1
					valid = checkPadding(attackingBytes[blockSize:blockToDiscoverEnd+blockSize], attackingBytes[:blockSize])
				}

				if valid {
					// keep track of intermediate state for creating next mask
					intermediateStateBytes[byteToDiscover] = i ^ byte(attackPaddingLen)

					// the plainBytes are deciphered by intermediate ^ previous block
					// get them back !
					plainBytes[byteToDiscover] = intermediateStateBytes[byteToDiscover] ^ allCipher[byteToDiscover]
					found = true
					break
				}
			}

			if !found {
				panic("no matching byte")
			}
		}
	}

	return algos.RemovePKCSPad(plainBytes, 16)
}
