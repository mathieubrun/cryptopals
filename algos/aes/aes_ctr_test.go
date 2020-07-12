package aes

import (
	"crypto/aes"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMakeStreamFunc(t *testing.T) {
	type args struct {
		aesKey []byte
		nonce  uint64
		count  uint64
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "1 call", args: args{
			aesKey: make([]byte, 16),
			nonce:  30,
			count:  0,
		},
		},
		{
			name: "2 calls", args: args{
			aesKey: make([]byte, 16),
			nonce:  20,
			count:  1,
		},
		},
		{
			name: "3 calls", args: args{
			aesKey: make([]byte, 16),
			nonce:  10,
			count:  2,
		},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			streamFunc := MakeStreamFunc(tt.args.aesKey, tt.args.nonce)
			cipher, _ := aes.NewCipher(tt.args.aesKey)

			// when
			cipherBytes := streamFunc()
			for i := uint64(0); i < tt.args.count; i++ {
				cipherBytes = streamFunc()
			}
			plainBytes := make([]byte, 16)
			cipher.Decrypt(plainBytes, cipherBytes)

			// then
			assert.Equal(t, tt.args.nonce, binary.LittleEndian.Uint64(plainBytes[:8]))
			assert.Equal(t, tt.args.count, binary.LittleEndian.Uint64(plainBytes[8:]))
		})
	}
}
