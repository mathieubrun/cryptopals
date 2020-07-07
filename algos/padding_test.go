package algos

import (
	"reflect"
	"testing"
)

func TestPKCSPadToBlockSize(t *testing.T) {
	type args struct {
		input     []byte
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "",
			args: args{
				input:     []byte{1},
				blockSize: 4,
			},
			want: []byte{1, 3, 3, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCSPadToBlockSize(tt.args.input, tt.args.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCSPadToBlockSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemovePKCSPad(t *testing.T) {
	type args struct {
		input []byte
		size  int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "1 byte",
			args: args{
				input: []byte{0x1, 0x2, 0x3, 1},
				size:  4,
			},
			want:    []byte{0x1, 0x2, 0x3},
			wantErr: false,
		},
		{
			name: "2 byte",
			args: args{
				input: []byte{0x1, 0x2, 2, 2},
				size:  4,
			},
			want:    []byte{0x1, 0x2},
			wantErr: false,
		},
		{
			name: "1 block",
			args: args{
				input: []byte{0x1, 0x2, 2, 2},
				size:  2,
			},
			want:    []byte{0x1, 0x2},
			wantErr: false,
		},
		{
			name: "invalid last byte",
			args: args{
				input: []byte{0x1, 0x2, 0x3, 0},
				size:  4,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid last byte",
			args: args{
				input: []byte{0x1, 0x2, 0x3, 5},
				size:  4,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RemovePKCSPad(tt.args.input, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemovePKCSPad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemovePKCSPad() got = %v, want %v", got, tt.want)
			}
		})
	}
}
