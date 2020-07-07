package aes

import (
	"reflect"
	"testing"
)

func TestEncryptCBC(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
		iv   []byte
		size int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "encrypt / decrypt with CBC",
			args: args{
				data: []byte("FFEEDDCCBBAA99887766554433221100"),
				key:  []byte("0123456789ABCDEF"),
				iv:   []byte{0, 0, 0},
				size: 16,
			},
			want:    []byte("FFEEDDCCBBAA99887766554433221100"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := EncryptCBC(tt.args.data, tt.args.key, tt.args.iv, tt.args.size)
			got, err := DecryptCBC(encrypted, tt.args.key, tt.args.iv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptCBC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptECB(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
		size int
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "encrypt / decrypt with ECB",
			args: args{
				data: []byte("FFEEDDCCBBAA99887766554433221100"),
				key:  []byte("0123456789ABCDEF"),
				size: 16,
			},
			want:    []byte("FFEEDDCCBBAA99887766554433221100"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := EncryptECB(tt.args.data, tt.args.key, tt.args.size)
			got, err := DecryptECB(encrypted, tt.args.key, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptECB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptECB() = %v, want %v", got, tt.want)
			}
		})
	}
}
