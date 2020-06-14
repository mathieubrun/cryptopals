package algos

import "testing"

func TestHamming(t *testing.T) {
	type args struct {
		b1 []byte
		b2 []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "simple case",
			args: args{
				b1: []byte("this is a test"),
				b2: []byte("wokka wokka!!!"),
			},
			want: 37,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hamming(tt.args.b1, tt.args.b2); got != tt.want {
				t.Errorf("Hamming() = %v, want %v", got, tt.want)
			}
		})
	}
}
