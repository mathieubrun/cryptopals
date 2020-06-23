package aes_attacks

import (
	"reflect"
	"testing"
)

func Test_parseProfileString(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    *user
		wantErr bool
	}{
		{
			name: "basic case",
			args: args{str: "email=foo@bar.com&uid=10&role=user"},
			want: &user{
				Email: "foo@bar.com",
				UID:   10,
				Role:  "user",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProfileString(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseProfileString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseProfileString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_profileFor(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{email: "foo@b=a&r.com"},
			want: "email=foo@bar.com&uid=10&role=user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := profileFor(tt.args.email); got != tt.want {
				t.Errorf("profileFor() = %v, want %v", got, tt.want)
			}
		})
	}
}
