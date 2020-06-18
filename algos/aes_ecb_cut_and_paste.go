package algos

import (
	"fmt"
	"strconv"
	"strings"
)

type user struct {
	Email string
	UID   int
	Role  string
}

func profileFor(email string) string {
	return fmt.Sprintf("email=%s&uid=10&role=user", strings.Replace(strings.Replace(email, "=", "", -1), "&", "", -1))
}

func ECBCutAndPaste() []byte {
	cookieDough := EncryptProfile("foo@baaar.admin\v\v\v\v\v\v\v\v\v\v\vcom")

	//  email=foo@baaar.
	//  admin[ padding ]
	//  com&uid=10&role=
	//  user[  padding ]
	return append(cookieDough[0:16], append(cookieDough[32:48], cookieDough[16:32]...)...)
}

var aesKey = GenerateRandomBytes(16)

func EncryptProfile(profile string) []byte {
	return EncryptECB([]byte(profileFor(profile)), aesKey, 16)
}

func DecryptProfile(cipherProfile []byte) (*user, error) {
	return parseProfileString(string(DecryptECB(cipherProfile, aesKey, 16)))
}

func parseProfileString(str string) (*user, error) {
	elems := strings.Split(str, "&")
	uid, err := strconv.Atoi(strings.Split(elems[1], "=")[1])
	if err != nil {
		return nil, err
	}
	return &user{
		Email: strings.Split(elems[0], "=")[1],
		UID:   uid,
		Role:  strings.Split(elems[2], "=")[1],
	}, nil
}
