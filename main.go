package main

import (
	"context"
	"errors"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/crypto/argon2"
)

const login = "su"
const salt = "<your salt>"

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func areSlicesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func HandleRequest(ctx context.Context, credentials Credentials) (string, error) {
	password := []byte{221, 35, 76, 136, 29, 114, 39, 75, 41, 248, 62, 216, 149, 39, 248, 154, 243, 203, 188, 106, 206, 74, 122, 47, 255, 61, 173, 43, 102, 173, 222, 125}

	if credentials.Login != login {
		return "auth failed", errors.New("auth failed")
	}
	key := argon2.Key([]byte(credentials.Password), []byte(salt), 3, 128, 1, 32)
	if areSlicesEqual(key, password) {
		return "ok", nil
	}
	return "auth failed", errors.New("auth failed")
}

func main() {
	lambda.Start(HandleRequest)
}
