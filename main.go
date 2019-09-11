package main

import (
	"context"
	"errors"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/crypto/argon2"
)

const login = "su"
const salt = "<your salt>"
const password = "<your password here>"

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
	if credentials.Login != login {
		return "auth failed", errors.New("auth failed")
	}
	key := argon2.Key([]byte(credentials.Password), []byte(salt), 3, 128, 1, 32)
	if areSlicesEqual(key, []byte(password)) {
		return "ok", nil
	}
	return "auth failed", errors.New("auth failed")
}

func main() {
	lambda.Start(HandleRequest)
}
