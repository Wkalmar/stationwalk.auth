package main

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/forestgiant/sliceutil"
	"golang.org/x/crypto/argon2"
)

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func issueJwtToken(login string) (string, error) {
	jwtKey := []byte(os.Getenv("JWTKEY"))

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: login,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func parseCredentials(req string) (*Credentials, error) {
	credentials := &Credentials{
		Login:    "",
		Password: "",
	}

	err := json.Unmarshal([]byte(req), credentials)

	return credentials, err
}

func Auth(req string) (string, error) {
	login := os.Getenv("LOGIN")
	salt := os.Getenv("SALT")
	password := []byte{221, 35, 76, 136, 29, 114, 39, 75, 41, 248, 62, 216, 149, 39, 248, 154, 243, 203, 188, 106, 206, 74, 122, 47, 255, 61, 173, 43, 102, 173, 222, 125}

	credentials, err := parseCredentials(req)

	if err != nil {
		return "", err
	}

	if credentials.Login != login {
		return "", errors.New("Authentication failed")
	}
	key := argon2.Key([]byte(credentials.Password), []byte(salt), 3, 128, 1, 32)
	if sliceutil.OrderedCompare(key, password) {
		return issueJwtToken(login)
	}
	return "", errors.New("Authentication failed")
}
