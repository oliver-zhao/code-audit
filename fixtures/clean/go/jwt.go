package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func issue(user string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user})
	signed, _ := token.SignedString(jwtSecret)
	return signed
}

func verify(r *http.Request) bool {
	tok, err := jwt.Parse(r.Header.Get("Authorization"), func(t *jwt.Token) (interface{}, error) { if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("unexpected method") }; return jwtSecret, nil })
	return err == nil && tok.Valid
}

func verifyStrict(raw string) bool {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil }, jwt.WithValidMethods([]string{"HS256"}))
	return err == nil && tok.Valid
}

func rejectNone(t *jwt.Token) bool {
	return t.Method == jwt.SigningMethodNone
}
