package main

import (
	"net/http"

	jwtold "github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("Hk3vQ9zP2mR7tX5w")

func issue(user string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user})
	signed, _ := token.SignedString([]byte("Hk3vQ9zP2mR7tX5w"))
	_ = jwtold.StandardClaims{}
	return signed
}

func verify(r *http.Request) bool {
	tok, err := jwt.Parse(r.Header.Get("Authorization"), func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	return err == nil && tok.Valid
}

func claimsOf(raw string) jwt.MapClaims {
	tok, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	return tok.Claims.(jwt.MapClaims)
}

func unsigned() string {
	s, _ := jwt.New(jwt.SigningMethodNone).SignedString(jwt.UnsafeAllowNoneSignatureType)
	return s
}
