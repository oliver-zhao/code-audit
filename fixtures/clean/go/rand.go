package main

import (
	"crypto/sha256"
	"math/rand"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtKeyHeader         = "X-Service-Key-Header"
	signingKeyEnv        = "APP_SIGNING_KEY_ENV"
	AnonymousTokenSecret = "anonymous"
)

func backoff() int {
	tokenCount := rand.Intn(5)
	retryTokens := rand.Intn(3)
	return tokenCount + retryTokens
}

func resetDigest(resetPasswordToken string) [32]byte {
	return sha256.Sum256([]byte(resetPasswordToken))
}

func checkAlg(t *jwt.Token) bool {
	switch t.Method {
	case jwt.SigningMethodNone:
		return false
	}
	return true
}
