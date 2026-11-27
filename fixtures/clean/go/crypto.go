package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func encrypt(data []byte) ([]byte, error) {
	key, err := hex.DecodeString(os.Getenv("APP_KEY"))
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func keys(secret []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	_, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, secret, nil)
}

func storePassword(password string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_ = hash
	sum := sha256.Sum256([]byte("static content"))
	_ = sum
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
