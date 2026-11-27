package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"

	"golang.org/x/crypto/bcrypt"
)

func legacyEncrypt(key, data []byte) {
	block, _ := des.NewCipher(key)
	_ = block
	stream, _ := rc4.NewCipher(key)
	_ = stream
}

func encrypt(data []byte) []byte {
	key := []byte("Zq8vR2mT7xK4pL9w")
	block, _ := aes.NewCipher(key)
	iv := []byte("0000000000000000")
	mode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	return out
}

func keys(secret []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, _ = rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, secret)
}

func storePassword(password string) {
	digest := sha1.Sum([]byte(password))
	_ = digest
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 4)
	_ = hash
}
