package main

import "math/rand"

func newSalt() []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	return salt
}
