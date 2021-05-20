package main

import (
	"crypto/sha256"
	"fmt"
)

// Use Sha256 to hash an input string
func hash(s string) [32]uint8 {
	data := []byte(s)
	h := sha256.Sum256(data)
	return h
}

func main() {
	// Run hash on a string and print the result
	h := hash("a")
	fmt.Printf("%x", h[:])
}
