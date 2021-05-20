package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/pbkdf2"
)

func kdf(password string, salt string) [32]uint8 {
	// hash the original password
	// using sha256
	hashedPassword := sha256.Sum256([]byte(password))

	fmt.Printf("2.) Hashed Password :-> %x\n\n", hashedPassword)

	// generate the derived key
	// base on the input parameter
	// password to stretch
	// salt to use
	// number of iteration to use while generating the new key
	// length of the new key to be generated
	// hash function to be used while deriving the new key
	derivedKey := pbkdf2.Key([]byte(password), []byte(salt), 10, 128, sha1.New)

	// print out the derived key
	fmt.Printf("3.) KDF Key :->  %x\n\n", derivedKey)

	// compute the hash function of the derived key to make it stronger
	hashDerivedKey := sha256.Sum256(derivedKey)

	return hashDerivedKey
}

func main() {
	fmt.Printf("%s\n\n", " >>> Supply Password to generate a secure Key")

	// get password from the user terminal
	// password is in  bytes
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Println("error reading password")
		return
	}

	// print out the original password entered by the user
	fmt.Printf("1.) Original Password :-> %s\n\n", string(password))

	salt := "domain_date"

	hashDerivedKey := kdf(string(password), salt)

	// print the  hashed derived key
	fmt.Printf("4.) Hashed Derived Key :-> %x\n\n", hashDerivedKey)

}
