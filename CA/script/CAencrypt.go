package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func kdf(password string, salt string) [32]uint8 {
	// generate the derived key
	// base on the input parameter
	// password to stretch
	// salt to use
	// number of iteration to use while generating the new key
	// length of the new key to be generated
	// hash function to be used while deriving the new key
	derivedKey := pbkdf2.Key([]byte(password), []byte(salt), 10, 128, sha1.New)

	// compute the hash function of the derived key to make it stronger
	hashDerivedKey := sha256.Sum256(derivedKey)

	return hashDerivedKey
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func main() {
	var domain_name string
	var master_key string

	// Taking input from user
	fmt.Println("Enter CA password: ")

	fmt.Scanln(&master_key)

	fmt.Println("Enter domain name: ")

	fmt.Scanln(&domain_name)
	domain_name = strings.ToLower(domain_name)

	root := "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Storage/Domain Certificates/"
	folder := root + domain_name

	var certs []string
	files, err := ioutil.ReadDir(folder)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		certs = append(certs, f.Name())
	}

	for i := 0; i < len(certs); i++ {
		salt := domain_name + certs[i]
		key := kdf(master_key, salt)

		plaintext, err := ioutil.ReadFile(folder + "/" + certs[i])
		if err != nil {
			log.Fatal(err)
		}

		ciphertext := encrypt(string(plaintext), hex.EncodeToString(key[:]))
		enc_folder := "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Encrypted Certificates/" + domain_name

		f, err := os.Create(enc_folder + "/encrypted" + certs[i])
		if err != nil {
			fmt.Println(err)
			return
		}
		l, err := f.WriteString(ciphertext)
		if err != nil {
			fmt.Println(err)
			f.Close()
			return
		}
		fmt.Println(l, "bytes written successfully")
		err = f.Close()
		if err != nil {
			fmt.Println(err)
			return
		}

	}

}
