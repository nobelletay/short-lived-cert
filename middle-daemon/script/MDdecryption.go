package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

func main() {
	var domain_name string
	var day_num string

	fmt.Println("Enter domain name: ")

	fmt.Scanln(&domain_name)
	domain_name = strings.ToLower(domain_name)

	fmt.Println("Enter day number: ")

	fmt.Scanln(&day_num)

	// Read entire file content
	content, err := ioutil.ReadFile("C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Daily Keys/" + domain_name + "/daily_key.txt")
	if err != nil {
		log.Fatal(err)
	}

	// Convert []byte to string
	key := string(content)

	// Read entire file content
	cipher, err := ioutil.ReadFile("C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Encrypted Certificates/" + domain_name + "/encryptedc" + day_num + ".txt")
	if err != nil {
		log.Fatal(err)
	}

	// Convert []byte to string
	encrypted := string(cipher)

	decrypted := decrypt(encrypted, key)

	f, err := os.Create("C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/Middle Daemon Website Daemon Storage/Daily Certificates/" + domain_name + "/certday" + day_num + ".txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	l, err := f.WriteString(decrypted)
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
