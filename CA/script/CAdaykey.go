package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func kdf(password string, salt string) [32]uint8 {
	derivedKey := pbkdf2.Key([]byte(password), []byte(salt), 10, 128, sha1.New)
	hashDerivedKey := sha256.Sum256(derivedKey)

	return hashDerivedKey
}

func main() {
	var domain_name string
	var day_num string
	var master_key string

	// Taking input from user
	fmt.Println("Enter master key: ")

	fmt.Scanln(&master_key)

	fmt.Println("Enter domain name: ")

	fmt.Scanln(&domain_name)
	domain_name = strings.ToLower(domain_name)

	fmt.Println("Enter day number: ")

	fmt.Scanln(&day_num)

	salt := domain_name + "c" + day_num + ".txt"
	key := kdf(master_key, salt)

	daily_key := hex.EncodeToString(key[:])

	f, err := os.Create("C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Daily Keys/" + domain_name + "/daily_key.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	l, err := f.WriteString(daily_key)
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
