package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// Use Sha256 to hash an input string
func hash(s string) [32]uint8 {
	data := []byte(s)
	h := sha256.Sum256(data)
	return h
}

func main() {
	var domain_name string
	var day_num string

	fmt.Println("Enter domain name: ")

	fmt.Scanln(&domain_name)

	fmt.Println("Enter day number: ")

	fmt.Scanln(&day_num)

	domain_name = strings.ToLower(domain_name)

	root := "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/Middle Daemon Website Daemon Storage/Daily Certificates/"
	folder := root + domain_name

	cert, err := ioutil.ReadFile(folder + "/certday" + day_num + ".txt")
	if err != nil {
		log.Fatal(err)
	}
	cert_text := string(cert)

	hash := hash(cert_text)

	cert_hash := hex.EncodeToString(hash[:])

	f, err := os.Create("C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/Website Daemon Storage/Daily Cert Verification/cert_hash.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	l, err := f.WriteString(cert_hash)
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
