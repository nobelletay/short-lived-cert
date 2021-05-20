package main

import (
	"bufio"
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
	var hashlist []string

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
		cert, err := ioutil.ReadFile(folder + "/" + certs[i])
		if err != nil {
			log.Fatal(err)
		}
		cert_text := string(cert)

		hash := hash(cert_text)

		hashlist = append(hashlist, hex.EncodeToString(hash[:]))
	}

	save_fold := "C:/Users/galan/Desktop/Stanford Classes/Crypto Research/Storage Folders/CA Middle Daemon Storage/Hashlists/"

	file, err := os.OpenFile(save_fold+domain_name+"/hashlist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range hashlist {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()

}
