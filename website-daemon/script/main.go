package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Use Sha256 to hash an input string
func hash(s string) [32]uint8 {
	data := []byte(s)
	h := sha256.Sum256(data)
	return h
}

func main() {
	fmt.Println("Listening to request...")
	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			day_num := words[1]
			domain_name := words[0]

			fmt.Println("Get certificate and hash...")
			root := "../../middle-daemon-website-daemon-storage/certificate/"
			folder := root + domain_name

			cert, err := ioutil.ReadFile(folder + "/certday" + day_num + ".pem")
			check(err)
			cert_text := string(cert)
			hash := hash(cert_text)
			cert_hash := hex.EncodeToString(hash[:])

			// Get Merkle root from precertificate
			fmt.Println("Loading Precertificate...")
			folder = "../../middle-daemon-website-daemon-storage/precertificate/" + domain_name

			precert, err := ioutil.ReadFile(folder + "/precert.pem")
			check(err)
			block, _ := pem.Decode([]byte(precert))
			if block == nil {
				panic("failed to parse certificate PEM")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}

			merkle_root := certificate.Extensions[5].Value
			fmt.Println("root: " + string(merkle_root))

			fmt.Println("Verifying proof...")
			// fmt.Println(string(merkle_root))
			ex, err := os.Executable()
			check(err)
			exPath := filepath.Dir(ex)
			file := exPath + "/WDverify.py"
			c := exec.Command("python", file, string(merkle_root), cert_hash)
			if err := c.Run(); err != nil {
				check(err)
			}
		}

		if scanner.Err() != nil {
			// Handle error.
		}
	}

}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
