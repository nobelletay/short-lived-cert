package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Subject to change
const num_of_cert = 3

type Ca struct {
	certificate      tls.Certificate
	master_key       string
	first_start_time time.Time
}

// New constructs a new CA instance
func new(master_key string) Ca {
	catls, err := tls.LoadX509KeyPair("../storage/root-certificate/ca_cert.pem", "../storage/root-certificate/ca_key.pem")
	check(err)
	first_start_time := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 0)
	return Ca{catls, master_key, first_start_time}
}

func main() {
	argsWithoutProg := os.Args[1:]

	if len(argsWithoutProg) != 2 {
		panic("Enter master key, domain name!")
	}
	domain_name := os.Args[2]

	// Load CA
	fmt.Println("Initializing CA...")
	master_key := os.Args[1]
	ca := new(master_key)

	// Generate domain RSA key
	privkeyDir := "../storage/domain-privkey/" + domain_name
	pubkeyDir := "../storage/domain-pubkey/" + domain_name
	if _, err := os.Stat(privkeyDir); os.IsNotExist(err) {
		os.Mkdir(privkeyDir, 0744)
	}
	if _, err := os.Stat(pubkeyDir); os.IsNotExist(err) {
		os.Mkdir(pubkeyDir, 0744)
	}
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey

	var privkeyOut bytes.Buffer
	pem.Encode(&privkeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)})
	ioutil.WriteFile(privkeyDir + "/key.pem", privkeyOut.Bytes(), 0744)
	//var domainPubkeyOut bytes.Buffer
	//pem.Encode(&domainPubkeyOut, &pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKIXPublicKey(domainPublicKey)})
	//ioutil.WriteFile(publicKeyPath + "/pubkey.pem", domainPubkeyOut.Bytes(), 0744)


	// Generate cert
	fmt.Println("Generating " + strconv.Itoa(num_of_cert) + " certificates. Encrypting...")
	count := 0
	hashlist := [][]byte{}
	hashlist_string := [num_of_cert]string{}
	for count < num_of_cert {
		ca.gen_enc_cert(&pubkey, count, domain_name, &hashlist, &hashlist_string)
		count += 1
	}

	fmt.Println("Exporting hashlist...")
	export_hashlist(hashlist_string, domain_name)

	// Get merkle root
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	c := exec.Command("/home/nobellet/usr/local/bin/python3.9", exPath+"/CAmroot.py", domain_name)
        stderr, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		fmt.Println("Error: ", err)
	}

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	fmt.Println("Preparing precertificate...")

	genPreCert(domain_name, &pubkey)
	// fmt.Println("Merkle root: " + string(merkle_root))

	fmt.Println("Listening to daily key request...")
	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			count, err := strconv.Atoi(words[1])
			check(err)
			ca.main_daykey(words[0], count)
		}

		if scanner.Err() != nil {
			// Handle error.
		}
	}

}

func export_hashlist(hashlist [num_of_cert]string, domain_name string) {
	// Write hashlist to file
	hashlist_folder := "../../CA-middle-daemon-storage/Hashlists/" + domain_name

	if _, err := os.Stat(hashlist_folder); os.IsNotExist(err) {
		os.Mkdir(hashlist_folder, 0700)
	}
	hashlist_file, err := os.OpenFile(hashlist_folder+"/hashlist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	check(err)

	datawriter := bufio.NewWriter(hashlist_file)

	for _, data := range hashlist {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	hashlist_file.Close()
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	check(err)
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	f, err := os.Create("./domain/pub_key.pem")
	check(err)
	l, err := f.WriteString(string(pubkey_pem))
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	fmt.Println(l, "bytes written successfully")
	err = f.Close()
	check(err)
}
