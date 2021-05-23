package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

	// Load domain RSA key
	fmt.Println("Loading domain public key...")
	key, err := ioutil.ReadFile("../storage/domain-pubkey/" + domain_name + "/pub_key.pem")
	check(err)

	pubkey, err := ParseRsaPublicKeyFromPemStr(string(key))
	check(err)

	// Generate cert
	fmt.Println("Generating " + strconv.Itoa(num_of_cert) + " certificates. Encrypting...")
	count := 0
	hashlist := [][]byte{}
	hashlist_string := [num_of_cert]string{}
	for count < num_of_cert {
		ca.gen_enc_cert(pubkey, count, domain_name, &hashlist, &hashlist_string)
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

	c := exec.Command("python", exPath+"/CAmroot.py", domain_name)
	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}

	fmt.Println("Preparing precertificate...")

	genPreCert(domain_name, pubkey)
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
		os.MkdirAll(hashlist_folder, 0700)
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

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	// pubkeystring, _ := ExportRsaPublicKeyAsPemStr(&privatekey.PublicKey)
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
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
