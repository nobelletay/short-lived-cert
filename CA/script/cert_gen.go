package main

// Generate domain certificate
// Generate root certificte
// Generate precertificate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func (ca *Server) gen_enc_cert(pubkey *rsa.PublicKey, count int, domain_name string, salt_time string) (string, string) {
	// Prepare directory
	certpath := "../storage/domain-certificates/" + domain_name
	enc_certpath := "../storage/encrypted-certificates/" + domain_name
	if _, err := os.Stat(certpath); os.IsNotExist(err) {
		os.MkdirAll(certpath, 0744)
	}
	if _, err := os.Stat(enc_certpath); os.IsNotExist(err) {
		os.MkdirAll(enc_certpath, 0744)
	}

	// Get Root certificate
	cert_auth, err := x509.ParseCertificate(ca.certificate.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	// Generate certificate
	certificate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{Organization: []string{domain_name}},
		NotBefore:    time.Now().AddDate(0, 0, count),
		NotAfter:     time.Now().AddDate(0, 0, (count + 4)),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain_name},
	}

	if ip := net.ParseIP(domain_name); ip != nil {
		certificate.IPAddresses = append(certificate.IPAddresses, ip)
	} else {
		certificate.DNSNames = append(certificate.DNSNames, domain_name)
	}

	crt, err := x509.CreateCertificate(rand.Reader,
		&certificate,
		cert_auth,
		pubkey,
		ca.certificate.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Export original certificate
	var certOut bytes.Buffer
	certfilepath := certpath + "/cert" + strconv.Itoa(count) + ".pem"
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	f, err := os.Create(certfilepath)
	if err != nil {
		log.Fatal(err)
	}

	l, err := f.Write(certOut.Bytes()) // Certificate written in byte
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(l, "bytes written successfully --- Original certificate in CA's storage")
	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt certificate and export
	salt := domain_name + salt_time
	encrypt_key := kdf(ca.master_key, salt)
	enc_cert := encrypt(string(certOut.Bytes()), hex.EncodeToString(encrypt_key[:]))
	hash_cert := hex.EncodeToString(hash(string(certOut.Bytes()))[:])
	return enc_cert, hash_cert
}

func ByteSlice(b []byte) []byte { return b }

func genPreCert(domain_name string, pubkey *rsa.PublicKey) []byte {
	merkle_root_value, err := ioutil.ReadFile("../storage/merkle-roots/" + domain_name + "/merkleroot.txt")
	if err != nil {
		log.Fatal(err)
	}

	sct_value, err := ioutil.ReadFile("../storage/sct/" + domain_name + "/sct.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Load CA
	catls, err := tls.LoadX509KeyPair("../storage/root-certificate/ca_cert.pem", "../storage/root-certificate/ca_key.pem")
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	var extension = make([]pkix.Extension, 3)
	poison_extension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
		Critical: true,
		Value:    []byte{5, 0},
	}
	extension[0] = poison_extension

	merkle_root := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		Critical: false,
		// Value:    []byte{0xe},
		Value: merkle_root_value,
	}
	extension[1] = merkle_root

	sct_extension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
		Critical: false,
		Value:    sct_value,
	}
	extension[2] = sct_extension

	template := x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().Unix()),
		Subject:         pkix.Name{Organization: []string{domain_name}},
		NotBefore:       time.Now().Add(time.Hour * 24 * 0),
		NotAfter:        time.Now().Add(time.Hour * 24 * 4),
		KeyUsage:        x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:        []string{domain_name},
		ExtraExtensions: extension,
	}

	if ip := net.ParseIP(domain_name); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain_name)
	}

	// privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	// if err != nil {
	// 	panic(err)
	// }
	crt, err := x509.CreateCertificate(rand.Reader,
		&template,
		ca,
		pubkey,
		catls.PrivateKey)
	if err != nil {
		panic(err)
	}
	var certOut bytes.Buffer
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	return certOut.Bytes()

}
