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
	"os"
	"strconv"
	"time"
)

// GenRSA returns a new RSA key of bits length
func GenRSA(*rsa.PrivateKey, error) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func (ca Ca) gen_enc_cert(pubkey *rsa.PublicKey, count int, domain_name string, hash_list *[][]byte, hashlist_string *[num_of_cert]string) {
	// Prepare directory
	certpath := "../storage/Domain Certificates/" + domain_name
	enc_certpath := "../../CA-middle-daemon-storage/Encrypted Certificates/" + domain_name
	if _, err := os.Stat(certpath); os.IsNotExist(err) {
		os.MkdirAll(certpath, 0744)
	}
	if _, err := os.Stat(enc_certpath); os.IsNotExist(err) {
		os.MkdirAll(enc_certpath, 0744)
	}

	// Get Root certificate
	cert_auth, err := x509.ParseCertificate(ca.certificate.Certificate[0])
	check(err)

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

	crt, err := x509.CreateCertificate(rand.Reader,
		&certificate,
		cert_auth,
		pubkey,
		ca.certificate.PrivateKey)
	check(err)

	// Export original certificate
	var certOut bytes.Buffer
	certfilepath := certpath + "/cert" + strconv.Itoa(count) + ".pem"
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	f, err := os.Create(certfilepath)
	check(err)

	l, err := f.Write(certOut.Bytes()) // Certificate written in byte
	check(err)
	fmt.Println(l, "bytes written successfully --- Original certificate in CA's storage")
	err = f.Close()
	check(err)

	// Encrypt certificate and export
	salt := domain_name + time.Time.String(ca.first_start_time.AddDate(0, 0, count))
	encrypt_key := kdf(ca.master_key, salt)
	enc_cert := encrypt(string(certOut.Bytes()), hex.EncodeToString(encrypt_key[:]))
	enc_certfilepath := enc_certpath + "/enc_cert" + strconv.Itoa(count) + ".txt"
	f, err = os.Create(enc_certfilepath)
	check(err)

	l, err = f.WriteString(enc_cert) // Encrypted certificate written in string
	check(err)

	fmt.Println(l, "bytes written successfully --- Encrypted certificate in shared storage")
	err = f.Close()
	check(err)

	// Add to hash list
	hash_cert := hash(string(certOut.Bytes()))
	hashlist_string[count] = hex.EncodeToString(hash_cert[:]) // Hash list written in string
	*hash_list = append((*hash_list)[:], ByteSlice(hash_cert))

}

func ByteSlice(b []byte) []byte { return b }

func genCA() {
	ca := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{Organization: []string{"localhost"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	Caprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	Cacrt, err := x509.CreateCertificate(rand.Reader,
		&ca,
		&ca,
		&Caprivatekey.PublicKey,
		Caprivatekey)
	if err != nil {
		panic(err)
	}
	var CacertOut, CakeyOut bytes.Buffer
	pem.Encode(&CacertOut, &pem.Block{Type: "CERTIFICATE", Bytes: Cacrt})
	pem.Encode(&CakeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(Caprivatekey)})
	ioutil.WriteFile("./ca/ca_cert.pem", CacertOut.Bytes(), 0744)
	ioutil.WriteFile("./ca/ca_key.pem", CakeyOut.Bytes(), 0744)
}

func genPreCert(domain_name string, pubkey *rsa.PublicKey) {
	merkle_root_value, err := ioutil.ReadFile("../storage/Merkle Roots/" + domain_name + "/merkleroot.txt")
	if err != nil {
		log.Fatal(err)
	}

	certpath := "../storage/Precertificate/" + domain_name
	if _, err := os.Stat(certpath); os.IsNotExist(err) {
		os.MkdirAll(certpath, 0744)
	}

	// Load CA
	catls, err := tls.LoadX509KeyPair("../storage/Root Certificate/ca_cert.pem", "../storage/Root Certificate/ca_key.pem")
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	var extension = make([]pkix.Extension, 2)
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
	// pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	// ioutil.WriteFile("./precert/key.pem", keyOut.Bytes(), 0744)
	ioutil.WriteFile(certpath+"/cert.pem", certOut.Bytes(), 0744)

}
