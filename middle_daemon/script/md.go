package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "certificate/cert"
)

// Subject to change
const num_of_cert = 3

/// Mapping domain name to certificate starting time
type Middledm struct {
	domain_time_map map[string][]string
}

func main() {
	md := Middledm{make(map[string][]string)}
	// establish TLS credentials
	tlsCredentials, err := loadTLSCredentials()
	if err != nil {
		log.Fatal("cannot load TLS credentials: ", err)
	}

	// connect to CA
	var conn *grpc.ClientConn
	conn, err = grpc.Dial(":9000", grpc.WithTransportCredentials(tlsCredentials))
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := pb.NewCertServiceClient(conn)

	// say hello to ensure connection successes
	response, err := c.SayHello(context.Background(), &pb.Message{Body: "Hello From Client!"})
	check(err)
	log.Printf("Response from server: %s", response.Body)

	fmt.Println("Listening to instruction...")
	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			switch intruction := words[0]; intruction {
			case "request":
				domain_name := words[1]
				// Load domain public key
				fmt.Println("Loading domain public key...")
				key, err := ioutil.ReadFile("../storage/domain-pubkey/" + domain_name + "/pub_key.pem")
				check(err)

				pubkey, err := ParseRsaPublicKeyFromPemStr(string(key))
				check(err)

				pubkey_string, err := ExportRsaPublicKeyAsPemStr(pubkey)
				check(err)

				// Request short-lived certificates
				stream, err := c.Issue(context.Background(), &pb.DomainInfo{Domain: domain_name, Pubkey: pubkey_string})
				check(err)

				count := 0
				hashlist := [num_of_cert]string{}
				for {
					cert, err := stream.Recv()
					if err == io.EOF {
						break
					}
					check(err)
					enc_cert := cert.Cert
					hash_cert := cert.Hash
					hashlist[count] = hash_cert
					md.domain_time_map[domain_name] = append(md.domain_time_map[domain_name], cert.Time)
					if count == 0 {
						// deliver precertificate
						precertfolder := "../../middle-daemon-website-daemon-storage/precertificate/" + domain_name
						if _, err := os.Stat(precertfolder); os.IsNotExist(err) {
							os.Mkdir(precertfolder, 0744)
						}
						precertfile := precertfolder + "/precert.pem"
						f, err := os.Create(precertfile)
						check(err)
						l, err := f.WriteString(cert.Precert)
						check(err)
						fmt.Println(l, "bytes written successfully --- Precertificate delivered")
						err = f.Close()
						check(err)
					}

					// store encrypted certificates
					enc_certpath := "../storage/encrypted-certificates/" + domain_name
					if _, err := os.Stat(enc_certpath); os.IsNotExist(err) {
						os.MkdirAll(enc_certpath, 0744)
					}
					enc_certfilepath := enc_certpath + "/enc_cert" + strconv.Itoa(count) + ".txt"
					f, err := os.Create(enc_certfilepath)
					check(err)

					l, err := f.WriteString(enc_cert) // Encrypted certificate written in string
					check(err)

					fmt.Println(l, "bytes written successfully --- Encrypted certificate stored")
					err = f.Close()
					check(err)
					count += 1
				}

				fmt.Println("Saving hashlist...")
				hashlist_folder := "../storage/hashlist/" + domain_name
				if _, err := os.Stat(hashlist_folder); os.IsNotExist(err) {
					os.MkdirAll(hashlist_folder, 0744)
				}
				hashlist_file, err := os.OpenFile(hashlist_folder+"/hashlist.txt", os.O_CREATE|os.O_WRONLY, 0644)
				check(err)

				datawriter := bufio.NewWriter(hashlist_file)

				for _, data := range hashlist {
					_, _ = datawriter.WriteString(data + "\n")
				}

				datawriter.Flush()
				hashlist_file.Close()
			case "key":
				domain := words[1]
				count, err := strconv.Atoi(words[2])
				check(err)

				// Read start time
				now := md.domain_time_map[domain][0]
				md.domain_time_map[domain] = md.domain_time_map[domain][1:]

				// Request daily key
				response, err := c.RequestKey(context.Background(), &pb.KeyRequest{Domain: domain, Time: now})
				check(err)

				key := response.Dailykey
				fmt.Println("Decrypting certificates...")
				main_decrypt(domain, count, key)

				fmt.Println("Building merkle tree and proof...")
				ex, err := os.Executable()
				check(err)
				exPath := filepath.Dir(ex)

				c := exec.Command("python", exPath+"/MDincproof.py", domain, strconv.Itoa(count))
				if err := c.Run(); err != nil {
					check(err)
				}
			}
		}
	}
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
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

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := ioutil.ReadFile("../storage/ca-cert/ca_cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Load client's certificate and private key
	clientCert, err := tls.LoadX509KeyPair("../storage/md-cert/md_cert.pem", "../storage/md-cert/md_key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
