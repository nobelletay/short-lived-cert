package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "certificate/cert"
)

// Subject to change
const num_of_cert = 3

type Server struct {
	pb.UnimplementedCertServiceServer
	certificate tls.Certificate
	master_key  []byte
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (ca *Server) Issue(in *pb.DomainInfo, stream pb.CertService_IssueServer) error {
	domain := in.Domain
	pubkey, err := ParseRsaPublicKeyFromPemStr(in.Pubkey)
	if err != nil {
		return err
	}

	fmt.Println("Creating hashlist...")
	hashlist_folder := "../storage/hashlist/" + domain
	if _, err := os.Stat(hashlist_folder); os.IsNotExist(err) {
		os.MkdirAll(hashlist_folder, 0744)
	}
	hashlist_file, err := os.OpenFile(hashlist_folder+"/hashlist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	check(err)
	datawriter := bufio.NewWriter(hashlist_file)

	fmt.Println("Generating " + strconv.Itoa(num_of_cert) + " certificates. Encrypting...")
	count := 0
	now := time.Now()
	now_string := now.Format(time.RFC3339)

	cert_list := []string{}
	hash_list := []string{}
	for count < num_of_cert {
		salt_time := now.AddDate(0, 0, count).Format(time.RFC3339)
		enc_cert, hash_cert := ca.gen_enc_cert(pubkey, count, domain, salt_time)
		cert_list = append(cert_list[:], enc_cert)
		hash_list = append(hash_list[:], hash_cert)
		datawriter.WriteString(hash_cert + "\n")
		count += 1
	}
	datawriter.Flush()
	hashlist_file.Close()

	// Get merkle root
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	c := exec.Command("python", exPath+"/CAmroot.py", domain)
	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}

	fmt.Println("Preparing precertificate...")

	precert := genPreCert(domain, pubkey)

	i := 0
	for i < num_of_cert {
		if err := stream.Send(&pb.Cert{Cert: cert_list[i], Hash: hash_list[i], Time: now_string, Precert: string(precert)}); err != nil {
			return err
		}
		i++
	}

	return nil
}

func (ca *Server) RequestKey(ctx context.Context, in *pb.KeyRequest) (*pb.Key, error) {
	domain_name := in.Domain
	time := in.Time
	key := ca.main_daykey(domain_name, time)

	return &pb.Key{Dailykey: key}, nil
}
func main() {

	// initialze CA
	fmt.Println("Initializing CA...")
	token := make([]byte, 128)
	rand.Read(token)
	master_key := token
	catls, err := tls.LoadX509KeyPair("../storage/root-certificate/ca_cert.pem", "../storage/root-certificate/ca_key.pem")
	if err != nil {
		log.Fatal(err)
	}
	s := Server{certificate: catls, master_key: master_key}

	// Load TLS credentials
	fmt.Println("Loading TLS credentials...")
	tlsCredentials, err := loadTLSCredentials()
	if err != nil {
		log.Fatal("cannot load TLS credentials: ", err)
	}

	fmt.Println("Listening from middle daemon...")
	// connection
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 9000))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCredentials),
	)
	pb.RegisterCertServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
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

func (s *Server) SayHello(ctx context.Context, in *pb.Message) (*pb.Message, error) {
	log.Printf("Receive message body from client: %s", in.Body)
	return &pb.Message{Body: "Hello From the Server!"}, nil
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed client's certificate
	pemClientCA, err := ioutil.ReadFile("../storage/root-certificate/ca_cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemClientCA) {
		return nil, fmt.Errorf("failed to add client CA's certificate")
	}

	// Load CA's certificate and private key
	serverCert, err := tls.LoadX509KeyPair("../storage/root-certificate/ca_cert.pem", "../storage/root-certificate/ca_key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}
