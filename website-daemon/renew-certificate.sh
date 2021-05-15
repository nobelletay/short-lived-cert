#!/bin/bash
cert_input_path="https://www.ieee-security.org/TC/W2SP/2012/papers/w2sp12-final9.pdf"
cert_output_path="/home/nobellet/short-lived-cert/website-daemon/certificate.pdf"

print_usage() {
    printf "Usage: $0 [-i input] [-o output]\n"
}

while getopts 'i:o:' flag; do
    case "${flag}" in
        i) cert_input_path="${OPTARG}" ;;
        o) cert_output_path="${OPTARG}" ;;
        *) print_usage
           exit 1 ;;
    esac
done

# Download short-lived certificate and Proof-of-Inclusion for the Merkle tree
wget $cert_input_path -O $cert_output_path

# Update certificate path in web server config
# Skipped since building a web server is out of the scope of this project

# Reload the web server to pick up the new config
# Skipped since building a web server is out of the scope of this project
