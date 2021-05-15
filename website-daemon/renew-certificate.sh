#!/bin/bash
certificate_download_path="https://www.ieee-security.org/TC/W2SP/2012/papers/w2sp12-final9.pdf"
certificate_path="/home/nobellet/afs-home/short-lived-cert/website-daemon/certificate.pdf"

# Download short-lived certificate and Proof-of-Inclusion for the Merkle tree
wget $certificate_download_path -O $certificate_path

# Update certificate path in web server config
# Skipped since building a web server is out of the scope of this project

# Reload the web server to pick up the new config
# Skipped since building a web server is out of the scope of this project
