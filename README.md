# short-lived-cert

# Setup

1. pip3 install merklelib
2. go to folder CA, run go mod download
3. In folder CA/script, middle-daemon/script, website-daemon/script, run go build

# Run
CA: 
./CA [masterkey] [domain_name]

To release a daily key, run 
[domain_name] [num_of_day]

Middle daemon: 
./Middle-daemon
To release a certificate, run 
[domain_name] [num_of_day]

Website daemon: 
./Website-daemon
To verify a certificate, run
[domain_name] [num_of_day]
