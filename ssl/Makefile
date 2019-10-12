# This file helps set up the keys and certificates you need to run remp-cap over a SSL/TLS secured connection.

# step 1: generate private key for CA - ca.key - PRIVATE FILE - DO NOT SHARE
certs_and_keys :
	@openssl genrsa -passout pass:${passphrase} -des3 -out ca.key 4096 \
	
# step 2: generate trust cert - ca.crt - NEEDED BY CLIENT
	@openssl req -passin pass:${passphrase} -new -x509 -days \
	365 -key ca.key -out ca.crt -subj "/CN=${host}" \

# step 3: generate server private key - server.key - PRIVATE FILE - DO NOT SHARE
	@openssl genrsa -passout pass:${passphrase} -des3 -out server.key 4096 \

# step 4: generate signing request - server.csr - NEEDED BY CA
	@openssl req -passin pass:${passphrase} -new -key \
	server.key -out server.csr -subj "/CN=${host}" \

# step 5: self-sign the cert using the CA private key - server.crt - PRIVATE FILE - DO NOT SHARE
	@openssl x509 -req -passin pass:${passphrase} -days 365 -in \
	server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt \

#step 6: convert to pem so our gRPC server can actually use it - server.pem - PRIVATE FILE - DO NOT SHARE
	@openssl pkcs8 -topk8 -nocrypt -passin pass:${passphrase} -in server.key -out server.pem
