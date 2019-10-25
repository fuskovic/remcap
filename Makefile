# Generate certificates and keys for establishing a secure connection
certs_and_keys :
# step 1: generate private key for CA - ca.key - PRIVATE FILE - DO NOT SHARE
	@openssl genrsa -passout pass:${pw} -des3 -out ca.key 4096 \
	
# step 2: generate trust cert - ca.crt - NEEDED BY CLIENT
	@openssl req -passin pass:${pw} -new -x509 -days \
	365 -key ca.key -out ca.crt -subj "/CN=${host}" \

# step 3: generate server private key - server.key - PRIVATE FILE - DO NOT SHARE
	@openssl genrsa -passout pass:${pw} -des3 -out server.key 4096 \

# step 4: generate signing request - server.csr - NEEDED BY CA
	@openssl req -passin pass:${pw} -new -key \
	server.key -out server.csr -subj "/CN=${host}" \

# step 5: self-sign the cert using the CA private key - server.crt - PRIVATE FILE - DO NOT SHARE
	@openssl x509 -req -passin pass:${pw} -days 365 -in \
	server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt \

#step 6: convert to pem so our gRPC server can actually use it - server.pem - PRIVATE FILE - DO NOT SHARE
	@openssl pkcs8 -topk8 -nocrypt -passin pass:${pw} -in server.key -out server.pem

# build server and client executables
binaries :
	@go build -o remcap client/main.go && \
	go build -o remcap_server server/*.go

# generate certs and keys and move them to an ssl dir then build server and client binaries
remcap : clean certs_and_keys binaries
	@mkdir ssl/ && mv ca* ssl/ && mv server.* ssl/

# run containerized server, copy the container generated certificate to host, and build the client binary
ready :
	@docker run -p 80:80 --rm -d --name remcap_server fuskovic/remcap:2.1 && \
	go build -o remcap client/main.go

# shell into container
interactive :
	@docker exec -it remcap_server /bin/sh

# delete certs, keys, and binaries
clean :
	@rm -rf ssl || true && \
	rm remcap* || true