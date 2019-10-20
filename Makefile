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

# delete certs, keys, and binaries
clean :
	@rm -rf ssl || true && \
	rm remcap* || true

# required args : pw ( passphrase used for key and cert generation ) and host ( address gRPC server is running on)
remcap : clean certs_and_keys
	@go build -o remcap client/main.go && \
	go build -o remcap_server server/*.go && \
	mkdir ssl/ && mv ca* ssl/ && mv server.* ssl/

# run a containerized remcap server
remcap_container : 
	@docker run -p 4444:4444 --rm -d --name remcap_server remcap

interactive :
	@docker exec -it remcap_server /bin/sh

container_address :
	@docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' remcap_server

# run containerized server, copy the container generated certificate to host, and build the client binary
ready : remcap_container
	@docker cp remcap_server:/app/rem-cap/ssl/ca.crt . && \
	go build -o remcap client/main.go