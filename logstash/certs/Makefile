# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

# one may wish to consider not using self-signed certificates in production

all: ca server client

ca:
	openssl genrsa -out ca.key 2048
	openssl req -x509 -new -nodes -key ca.key -sha256 -days 9999 -subj /C=US/ST=ID/O=sensor/OU=ca -out ca.crt

server:
	openssl genrsa -out server.key 2048
	openssl req -sha512 -new -key server.key -out server.csr -config server.conf
	openssl x509 -days 3650 -req -sha512 -in server.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out server.crt -extensions v3_req -extfile server.conf
	mv server.key server.key.pem && openssl pkcs8 -in server.key.pem -topk8 -nocrypt -out server.key

client:
	openssl genrsa -out client.key 2048
	openssl req -sha512 -new -key client.key -out client.csr -config client.conf
	openssl x509 -days 3650 -req -sha512 -in client.csr -CAcreateserial -CA ca.crt -CAkey ca.key -out client.crt -extensions v3_req -extensions usr_cert -extfile client.conf

.PHONY: clean
clean:
	@rm -f *.key *.crt *.pem *.csr *.srl
