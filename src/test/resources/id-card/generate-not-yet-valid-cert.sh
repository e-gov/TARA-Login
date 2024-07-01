#!/bin/bash

apt-get update && apt-get install -y libfaketime

openssl genrsa 2048 > privatekey.pem

openssl req -new -key privatekey.pem -out csr.pem -subj "/C=EE/ST=TEST/L=TEST /O=TEST/OU=TEST/CN=TEST/emailAddress=example@example.com"

LD_PRELOAD=/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1 FAKETIME="+50y" openssl x509 -req -days 1826 -in csr.pem -signkey privatekey.pem -out public.crt -extfile extensions.conf

openssl crl2pkcs7 -nocrl -certfile "public.crt" | openssl pkcs7 -print_certs -text > not-yet-valid-cert.pem

rm csr.pem privatekey.pem public.crt