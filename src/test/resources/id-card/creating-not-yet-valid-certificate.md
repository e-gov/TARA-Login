# Commands to generate certificate that's not yet valid 
**Note that the instructions are written for Ubuntu Linux, but they
should also work with other Debian-based distributions.**

```bash
sudo apt-get install -y libfaketime
openssl genrsa 2048 > privatekey.pem
openssl req -new -key privatekey.pem -out csr.pem -subj "/C=EE/ST=TEST/L=TEST /O=TEST/OU=TEST/CN=TEST/emailAddress=example@example.com"
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME="+50y" openssl x509 -req -days 1826 -in csr.pem -signkey privatekey.pem -out public.crt
openssl crl2pkcs7 -nocrl -certfile "public.crt" | openssl pkcs7 -print_certs -text > not-yet-valid-cert.pem
rm csr.pem privatekey.pem public.crt
```

The created certificate is not signed by any trusted CA, but works
for testing purposes because the validity time is checked before
the signature in *web-eid-authtoken-validation-java* library.
