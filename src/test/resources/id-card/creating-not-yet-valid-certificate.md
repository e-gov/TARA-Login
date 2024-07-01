## Command to generate certificate that's not yet valid

NB! Make sure your current folder is src/test/resources/id-card when running the following docker command.
```bash
docker run \
  --rm \
  --user root \
  --volume $(pwd):/usr/src/project \
  --workdir /usr/src/project eclipse-temurin:17 \
  ./generate-not-yet-valid-cert.sh
```

The created certificate is not signed by any trusted CA, but works
for testing purposes because the validity time is checked before
the signature in *web-eid-authtoken-validation-java* library.
