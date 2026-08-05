# The JS targets are thin wrappers around the npm scripts in disain/package.json,
# which is the single source of truth for how the tools are invoked. This Makefile
# only supplies the Node 14 container to run them in.

# == Variables ==

DOCKER_NPM = docker run --rm \
  --platform linux/amd64 \
  -v "$(CURDIR):/data" \
  -w /data/disain \
  -u $(shell id -u):$(shell id -g) \
  -e npm_config_cache=/data/disain/node_modules/.cache/npm \
  -e TARGET \
  node:14 sh -c

# Optional: TARGET=scripts/form/form-check.js  or  TARGET=SomeTest#someMethod
# Exported so the npm scripts inside the container can read it.
TARGET ?=
export TARGET

.DEFAULT_GOAL := compile

# == Java ==

.PHONY: compile clean test
compile:
	./mvnw test-compile

clean:
	./mvnw clean

test:
	./mvnw test $(if $(TARGET),-Dtest=$(TARGET),)

# == JS ==

.PHONY: npm-install js-build js-format js-format-fix js-lint js-lint-fix
npm-install:
	$(DOCKER_NPM) 'npm install'

js-build: npm-install
	$(DOCKER_NPM) 'npm run build'

js-format:
	$(DOCKER_NPM) 'npm run format'

js-format-fix:
	$(DOCKER_NPM) 'npm run format:fix'

js-lint:
	$(DOCKER_NPM) 'npm run lint'

js-lint-fix:
	$(DOCKER_NPM) 'npm run lint:fix'

# == Build ==

.PHONY: build image image-skip-tests
build: js-build
	./mvnw clean package

image: js-build
	./mvnw clean spring-boot:build-image

image-skip-tests: js-build
	./mvnw clean spring-boot:build-image -DskipTests
