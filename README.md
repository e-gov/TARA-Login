<img src="disain/assets/eu_regional_development_fund_horizontal.jpg" width="354" height="205" alt="European Union European Regional Development Fund logo">

# TARA login service

- [Overview](#overview)
- [Setting up the webapp](#build)
    * [Requirements](#build_requirements)
    * [Building the webapp](#building)
    * [Deploying the webapp](#deployment)
- [Configuration parameters](#configuration)
    * [Integration with Ory Hydra service](#hydra_integration_conf)
    * [Trusted TLS certificates](#tls_conf)
    * [Mobile-ID auth method](#mid_conf)
    * [Smart-ID auth method](#sid_conf)
    * [ID-card auth method](#esteid_conf)
    * [Eidas auth method](#eidas_conf)
    * [Monitoring](#monitoring_conf)
    * [Legal person attributes](#legalperson_conf)
    * [Security and session management](#session_and_sec_conf)
        * [Ignite integration](#ignite_conf)
        * [Security and session management](#sec_conf)
    * [Logging](#logging_conf)
    * [Alerts](#alerts_conf)
- [APPENDIX](#api_docs)
    * [API specification](#api_docs)

<a name="overview"></a>
## Overview

TARA login service is a webapp that integrates with the [Ory Hydra OIDC server](https://github.com/ory/hydra) implementation. TARA login service provides [login](https://www.ory.sh/hydra/docs/concepts/login) and [consent](https://www.ory.sh/hydra/docs/concepts/login) flow implementations. Apache Ignite is used for session persistence between requests. 

The webapp provides implementation for following authentication methods:
* Estonian ID-card
* Estonian Mobile-ID
* Estonian Smart-ID
* Estonian EIDAS

<a name="build"></a>
## Building the webapp

<a name="build_requirements"></a>
### Requirements:

- Java (JDK 17+) runtime is required to build and run the webapp.
- [Docker](https://www.docker.com/) is required to package images, fonts, CSS and JavaScript using `npm` and `gulp`.
- [Maven](https://maven.apache.org/) is required to build and test the software.

<a name="build"></a>
### Building the webapp:

To build the software, execute the following commands in the current (TARA-Login) directory:

```shell
docker run --rm -v "${PWD}:/data" -w /data/disain -u $(id -u):$(id -g) node:14 sh -c 'npm install && node_modules/.bin/gulp build'
./mvnw clean package
```

For Git Bash on Windows:
```shell
MSYS_NO_PATHCONV=1 docker run --rm -v "${PWD}:/data" -w /data/disain node:14 sh -c 'npm install && node_modules/.bin/gulp build'
./mvnw clean package
```

You can find the compiled JAR file with embedded Tomcat in the target/ directory.

### Building Docker image

Follow the instructions above to build the webapp. After that, execute the following command to build a Docker image:
```shell
./mvnw spring-boot:build-image -DskipTests
```
The built image is named and tagged as "tara-login-server:latest" by default.
You can override it by using `-DimageName` parameter for Maven.

<a name="deploying"></a>
## Deploying the webapp

TARA login service is distributed as a JAR file with embedded Tomcat that can be deployed by just running the JAR with Java.

Example: to deploy the webapp using embedded Tomcat

1. Set the location of the configuration file (see chapter Configuration properties for further details):
    ```
    export JAVA_OPTS="$JAVA_OPTS -Dspring.config.additional-location=file:/etc/tara-login-server/application.yml"
    ```
2. Run tara-login.jar:
    ```
   java $JAVA_OPTS -jar tara-login.jar
   ```

<a name="configuration"></a>
## 1 TARA login service configuration properties

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.default-locale` | No | Locale that is used by default. Default `et` |
| `tara.default-authentication-methods` | No | default authentication methods. Example `ID_CARD, MOBILE_ID, SMART_ID, EIDAS` |
| `tara.error-report-address` | Yes | E-mail address where users can send error reports. Example `help@example.com` |
| `tara.auth-flow-timeout` | Yes | Duration till authentication flow timeout. Example `1800s` (30min) |
| `tara.site-origin` | Yes | Web page's [origin](https://developer.mozilla.org/en-US/docs/Glossary/Origin) (scheme (protocol), hostname (domain), and port) where user's browser accesses TARA service from. Used by Web eID and Smart ID Web2App authenticaton flows. Example: https://example.com |


<a name="hydra_integration_conf"></a>
### 1.1 Integration with Ory Hydra service

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Ory Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Ory Hydra OIDC server login request |
| `tara.hydra-service.reject-login-url` | Yes | Url to reject Ory Hydra OIDC server login request |
| `tara.hydra-service.accept-consent-url` | Yes | Url to accept Ory Hydra OIDC server consent |
| `tara.hydra-service.reject-consent-url` | Yes | Url to reject Ory Hydra OIDC server consent |
| `tara.hydra-service.health-url` | Yes | Ory Hydra service health url |
| `tara.hydra-service.request-timeout-in-seconds` | No | Ory Hydra service request timeout |
| `tara.hydra-service.max-connections-total` | No | Max connection pool size for hydra requests. Defaults to 50 |
| `govsso.hydra-service.login-url` | No | Url for requesting GovSSO Ory Hydra login request info |
| `govsso.hydra-service.client-id` | No | TARA client_id that GovSSO uses |

<a name="tls_conf"></a>
### 1.2 TLS configuration for outbound connections

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.tls.trust-store-location` | Yes | Location of the truststore. Path to the location of the trusted CA certificates. In case the certificate files are to be loaded from classpath, this path should be prefixed with `classpath:` (example: `classpath:tls-truststore.p12`). In case the certificate files are to be loaded from disk, this path should be prefixed with `file:` (exaple ``file:/etc/tara/tls-truststore.p12``).  |
| `tara.tls.trust-store-password` | Yes | Truststore password |
| `tara.tls.trust-store-type` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |
| `tara.tls.x-road-trust-store-location` | Yes | Location of the X-road truststore. Path to the location of the trusted CA certificates. In case the certificate files are to be loaded from classpath, this path should be prefixed with `classpath:` (example: `classpath:tls-truststore.p12`). In case the certificate files are to be loaded from disk, this path should be prefixed with `file:` (exaple ``file:/etc/tara/tls-truststore.p12``).  |
| `tara.tls.x-road-trust-store-password` | Yes | Truststore password |
| `tara.tls.x-road-key-store-location` | Yes | Location of the X-road keystore. In case the key files are to be loaded from classpath, this path should be prefixed with `classpath:` (example: `classpath:tls-keystore.p12`). In case the key files are to be loaded from disk, this path should be prefixed with `file:` (exaple ``file:/etc/tara/tls-keystore.p12``).  |
| `tara.tls.x-road-key-store-password` | Yes | Keystore password |
| `tara.tls.x-road-store-type` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |
| `tara.tls.default-protocol` | No | Default protocol (see the list of supported [values](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#sslcontext-algorithms)). Defaults to `TLS` if not specified |
| `tara.tls.enabled-protocols` | No | List of enabled protocols (see the list of [standard names for protocols](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#additional-jsse-standard-names)). Defaults to JVM specific configuration if not specified |
| `tara.tls.enabled-cipher-suites` | No | List of enabled cipher suites (see the list of [standard names for cipher suites](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#jsse-cipher-suite-names)). Defaults to JVM specific configuration if not specified |

<a name="mid_conf"></a>
### 1.3 Mobile-ID auth method

Table 1.3.1 - Enabling Mobile-ID authentication

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.mobile-id.enabled` | No | Enable or disable Mobile-ID authentication method. Default `false` |

Table 1.3.2 - Assigning the Level of assurance to authentication method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.mobile-id.level-of-assurance` | Yes | Level of assurance of this auth method. Example `HIGH` |


Table 1.3.3 - Integration with the [SK MID service](https://github.com/SK-EID/MID)

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.mobile-id.host-url` | Yes | Mobile-ID authentication service url |
| `tara.auth-methods.mobile-id.truststore-path` | Yes | Path to truststore file. Example. `file:src/test/resources/mobileid-truststore-test.p12` |
| `tara.auth-methods.mobile-id.truststore-type` | Yes | Type of the truststore from truststore-path. Example. `PKCS12` |
| `tara.auth-methods.mobile-id.truststore-password` | Yes | Password of the truststore from truststore-path. Example `changeit` |
| `tara.auth-methods.mobile-id.relying-party-uuid` | Yes | UUID from mobile id contract |
| `tara.auth-methods.mobile-id.relying-party-name` | Yes | Name from mobile id contract |
| `tara.auth-methods.mobile-id.display-text` | Yes | Text to be displayed in user's mobile device. Used as a fallback in case the OIDC client has not registered a short name. |
| `tara.auth-methods.mobile-id.hash-type` | Yes | Type of authentication hash. Possible values `SHA256, SHA384, SHA512` |
| `tara.auth-methods.mobile-id.connection-timeout-milliseconds` | No | Connection timeout of the MID authentication initiation request. Default `5000` |
| `tara.auth-methods.mobile-id.read-timeout-milliseconds` | No | Read timeout used for MID requests. Must be at least 5 seconds longer than MID long polling timeout. Default `35000` |
| `tara.auth-methods.mobile-id.long-polling-timeout-seconds` | No | Long polling timeout period used for MID session status requests. Default `30` |
| `tara.auth-methods.mobile-id.interval-between-session-status-queries-in-milliseconds` | No | Interval between Mobile-ID status polling queries (from UI to tara-login-service). Default `5000` |
| `tara.auth-methods.mobile-id.delay-initiate-mid-session-in-milliseconds` | No | Delay before initiating Mobile-ID session after verification code is displayed. Default `0` |
| `tara.auth-methods.mobile-id.delay-status-polling-start-in-milliseconds` | No | Delay before long polling. Default `500` |

<a name="sid_conf"></a>
### 1.4 Smart-ID auth method

Table 1.4.1 - Enabling Smart-ID authentication

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.smart-id.enabled` | No | Enable or disable Smart-ID authentication method. Default `false` |
| `tara.auth-methods.smart-id.notification-based.enabled` | Yes | Enable or disable Smart-ID notification-based authentication flow. NB! This parameter has no effect if `tara.auth-methods.smart-id.enabled` is set to `false`. |
| `tara.auth-methods.smart-id.web2app.enabled` | Yes | Enable or disable Smart-ID Web2App authentication flow. NB! This parameter has no effect if `tara.auth-methods.smart-id.enabled` is set to `false`. |
| `tara.auth-methods.smart-id.qr-code.enabled` | Yes | Enable or disable Smart-ID QR code authentication flow. NB! This parameter has no effect if `tara.auth-methods.smart-id.enabled` is set to `false`. |

Table 1.4.2 - Assigning the Level of assurance to authentication method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.smart-id.level-of-assurance` | Yes | Level of assurance of this auth method. Example `HIGH` |


Table 1.4.3 - Integration with the [SK SID service](https://github.com/SK-EID/smart-id-documentation)

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.smart-id.host-url` | Yes | Smart-ID authentication service url |
| `tara.auth-methods.smart-id.schema-name` | Yes | Smart-ID service schema name. Must be either `smart-id-demo` for Smart-ID DEMO service or `smart-id` for Smart-ID LIVE service. |
| `tara.auth-methods.smart-id.trust-anchor-truststore.path` | Yes | Path to trust anchor truststore file. Trust anchor is the root CA which issues intermediate CA certificates (see `*.intermediate-ca-truststore-*` parameters below). Example. `file:src/test/resources/ocsp/sid-trust-anchor-truststore.p12` |
| `tara.auth-methods.smart-id.trust-anchor-truststore.type` | Yes | Type of the truststore from trust-anchor-truststore-path. Example: `PKCS12` |
| `tara.auth-methods.smart-id.trust-anchor-truststore.password` | Yes | Password of the truststore from trust-anchor-truststore-path. Example: `changeit` |
| `tara.auth-methods.smart-id.intermediate-ca-truststore.path` | Yes | Path to intermediate CA truststore file. Intermediate CA is the CA which issues personal certificates for Smart-ID users. Example: `file:src/test/resources/ocsp/sid-intermediate-ca-truststore.p12` |
| `tara.auth-methods.smart-id.intermediate-ca-truststore.type` | Yes | Type of the truststore from intermediate-ca-truststore-path. Example: `PKCS12` |
| `tara.auth-methods.smart-id.intermediate-ca-truststore.password` | Yes | Password of the truststore from intermediate-ca-truststore-path. Example: `changeit` |
| `tara.auth-methods.smart-id.relying-party-uuid` | Yes | UUID from RIA smart id contract |
| `tara.auth-methods.smart-id.relying-party-name` | Yes | Name from RIA smart id contract |
| `tara.auth-methods.smart-id.display-text` | Yes | Text to be displayed in user's mobile device. Used as a fallback in case the OIDC client has not registered a short name. |
| `tara.auth-methods.smart-id.connection-timeout-milliseconds` | No | Connection timeout of the SID session status requests. Default `5000` |
| `tara.auth-methods.smart-id.read-timeout-milliseconds` | No | Read timeout used for SID requests. Must be at least 5 seconds longer than SID long polling timeout. Default `35000` |
| `tara.auth-methods.smart-id.long-polling-timeout-milliseconds` | No | Long polling timeout period used for SID session status requests. Default `30000` |
| `tara.auth-methods.smart-id.delay-initiate-sid-session-in-milliseconds` | No | Delay before initiating Smart-ID session after verification code is displayed. Default `3000` |
| `tara.auth-methods.smart-id.delay-status-polling-start-in-milliseconds` | No | Delay before long polling. Default `500` |
| `tara.auth-methods.smart-id.allowed-countries` | No | List of ISO 3166-1 alpha-2 country codes that are allowed to use Smart-ID QR and Web2App flows. If the list is empty, all countries are allowed. Example `EE, LV, LT` Default `EE` |

Table 1.4.4 - Smart-ID Web2App flow settings

| Parameter | Mandatory | Description, example |
| :-------- | :-------- | :--------------------|
| `tara.auth-methods.smart-id.web2app.frontend-polling-interval-in-milliseconds` | No | Interval between status polling queries in Smart-ID Web2App flow (from UI to tara-login-service). Default `1000` |
| `tara.auth-methods.smart-id.web2app.custom-callback.enabled` | No | Enable or disable setting custom Web2App callback URLs for specific clients |
| `tara.auth-methods.smart-id.web2app.custom-callback.clients[].client-id` | Yes | The client application client ID |
| `tara.auth-methods.smart-id.web2app.custom-callback.clients[].callback-url` | Yes | The URL which the Smart-ID application should open after successful authentication |
| `tara.auth-methods.smart-id.web2app.custom-callback.clients[].authentication-request-app-flag-required` | No | If set to `true`, the custom callback URL will only be used if the authentication request has query parameter `app=true`. Defaults to `false` |


<a name="esteid_conf"></a>
### 1.5 ID-card auth method

ID-card authentication has been implemented using Web eID, which consists of a JavaScript library, a browser plugin and the native application to access the ID-card.

Table 1.5.1 - Enabling ID-card authentication

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.enabled` | No | Enable or disable ID-card authentication method. Default `false` |


Table 1.5.2 - Assigning the Level of assurance to authentication method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.level-of-assurance` | Yes | Level of assurance of this auth method. Allowed values: `HIGH`, `SUBSTANTIAL`, `LOW`. |

Table 1.5.3 - Configuring truststore for issuer certificates

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.issuer-truststore.path` | Yes | Path to truststore file. Example `file:src/test/resources/issuer-truststore-test.p12` |
| `tara.auth-methods.id-card.issuer-truststore.type` | Yes | Type of the truststore from truststore path. Example `PKCS12` |
| `tara.auth-methods.id-card.issuer-truststore.password` | Yes | Password of the truststore from truststore path. Example `changeit` |

Table 1.5.4 - OCSP configuration

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.enabled` | No | Enable or disable OCSP. Default `true` |
| `tara.auth-methods.id-card.ocsp.allowed-response-time-skew` | No | Max time skew when checking OCSP response age. Default `15m`. See [longer description](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/v3.2.0/README.md?plain=1#L305). |
| `tara.auth-methods.id-card.ocsp.primary-server-this-update-max-age` | No | Max age for OCSP response from primary server. Default `2m`. See [longer description](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/v3.2.0/README.md?plain=1#L306). |
| `tara.auth-methods.id-card.ocsp.fallback-server-this-update-max-age` | No | Max age for OCSP response from fallback server. Default `24h`. TODO Add a link after Web eID documentation update. |
| `tara.auth-methods.id-card.ocsp.request-timeout` | No | Max timeout for OCSP request. Default `3s`. See [longer description](https://github.com/web-eid/web-eid-authtoken-validation-java/blob/v3.2.0/README.md?plain=1#L302). |

Table 1.5.5 - Configuring truststore for OCSP responder certificates

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.responder-truststore.path` | Yes | Path to OCSP responder truststore file. Example `file:src/test/resources/ocsp-responder-truststore-test.p12` |
| `tara.auth-methods.id-card.ocsp.responder-truststore.type` | Yes | Type of the OCSP responder truststore from truststore path. Example `PKCS12` |
| `tara.auth-methods.id-card.ocsp.responder-truststore.password` | Yes | Password of the OCSP responder truststore from truststore path. Example `changeit` |

Table 1.5.6 - Explicit configuration of the primary OCSP server retry mechanism.
See [more](https://resilience4j.readme.io/docs/retry#create-and-configure-retry) for longer parameter descriptions.

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.retry.wait-duration` | No | A fixed wait duration between retry attempts. Default `500ms` |
| `tara.auth-methods.id-card.ocsp.retry.max-attempts` | No | The maximum number of attempts (including the initial call as the first attempt). Default `2` |

Table 1.5.7 - Explicit configuration of the circuit breaker.
See [more](https://resilience4j.readme.io/docs/circuitbreaker#create-and-configure-a-circuitbreaker) for longer
parameter descriptions.

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.circuit-breaker.sliding-window-size` | No | Configures the size of the sliding window which is used to record the outcome of calls when the CircuitBreaker is closed. Default `100` |
| `tara.auth-methods.id-card.ocsp.circuit-breaker.minimum-number-of-calls` | No | Configures the minimum number of calls which are required (per sliding window period) before the CircuitBreaker can calculate the error rate or slow call rate. Default `100` |
| `tara.auth-methods.id-card.ocsp.circuit-breaker.failure-rate-threshold` | No | Configures the failure rate threshold in percentage. Default `50` |
| `tara.auth-methods.id-card.ocsp.circuit-breaker.permitted-number-of-calls-in-half-open-state` | No | Configures the number of permitted calls when the CircuitBreaker is half open. Default `10` |
| `tara.auth-methods.id-card.ocsp.circuit-breaker.wait-duration-in-open-state` | No | 	The time that the CircuitBreaker should wait before transitioning from open to half-open. Default `60s` |

Table 1.5.8 - Explicit configuration of the certificate chains

The webapp allows multiple sets of certificate chain configurations to be defined by using the
`tara.auth-methods.id-card.ocsp.certificate-chains[{index}]` notation.

Each certificate chain configuration can contain the following set of properties:

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].issuer-dn` | Yes | Required issuer DN. Example `CN=Test ESTEID2025, organizationIdentifier=NTREE-17066049, O=Zetes Estonia OÜ, C=EE` |
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].primary-server` | Yes | Required primary OCSP server. |
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].first-fallback-server` | No | Optional first fallback OCSP server. |
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].second-fallback-server` | No | Optional second fallback OCSP server. |

Table 1.5.8.1 - Configuration that applies to both primary and fallback OCSP servers.

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].{primary-server\|first-fallback-server\|second-fallback-server}.nonce-enabled` | No |  Determines whether the OCSP nonce extension is enabled. When enabled a random nonce is sent with the OCSP request and verified in response. Default `true` |

Table 1.5.8.2 - Configuration that applies to fallback OCSP servers.

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].{first-fallback-server\|second-fallback-server}.url` | Yes | Required OCSP server URL. Example `http://ocsp.sk.ee/` |
| `tara.auth-methods.id-card.ocsp.certificate-chains[0].{first-fallback-server\|second-fallback-server}.responder-certificate-cn` | No | Responder certificate CN. Example `local-ocsp` |

Example: using SK's AIA OCSP as the primary service, SK's commercial OCSP (with subscription only) as the first fallback
and CRLs as the second fallback:

````
tara:
  auth-methods:
    id-card:
      enabled: true
      level-of-assurance: HIGH
      issuer-truststore:
        truststore-path: file:src/test/resources/issuer-truststore-test.p12
        truststore-type: PKCS12
        truststore-password: changeit
      ocsp:
        enabled: true
        responder-truststore:
          truststore-path: file:src/test/resources/ocsp-responder-truststore-test.p12
          truststore-type: PKCS12
          truststore-password: changeit
        allowed-response-time-skew: 15m
        primary-server-this-update-max-age: 2m
        fallback-server-this-update-max-age: 24h
        request-timeout: 3s
        retry:
          wait-duration: 500ms
          max-attempts: 2
        circuit-breaker:
          sliding-window-size: 100
          minimum-number-of-calls: 100
          failure-rate-threshold: 50
          permitted-number-of-calls-in-half-open-state: 10
          wait-duration-in-open-state: 60s
        certificate-chains:
          - issuer-dn: C=EE, O=SK ID Solutions AS, organizationIdentifier=NTREE-10747013, CN=TEST of ESTEID2018
            primary-server:
              url: http://aia.demo.sk.ee/esteid2018
            first-fallback-server:
              url: http://ocsp.sk.ee/
            second-fallback-server:
              url: https://ocspcrl:14443/ocsp/test_esteid2018
              responder-certificate-cn: local-ocsp
````

<a name="eidas_conf"></a>
### 1.6 Eidas auth method

Table 1.6.1 - Enabling Eidas authentication

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.eidas.enabled` | No | Enable or disable Eidas authentication method. Default `false` |

Table 1.6.2 - Assigning the Level of assurance to authentication method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.eidas.client-url` | Yes | Eidas client url. Example. `https://eidas-client:8889` |
| `tara.auth-methods.eidas.refresh-countries-interval-in-milliseconds` | No | How often allowed countries are requested from Eidas client. Default. `300000` |
| `tara.auth-methods.eidas.request-timeout-in-seconds` | No | Eidas client request timeout. Default. `3` |
| `tara.auth-methods.eidas.read-timeout-in-seconds` | No | Eidas client read timeout. Default. `3` |
| `tara.auth-methods.eidas.max-connections-total` | No | Max connection pool size for eidas client requests. Defaults to `50` |
| `tara.auth-methods.eidas.relay-state-cache-duration-in-seconds` | No | Eidas client read timeout. Default. `30` |
| `tara.auth-methods.eidas.script-hash` | No | hash to allow inline javascript for eidas redirect. Default. `sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=` |

<a name="legalperson_conf"></a>
## 1.7 Legal person attributes

Table 1.7.1 - Enabling legal-person attribute support 

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.legal-person-authentication.enabled` | No | Enables or disables the legalperson attribute support and endpoints. Defaults to `true` if not specified.  |


Table 1.7.2 - Integration with the Estonian business registry

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.legal-person-authentication.x-road-server-url` | Yes | X-Road security request URL. Example `https://localhost:9877/cgi-bin/consumer_proxy`  |
| `tara.legal-person-authentication.x-road-service-member-class` | Yes | X-Road service member class. Example `GOV`  |
| `tara.legal-person-authentication.x-road-service-instance` | Yes | X-Road service instance. Example `ee-dev`  |
| `tara.legal-person-authentication.x-road-service-member-code` | Yes | X-Road service member code. Example `70000310`  |
| `tara.legal-person-authentication.x-road-service-subsystem-code` | Yes | X-Road service subsystem code. Example `arireg`  |
| `tara.legal-person-authentication.x-road-client-member-class` | Yes | X-Road client member class. Example `GOV`  |
| `tara.legal-person-authentication.x-road-client-instance` | Yes | X-Road client instance. Example `ee-dev`  |
| `tara.legal-person-authentication.x-road-client-member-code` | Yes | X-Road client member code. Example `70006317`  |
| `tara.legal-person-authentication.x-road-client-subsystem-code` | Yes | X-Road client subsystem code. Example `idp`  |
| `tara.legal-person-authentication.x-road-server-read-timeout-in-milliseconds` | No | X-Road security server response read timeout in milliseconds. Defaults to 3000 if not specified.  |
| `tara.legal-person-authentication.x-road-server-connect-timeout-in-milliseconds` | No | X-Road security server connect timeout in milliseconds. Defaults to 3000 if not specified.  |
| `tara.legal-person-authentication.esindus-v2-allowed-types` | No | List of legal person types in arireg.esindus_v2 service response that are considered valid for authentication. Defaults to `TÜ,UÜ, OÜ,AS,TÜH,SA,MTÜ` if not specified.  |

<a name="monitoring_conf"></a>
## 1.8 Monitoring

The webapp uses `Spring Boot Actuator` to enable endpoints for monitoring support. To customize Monitoring, Metrics, Auditing and more, see [Spring Boot Actuator documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready).
For configuring readiness and liveness probes, see [Kubernetes Probes](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.kubernetes-probes).

<a name="session_and_sec_conf"></a>
## 1.9 Security and session management

<a name="ignite_conf"></a>
### 1.9.1 Ignite configuration

Ignite is used for storing user’s session information.

| Map name        |  Description |
| :---------------- | :---------- |
| `spring:session:sessions` | Session cache. Holds users' session information. Default configuration: cacheMode:PARTITIONED, atomicityMode:ATOMIC, backups:0, expiry: 300s |

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `spring.session.timeout` | No | Session timeout. If a duration suffix is not specified, seconds will be used. Default value `300s` |
| `ignite.ignite-instance-name` | No | Ignite instance name. Default value `tara-ignite` |
| `ignite.discovery-spi.ip-finder.addresses` | Yes | Ignite cluster node discovery addresses. Should minimally contain local node ip address. Example value `['192.168.1.1','192.168.1.2']` |
| `ignite.ssl-context-factory.key-store-type` | Yes | Ignite key store type. Example value `PKCS12` |
| `ignite.ssl-context-factory.key-store-file-path` | Yes | Ignite key store path. Example value `/test/resources/tls-keystore.p12` |
| `ignite.ssl-context-factory.key-store-password` | Yes | Ignite key store password. |
| `ignite.ssl-context-factory.trust-store-type` | Yes | Ignite trust store type. Example value `PKCS12` |
| `ignite.ssl-context-factory.trust-store-file-path` | Yes | Ignite trust store path. Example value `/test/resources/tls-truststore.p12` |
| `ignite.ssl-context-factory.trust-store-password` | Yes | Ignite trust store password. |
| `ignite.ssl-context-factory.protocol` | No | Default protocol* (see the list of supported [values](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#sslcontext-algorithms)). Defaults to `TLS` if not specified |
| `ignite.ssl-context-factory.protocols` | No | List of enabled protocols* (see the list of [standard names for protocols](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#additional-jsse-standard-names)). Defaults to JVM specific configuration if not specified |
| `ignite.ssl-context-factory.cipher-suites` | No | List of enabled cipher suites (see the list of [standard names for cipher suites](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#jsse-cipher-suite-names)). Defaults to JVM specific configuration if not specified |

\* For Ignite 2.10.0 and older, [TLSv1.3 is not supported](https://ignite.apache.org/docs/2.10.0/quick-start/java#running-ignite-with-java-11).

<a name="sec_conf"></a>
## 1.10 Security and Session management

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `spring.session.timeout` | No | Session timeout. If a duration suffix is not specified, seconds will be used. Default value `300s` |
| `tara.content-security-policy` | No | Content security policy. Default value `connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content` |

<a name="logging_conf"></a>
## 1.11 Logging configuration
| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.masked_field_names` | No | Comma separated field names to mask when structurally logging objects. Default value `session_id` |

| Environment variable        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `LOG_HOME` | No | Log files path. Default value Java IO temp dir (java.io.tmpdir) or `/tmp` |
| `LOG_FILES_MAX_COUNT` | No | Rolling file appender max files history. Default value `31` |
| `LOG_FILE_LEVEL` | No | Log level for file logging. Default value `OFF` |
| `LOG_CONSOLE_PATTERN` | No | Log files path. Default value `%d{yyyy-MM-dd'T'HH:mm:ss.SSS'Z',GMT} [${springAppName}] [%15.15t] %highlight(%-5level) %-40.40logger{39} %green(%marker) [%X{trace.id},%X{transaction.id}] -%X{remoteHost} -%msg%n}` |
| `LOG_CONSOLE_LEVEL` | No | Log files path. Default value `INFO` |

Application logs:

````
${LOG_HOME}/TaraLoginService.%d{yyyy-MM-dd,GMT}.log
````

Authentication statistics logs:

````
${LOG_HOME}/TaraLoginServiceStatistics.%d{yyyy-MM-dd,GMT}.log
````

Statistic logs contain authentication end results with states AUTHENTICATION_SUCCESS, AUTHENTICATION_FAILED or AUTHENTICATION_CANCELED. 

<a name="alerts_conf"></a>
## 1.12 Alerts config

Table 1.12.1 - Alerts service configuration parameters 

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.alerts.enabled` | No | Enables alerts update service. Default value `false` |
| `tara.alerts.host-url` | Yes | Request url used when refreshing alerts list. Example value `http://alerts-mock:8080/alerts` |
| `tara.alerts.connection-timeout-milliseconds` | No | Connection timeout in milliseconds. Default value `3000`|
| `tara.alerts.read-timeout-milliseconds` | No | Read timeout in milliseconds. Default value `3000`|
| `tara.alerts.refresh-alerts-interval-in-milliseconds` | No | How often alerts are requested from the configured alerts url. Default. `600000` |
| `tara.alerts.alerts-cache-duration-in-seconds` | No | How long alerts request results are kept in cache, in case next refresh fails. Default. `86400` |

Table 1.12.2 - Static alert configuration parameters

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.alerts.static-alert.message-templates[x].message` | No | Static alert message.|
| `tara.alerts.static-alert.message-templates[x].locale` | No | Static alert message locale. Example value: `et` |

Where x denotes index. Example:

````
tara.alerts.static-alert.message-templates[0].message=Tegemist on testkeskkonnaga ja autentimiseks vajalik info on <a href="https://e-gov.github.io/TARA-Doku/Testimine#testimine-testnumbrite-ja-id-kaardiga">TARA dokumentatsioonis</a>!
tara.alerts.static-alert.message-templates[0].locale=en
tara.alerts.static-alert.message-templates[1].message=This is a test environment and necessary credentials for testing is available in <a href="https://e-gov.github.io/TARA-Doku/Testimine#testimine-testnumbrite-ja-id-kaardiga">TARA documentation</a>!
tara.alerts.static-alert.message-templates[1].locale=en
````

## APPENDIX

<a name="api_docs"></a>
### API specification

API description in OpenAPI format can be found [here](doc/api-specification.yml).
