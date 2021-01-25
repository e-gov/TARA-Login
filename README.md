# TARA login server

- [Overview](#overview)
- [Setting up the webapp](#build)
    * [Requirements](#build_requirements)
    * [Building the webapp](#building)
    * [Deploying the webapp](#deployment)
- [Configuration parameters](#configuration)
    * [Integration with Hydra service](#hydra_integration_conf)
    * [Trusted TLS certificates](#tls_conf)
    * [Mobile-ID auth method](#mid_conf)
    * [ID-card auth method](#esteid_conf)
    * [Monitoring](#monitoring_conf)
        * [Custom application health endpoint configuration](#monitoring_heartbeat_conf)      
    * [Legal person attributes](#legalperson_conf)
    * [Security and session managment](#session_and_sec_conf)
        * [Ignite integration](#ignite_conf)
        * [Security and session management](#sec_conf)

<a name="overview"></a>
## Overview

TARA login server is a webapp that integrates with the [ORY Hydra OIDC server](https://github.com/ory/hydra) implementation. TARA login server provides [login](https://www.ory.sh/hydra/docs/concepts/login) and [consent](https://www.ory.sh/hydra/docs/concepts/login) flow implementations. Apache Ignite is used for session persistence between requests. 

The webapp provides implementation for following authentication methods:
* Estonian ID-card
* Estonian Mobile-ID

<a name="build"></a>
## Building the webapp

<a name="build_requirements"></a>
### Requirements:

Java (JDK 11+) runtime is required to build and run the webapp. 

<a name="build"></a>
### Building the webapp:

[Maven](https://maven.apache.org/) is used to build and test the software.

To build the software, execute the following command:

````
./mvnw clean package
````

You can find the compiled WAR archive in the target/ directory.

<a name="deploying"></a>
## Deploying the webapp

TARA login server is distributed as a WAR archive that can be deployed to a web server that supports Java Servlets (ie Apache Tomcat).

Example: to deploy the webapp to a standalone Tomcat server

1. Add the tara-login-server-*.war file to Tomcat's webapp directory
2. Set the location of the configuration file in Tomcat's setenv.sh (see chapter Configuration properties for further details)
    ````
    export JAVA_OPTS="$JAVA_OPTS -Dspring.config.additional-location=file:/etc/tara-login-server/application.yml"
    ````

<a name="configuration"></a>
## 1 TARA login server configuration properties

<a name="hydra_integration_conf"></a>
### 1.1 Integration with Hydra service

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Hydra OIDC server login request |
| `tara.hydra-service.reject-login-url` | Yes | Url to reject Hydra OIDC server login request |
| `tara.hydra-service.accept-consent-url` | Yes | Url to accept Hydra OIDC server consent |
| `tara.hydra-service.reject-consent-url` | Yes | Url to reject Hydra OIDC server consent |
| `tara.hydra-service.health-url` | Yes | Hydra service health url |
| `tara.hydra-service.request-timeout-in-seconds` | No | Hydra service request timeout |
| `tara.hydra-service.max-connections-total` | No | Max connection pool size for hydra requests. Defaults to 50 |


<a name="tls_conf"></a>
### 1.2 Trusted TLS certificates

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.tls.trust-store-location` | Yes | Location of the truststore. Path to the location of the trusted CA certificates. In case the certificate files are to be loaded from classpath, this path should be prefixed with `classpath:` (example: `classpath:tls-truststore.p12`). In case the certificate files are to be loaded from disk, this path should be prefixed with `file:` (exaple ``file:/etc/tara/tls-truststore.p12``).  |
| `tara.tls.trust-store-password` | Yes | Truststore password |
| `tara.tls.trust-store-location` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |

<a name="mid_conf"></a>
### 1.3 Mobile-ID auth method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.mobile-id.enabled` | No | Enable or disable this auth method. Default `true` |
| `tara.auth-methods.mobile-id.level-of-assurance` | Yes | Level of assurance of this auth method. Example `HIGH` |
| `tara.auth-methods.mobile-id.host-url` | Yes | Mobile id client url |
| `tara.auth-methods.mobile-id.truststore-path` | Yes | Path to truststore file. Example. `file:src/test/resources/mobileid-truststore-test.p12` |
| `tara.auth-methods.mobile-id.truststore-type` | Yes | Type of the truststore from truststore-path. Example. `PKCS12` |
| `tara.auth-methods.mobile-id.truststore-password` | Yes | Password of the truststore from truststore-path. Example `changeit` |
| `tara.auth-methods.mobile-id.relying-party-uuid` | Yes | UUID from RIA mobile id contract |
| `tara.auth-methods.mobile-id.relying-party-name` | Yes | Name from RIA mobile id contract |
| `tara.auth-methods.mobile-id.hash-type` | Yes | Type of authentication hash. Possible values `SHA256, SHA384, SHA512` |
| `tara.auth-methods.mobile-id.connection-timeout-milliseconds` | No | Connection timeout of the MID authentication initiation request. Default `5000` |
| `tara.auth-methods.mobile-id.read-timeout-milliseconds` | No | Read timeout of the MID authentication initiation request. Default `5000` |
| `tara.auth-methods.mobile-id.long-polling-timeout-seconds` | No | Long polling timeout period used for MID session status requests. Default `30` |
| `tara.auth-methods.mobile-id.interval-between-session-status-queries-in-milliseconds` | No | Interval between Mobile-ID status polling queries (from UI to tara-login-service). Default `5000` |

<a name="esteid_conf"></a>
### 1.4 ID-card auth method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.id-card.enabled` | No | Enable or disable this auth method. Default `true` |
| `tara.auth-methods.id-card.level-of-assurance` | Yes | Level of assurance of this auth method. Example `HIGH` |
| `tara.auth-methods.id-card.truststore-path` | Yes | Path to truststore file. Example `file:src/test/resources/mobileid-truststore-test.p12` |
| `tara.auth-methods.id-card.truststore-type` | Yes | Type of the truststore from truststore-path. Example `PKCS12` |
| `tara.auth-methods.id-card.truststore-password` | Yes | Password of the truststore from truststore-path. Example `changeit` |
| `tara.auth-methods.id-card.ocsp[0].issuer-cn` | Yes | Required issuer CN. Example `TEST of ESTEID-SK 2011, TEST of ESTEID-SK 2015` |
| `tara.auth-methods.id-card.ocsp[0].url` | Yes | Ocsp url. Example `http://aia.demo.sk.ee/esteid2018` |
| `tara.auth-methods.id-card.ocsp[0].nonce-disabled` | No | Default `false` |
| `tara.auth-methods.id-card.ocsp[0].accepted-clock-skew-in-seconds` | No | Default `2L` |
| `tara.auth-methods.id-card.ocsp[0].response-lifetime-in-seconds` | No | Default `900L` |
| `tara.auth-methods.id-card.ocsp[0].connect-timeout-in-milliseconds` | No | Default `3000` |
| `tara.auth-methods.id-card.ocsp[0].read-timeout-in-milliseconds` | No | Default `3000` |
| `tara.auth-methods.id-card.ocsp[0].responder-certificate-cn` | No | Required responder certificate CN. Example `TEST of SK OCSP RESPONDER 2020` |

<a name="legalperson_conf"></a>
## 1.5 Legal person attributes

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.legal-person-authentication.enabled` | No | Enables or disables the legalperson authentication functionality and endpoints. Defaults to `true` if not specified.  |
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
## 1.6 Monitoring

The webapp uses `Spring Boot Actuator` to enable endpoints for monitoring support. To customize Monitoring, Metrics, Auditing, and more see [Spring Boot Actuator documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready).

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `management.endpoints.web.base-path` | No | Base path of heartbeat endpoint. Default `/` |
| `management.endpoints.web.exposure.exclude` | No | Endpoint IDs that should be excluded or `*` for all. Example `heartbeat` Default `*` |
| `management.endpoints.web.exposure.include` | No | Endpoint IDs that should be included or `*` for all. Example `heartbeat` |

<a name="monitoring_heartbeat_conf"></a>
### 1.6.1 Custom application health endpoint configuration

The webapp implements [custom health endpoint](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#production-ready-endpoints-custom) with id `heartbeat` and [custom health indicators](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html#writing-custom-healthindicators) with id's `oidcServer`,  `truststore`. This endpoint is disabled by default.

Request:

````
curl -X GET https://localhost:8443/heartbeat
````

Response:
````
{
	"currentTime": "2021-01-21T11:32:48.955620Z",
	"upTime": "PT11M45S",
	"buildTime": "2021-01-21T11:19:12.785Z",
	"name": "tara-login-server",
	"startTime": "2021-01-21T11:21:03.568Z",
	"commitId": "11111cd7b41f111111dfa93ba2f2cf16b55fef4c",
	"version": "1.0.0-SNAPSHOT",
	"commitBranch": "develop",
	"status": "UP",
	"dependencies": [
		{
			"name": "oidcServer",
			"status": "UP"
		},
		{
			"name": "truststore",
			"status": "UP"
		}
	]
}
````

This endpoint is turned off by default. Here is the minimum required configuration to turn it on:

````yaml
management:
  endpoints:
    web:
      exposure:
        exclude: ""
        include: "heartbeat"
````

<a name="session_and_sec_conf"></a>
## 1.7 Security and session management

<a name="ignite_conf"></a>
### 1.7.1 Ignite configuration

Ignite is used for storing user’s session information.

| Map name        |  Description |
| :---------------- | :---------- |
| `spring:session:sessions` | Session cache. Holds users' session information. Default configuration: cacheMode:PARTITIONED, atomicityMode:ATOMIC, backups:0, expiry: 300s |

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `spring.session.timeout` | No | Session timeout. If a duration suffix is not specified, seconds will be used. Default value `300s` |
| `ignite.ignite-instance-name` | No | Ignite instance name. Default value `tara2-ignite` |
| `ignite.discovery-spi.ip-finder.addresses` | Yes | Ignite cluster node discovery addresses. Should minimally contain local node ip address. Example value `['192.168.1.1','192.168.1.2']` |
| `ignite.ssl-context-factory.key-store-type` | Yes | Ignite key store type. Example value `PKCS12` |
| `ignite.ssl-context-factory.key-store-file-path` | Yes | Ignite key store path. Example value `/test/resources/tls-keystore.p12` |
| `ignite.ssl-context-factory.key-store-password` | Yes | Ignite key store password. |
| `ignite.ssl-context-factory.trust-store-type` | Yes | Ignite trust store type. Example value `PKCS12` |
| `ignite.ssl-context-factory.trust-store-file-path` | Yes | Ignite trust store path. Example value `/test/resources/tls-truststore.p12` |
| `ignite.ssl-context-factory.trust-store-password` | Yes | Ignite trust store password. |

<a name="sec_conf"></a>
## 1.7 Security and Session management
| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `spring.session.timeout` | No | Session timeout. If a duration suffix is not specified, seconds will be used. Default value `300s` |
| `tara.content-security-policy` | No | Content security policy. Default value `connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content` |
