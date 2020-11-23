# TARA login server
## 1 TARA login server configuration properties

### 1.1 hydra service

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Hydra OIDC server login |
| `tara.hydra-service.accept-consent-url` | Yes | Url to accept Hydra OIDC server consent |
| `tara.hydra-service.request-timeout` | Yes | Hydra service request timeout |

### 1.2 trusted TLS certificates

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.tls.trust-store-location` | Yes | Location of the truststore. Path to the location of the trusted CA certificates. In case the certificate files are to be loaded from classpath, this path should be prefixed with `classpath:` (example: `classpath:tls-truststore.p12`). In case the certificate files are to be loaded from disk, this path should be prefixed with `file:` (exaple ``file:/etc/tara/tls-truststore.p12``).  |
| `tara.tls.trust-store-password` | Yes | Truststore password |
| `tara.tls.trust-store-location` | No | Truststore type (jks, pkcs12). Defaults to PKCS12 if not specified |

### 1.3 mobile id auth method

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.auth-methods.mobile-id.enabled` | Yes | Enable or disable this auth method, default - true |
| `tara.auth-methods.mobile-id.level-of-assurance` | Yes | Level of assurance of this auth method, example - HIGH |
| `tara.auth-methods.mobile-id.host-url` | Yes | Mobile id client url |
| `tara.auth-methods.mobile-id.truststore-path` | Yes | Path to truststore file, example - file:src/test/resources/mobileid-truststore-test.p12 |
| `tara.auth-methods.mobile-id.truststore-type` | Yes | Type of the truststore from truststore-path, example - PKCS12 |
| `tara.auth-methods.mobile-id.truststore-password` | Yes | Password of the truststore from truststore-path |
| `tara.auth-methods.mobile-id.relying-party-uuid` | Yes | UUID from RIA mobile id contract |
| `tara.auth-methods.mobile-id.relying-party-name` | Yes | Name from RIA mobile id contract |
| `tara.auth-methods.mobile-id.hash-type` | Yes | Type of authentication hash, possible values - SHA256, SHA384, SHA512 |
| `tara.auth-methods.mobile-id.connection-timeout-milliseconds` | No | Connection timeout of the MID authentication initiation request. Defaults to 5000 if not specified. |
| `tara.auth-methods.mobile-id.read-timeout-milliseconds` | No | Read timeout of the MID authentication initiation request. Defaults to 5000 if not specified. |
| `tara.auth-methods.mobile-id.long-polling-timeout-seconds` | No | Long polling timeout period used for MID session status requests. Defaults to 30 if not specified. |


## 1.4 Legal person authentication configuration properties

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
| `tara.legal-person-authentication.x-road-query-esindus-v2-allowed-types` | No | List of legal person types in arireg.esindus_v2 service response that are considered valid for authentication. Defaults to `TÜ,UÜ, OÜ,AS,TÜH,SA,MTÜ` if not specified.  |


## 2 TARA login server endpoints

### 2.1 /auth/init

#### Request:

````
GET /auth/init?login_challenge={login_challenge}
````

| Parameter        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `login_challenge` | Yes | Only numbers and characters allowed (a-ZA-Z0-9). Max 50 symbols. |

#### Response:

##### Response Code: 200

##### Headers

````
Set-Cookie: SESSION={sessionId}; Path=/; HttpOnly; SameSite=Strict
Content-Type: text/html;charset=UTF-8
````

##### Body

````
HTML page including a form with a personalized list of authentication methods
````

### 2.2 /auth/accept

#### Request:

````
GET /auth/accept
````

| Cookie        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `SESSION` | Yes | id of an existing session |

#### Response:

##### Response Code: 302

##### Headers

````
Location: {redirectUrl}
````

### 2.3 /auth/mid/init

#### Request:

````
POST /auth/mid/init
````

| Cookie        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `SESSION` | Yes | id of an existing session |

| Form Parameter        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `idCode` | Yes | Personal ID code |
| `telephoneNumber` | Yes | Phone number used for authentication |

#### Response:

##### Response Code: 200

##### Headers

````
Set-Cookie: SESSION={sessionId}; Path=/; HttpOnly; SameSite=Strict
Content-Type: text/html;charset=UTF-8
````

##### Body

````
HTML page including a control code for mobile authentication
````

### 2.4 /auth/mid/poll

#### Request:

````
GET /auth/mid/poll
````

| Cookie        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `SESSION` | Yes | id of an existing session |

#### Response:

##### Response Code: 200

##### Headers

````
Set-Cookie: SESSION={sessionId}; Path=/; HttpOnly; SameSite=Strict
Content-Type: application/json
````

##### Body

Example json:
````
{"status":"PENDING"}
````