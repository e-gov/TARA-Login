# TARA login server
## 1 TARA login server configuration properties

### 1.1 hydra service

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Hydra OIDC server login |
| `tara.hydra-service.accept-consent-url` | Yes | Url to accept Hydra OIDC server consent |
| `tara.hydra-service.request-timeout` | Yes | Hydra service request timeout |

### 1.2 mobile id auth method

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
| `tara.auth-methods.mobile-id.connection-timeout-milliseconds` | Yes | Connection timeout of mobile id requests |
| `tara.auth-methods.mobile-id.read-timeout-milliseconds` | Yes | Read timeout of mobile id requests |

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