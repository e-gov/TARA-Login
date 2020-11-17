# TARA login server
## 1 TARA login server configuration properties

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Hydra OIDC server login |


## Legal person authentication configuration properties

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.legal-person-authentication.enabled` | No | Enables or disables the legalperson authentication functionality and endpoints. Defaults to `true` if not specified.  |
| `tara.legal-person-authentication.x-road-server-url` | Yes | X-Road security request URL. Example `https://localhost:9877/cgi-bin/consumer_proxy`  |
| `x-road-service-member-class` | Yes | X-Road service member class. Example `GOV`  |
| `x-road-service-instance` | Yes | X-Road service instance. Example `ee-dev`  |
| `x-road-service-member-code` | Yes | X-Road service member code. Example `70000310`  |
| `x-road-service-subsystem-code` | Yes | X-Road service subsystem code. Example `arireg`  |
| `x-road-client-member-class` | Yes | X-Road client member class. Example `GOV`  |
| `x-road-client-instance` | Yes | X-Road client instance. Example `ee-dev`  |
| `x-road-client-member-code` | Yes | X-Road client member code. Example `70006317`  |
| `x-road-client-subsystem-code` | Yes | X-Road client subsystem code. Example `idp`  |
| `x-road-server-read-timeout-in-milliseconds` | No | X-Road security server response read timeout in milliseconds. Defaults to 3000 if not specified.  |
| `x-road-server-connect-timeout-in-milliseconds` | No | X-Road security server connect timeout in milliseconds. Defaults to 3000 if not specified.  |
| `x-road-query-esindus-v2-allowed-types` | No | List of legal person types in arireg.esindus_v2 service response that are considered valid for authentication. Defaults to `TÜ,UÜ, OÜ,AS,TÜH,SA,MTÜ` if not specified.  |


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