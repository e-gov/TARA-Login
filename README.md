# TARA login server
## 1 TARA login server configuration properties

| Parameter        | Mandatory | Description, example |
| :---------------- | :---------- | :----------------|
| `tara.hydra-service.login-url` | Yes | Url to initialize Hydra OIDC server login process |
| `tara.hydra-service.accept-login-url` | Yes | Url to accept Hydra OIDC server login |

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