# Spring Boot 2 Oauth2 Authorization Server with jwt tokens

## Certificate configuration
Keypair generation:
`keytool -genkeypair -alias jwtcert -keyalg RSA  -keypass mypass  -keystore authorization-server.jks  -storepass mypass`

Export public certificate:
`keytool -list -rfc --keystore authorization-server.jks | openssl x509 -inform pem -pubkey`
`keytool -list -rfc --keystore authorization-server.jks | openssl x509 -inform pem -pubkey -noout`

## Usage

Token request: 
`http://localhost:8080/oauth/authorize?client_id=front-app&redirect_uri=http://localhost/tonr2/sparklr/photos&response_type=token&scope=operate&state=g72OJm`

Retrieve signing cert from server:
`http://localhost:8080/oauth/token_key`


