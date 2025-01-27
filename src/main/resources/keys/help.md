We used https://mkjwk.org/ to generate all the keys.

RSA

Key Size: 2048
Key Use: Signature
Algorithm: RS256
Key ID: test
Show X.509 Certificate: Yes

Used the:

 - [x] Private Key (X.509 PEM Format)

 - [x] Public Key (X.509 PEM Format)

 - [x] Public Key (jwks.json)

openssl rsa -in key.pem -outform DER -out key.der
openssl rsa -in key-pub.pem -pubin -outform DER -out key-pub.der