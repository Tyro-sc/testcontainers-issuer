[![codecov](https://codecov.io/gh/Tyro-sc/testcontainers-issuer/graph/badge.svg?token=o5hgZV3fcv)](https://codecov.io/gh/Tyro-sc/testcontainers-issuer)

# Introduction

This project is a TestContainers module to stub an Oauth2 Issuer.
It's allows you to test security scenario involving a JWT easily.

For more information about TestContainers, please refer to the [official documentation](https://www.testcontainers.org/).

# Installation

Add the dependency to your project:

```xml
<dependency>
    <groupId>sc.tyro</groupId>
    <artifactId>testcontainers-issuer</artifactId>
    <version>1.0.0</version>
    <scope>test</scope>
</dependency>
```

# Usage

```java
import sc.tyro.testcontainers.issuer.IssuerContainer;

@Container
static IssuerContainer issuer = IssuerContainer.withDefaults();
```

You can also set up a secured issuer (https) with a self-signed certificate with [mkcert](https://mkcert.org/).

```java
import sc.tyro.testcontainers.issuer.IssuerContainer;

@Container
static IssuerContainer issuer = IssuerContainer.securedDefaults();
```

In this case, you need to add the TLS certificate to your truststore.
```java
System.setProperty("javax.net.ssl.trustStore", IssuerContainer.class.getResource("/truststore/cacerts.jks").getFile());
System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
```

Now you have a Docker container exposing the issuer URL.

```java
URL url = issuer.url();
```

The public key is available at the `issuer.url() + ".well-known/jwks.json"` endpoint.
```bash
curl http://localhost:32773/default/.well-known/jwks.json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "test",
      "alg": "RS256",
      "n": "inRAlzsmJXbupYuq_w0BOZElIrzGOS9-C7mXG-G4imUxGhYli0wbNmJS9FE7LrlsFTaZegfC5h6JXF7P0G40k2zA_gTETn_Xo4Dy1hhVgG60V4tOpuxV-KGIwxKa7mlHsn-mThgmeZOs6Erk36Xcqc6rj5G0PTAdiOBIeiMBojVly3JvVB_xegFgW3NEzapwRVkR4qGtlFUT6S_SecbyYq40n7HvoZSRCDw7VY5lpcWgmc3Fit9-_hmgfpTtGURCT5Jjg-BP_4vYr0OXOhzKCFrYsp5XwQcxEp-wM1XhHdrSScBZljOV3_GJlFmJ0J3f-zJzslXlFIAbnFoIqFisNQ"
    }
  ]
}

```

We also provide the URL of the standard OpenID configuration endpoint (.well-known/openid-configuration).
```bash
curl http://localhost:32773/default/.well-known/openid-configuration
{
  "issuer": "http://localhost:32773/default",
  "jwks_uri": "http://localhost:32773/default/.well-known/jwks.json"
} 
```

You can now forge a token.
```java
TokenForgery tokenForgery = issuerContainer.forgery();
tokenForgery.withAudience("audience")
            .withJWTId("jwtId")
            .withSubject("subject")
            .withArrayClaim("scp", "scope::1", "scope::2")
            .withClaim("cid", "client_id")
            .withClaim("pid", "principal_id")
            .expiresAt(expirationTime)
            .issuedAt(now)
            .notBefore(now);

String token = tokenForgery.forge();
```

# Sample test code for SpringBoot

```java
@Testcontainers
@SpringBootTest(webEnvironment = RANDOM_PORT)
class JwtTest {
    @Container
    static IssuerContainer issuerContainer = new IssuerContainer();

    @DynamicPropertySource
    static void auth(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", issuerContainer::url);
    }

    @Test
    void invalidScope() {
        LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(10);
        TokenForgery tokenForgery = issuerContainer.forgery();
        tokenForgery
            .withAudience("audience")
            .withJWTId("jwtId")
            .withSubject("subject")
            .withArrayClaim("scp", "SCOPE_1", "SCOPE_2")
            .withClaim("cid", "client_id")
            .withClaim("resource_access", Map.of("client_id", Map.of("roles", List.of("user", "admin"))))    
            .expiresAt(expiration)
            .issuedAt(now)
            .notBefore(now);

        String accessToken = tokenForgery.forge();

        given()
            .auth()
                .oauth2(accessToken)
        .when()
            .get("/users")
        .then()
            .statusCode(200);
    }
}
```
