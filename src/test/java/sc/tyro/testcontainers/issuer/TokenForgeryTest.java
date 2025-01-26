package sc.tyro.testcontainers.issuer;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;
import static java.time.LocalDateTime.now;
import static java.time.ZoneId.systemDefault;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@Testcontainers
class TokenForgeryTest {

    private static JWTVerifier jwtVerifier;

    @Container
    private static final IssuerContainer issuerContainer = IssuerContainer.withDefaults();

    @BeforeAll
    static void setUp() {
        // public key
        JwkProvider jwkProvider = new JwkProviderBuilder(issuerContainer.url()).build();
        RSAKeyProvider keyProvider = createKeyProvider(jwkProvider);
        jwtVerifier = JWT.require(RSA256(keyProvider)).withIssuer(issuerContainer.url()).build();
    }

    @Test
    @DisplayName("Should forge JWT token with expected claims")
    void shouldForgeJwtToken() {
        LocalDateTime now = now(systemDefault());
        LocalDateTime expirationTime = now.plusMinutes(5);

        // @formatter:off
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
        // @formatter:on

        DecodedJWT jwt = jwtVerifier.verify(token);
        assertThat(jwt.getIssuer(), is(issuerContainer.url()));
        assertThat(jwt.getAudience(), contains("audience"));
        assertThat(jwt.getKeyId(), is("test"));
        assertThat(jwt.getId(), is("jwtId"));
        assertThat(jwt.getSubject(), is("subject"));

        assertThat(jwt.getExpiresAt(), equalTo(convert(expirationTime)));
        assertThat(jwt.getNotBefore(), equalTo(convert(now)));
        assertThat(jwt.getIssuedAt(), equalTo(convert(now)));

        assertThat(jwt.getClaim("cid").asString(), is("client_id"));
        assertThat(jwt.getClaim("pid").asString(), is("principal_id"));
        assertThat(jwt.getClaim("scp").asList(String.class), contains("scope::1", "scope::2"));
        assertThat(jwt.getClaims().size(), is(10));
    }

    private static Date convert(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(systemDefault()).withNano(0).toInstant());
    }

    private static RSAKeyProvider createKeyProvider(JwkProvider jwkProvider) {
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                PublicKey publicKey;
                try {
                    publicKey = jwkProvider.get(keyId).getPublicKey();
                } catch (Exception e) {
                    throw new RuntimeException("Failed to get public key", e);
                }
                return (RSAPublicKey) publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return "";
            }
        };
    }

}
