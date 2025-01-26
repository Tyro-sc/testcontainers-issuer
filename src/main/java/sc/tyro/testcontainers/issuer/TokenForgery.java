package sc.tyro.testcontainers.issuer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

import static java.util.Date.from;
import static org.apache.commons.io.IOUtils.toByteArray;

public class TokenForgery {

    private static final String PRIVATE_KEY_PATH = "/keys/key.der";
    private static final String PUB_KEY_PATH = "/keys/key-pub.der";
    private static final String KEY_ID = "test";

    private final JWTCreator.Builder jwtCreator = JWT.create();
    private final Map<String, String[]> claims = new HashMap<>();


    public TokenForgery(String issuer) {
        jwtCreator.withIssuer(issuer);
    }

    public TokenForgery withAudience(String... audience) {
        jwtCreator.withAudience(audience);
        return this;
    }

    public TokenForgery withJWTId(String jwtId) {
        jwtCreator.withJWTId(jwtId);
        return this;
    }

    public TokenForgery withSubject(String subject) {
        jwtCreator.withSubject(subject);
        return this;
    }

    public TokenForgery withArrayClaim(String name, String... values) {
        claims.put(name, values);
        return this;
    }

    public TokenForgery withClaim(String name, String value) {
        jwtCreator.withClaim(name, value);
        return this;
    }

    public TokenForgery expiresAt(LocalDateTime expirationTime) {
        jwtCreator.withExpiresAt(from(expirationTime.atZone(ZoneId.systemDefault()).toInstant()));
        return this;
    }

    public TokenForgery issuedAt(LocalDateTime issuedAt) {
        jwtCreator.withIssuedAt(from(issuedAt.atZone(ZoneId.systemDefault()).toInstant()));
        return this;
    }

    public TokenForgery notBefore(LocalDateTime notBefore) {
        jwtCreator.withNotBefore(from(notBefore.atZone(ZoneId.systemDefault()).toInstant()));
        return this;
    }

    public String forge() {
        Algorithm algorithm;
        try {
            // public key
            byte[] publicKeyBytes = toByteArray(TokenForgery.class.getResourceAsStream(PUB_KEY_PATH));
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

            // private key
            byte[] privateKeyBytes = toByteArray(TokenForgery.class.getResourceAsStream(PRIVATE_KEY_PATH));
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

            algorithm = Algorithm.RSA256(publicKey, privateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to create algorithm", e);
        }

        jwtCreator.withKeyId(KEY_ID);
        claims.forEach(jwtCreator::withArrayClaim);
        return jwtCreator.sign(algorithm);
    }

}
