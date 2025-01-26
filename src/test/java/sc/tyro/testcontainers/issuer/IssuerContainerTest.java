package sc.tyro.testcontainers.issuer;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@Testcontainers
class IssuerContainerTest {

    @Container
    private static final IssuerContainer defaultIssuerContainer = IssuerContainer.withDefaults();

    @Container
    private static final IssuerContainer securedIssuerContainer = IssuerContainer.securedDefaults();

    @Container
    private static final IssuerContainer customIssuerContainer = new IssuerContainer("custom", true);

    @BeforeAll
    static void beforeAll() {
        // Set TLS certificates
        System.setProperty("javax.net.ssl.trustStore", IssuerContainer.class.getResource("/truststore/cacerts.jks").getFile());
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    @Test
    @DisplayName("Should have expected configuration")
    void shouldHaveExpectedConfiguration() {
        // default
        var url = "http://localhost:" + defaultIssuerContainer.getMappedPort(80) + "/" + defaultIssuerContainer.name();
        assertThat(defaultIssuerContainer.url(), is(url));

        // secured default
        url = "https://localhost:" + securedIssuerContainer.getMappedPort(443) + "/" + securedIssuerContainer.name();
        assertThat(securedIssuerContainer.url(), is(url));

        // custom
        url = "https://localhost:" + customIssuerContainer.getMappedPort(443) + "/" + customIssuerContainer.name();
        assertThat(customIssuerContainer.url(), is(url));
    }

    @Test
    @DisplayName("Should fetch the openid configuration")
    void shouldFetchOpenIdConfiguration() {
        // @formatter:off
        given()
        .when()
            .get(defaultIssuerContainer.url() + "/.well-known/openid-configuration")
        .then()
            .body("issuer", equalTo(defaultIssuerContainer.url()))
            .body("jwks_uri", equalTo(defaultIssuerContainer.url() + "/.well-known/jwks.json"));

        given()
        .when()
            .get(securedIssuerContainer.url() + "/.well-known/openid-configuration")
        .then()
            .body("issuer", equalTo(securedIssuerContainer.url()))
            .body("jwks_uri", equalTo(securedIssuerContainer.url() + "/.well-known/jwks.json"));
        // @formatter:on
    }

    @Test
    @DisplayName("Should serve the JWT public key signature")
    void shouldServeJwtPublicKeySignature() {
        // @formatter:off
        given()
        .when()
            .get(defaultIssuerContainer.url() + "/.well-known/jwks.json")
        .then()
            .body("keys[0].kty", equalTo("RSA"))
            .body("keys[0].n", notNullValue())
            .body("keys[0].e", equalTo("AQAB"))
            .body("keys[0].alg", equalTo("RS256"))
            .body("keys[0].kid", equalTo("test"))
            .body("keys[0].use", equalTo("sig"));

        given()
        .when()
            .get(securedIssuerContainer.url() + "/.well-known/jwks.json")
        .then()
            .body("keys[0].kty", equalTo("RSA"))
            .body("keys[0].n", notNullValue())
            .body("keys[0].e", equalTo("AQAB"))
            .body("keys[0].alg", equalTo("RS256"))
            .body("keys[0].kid", equalTo("test"))
            .body("keys[0].use", equalTo("sig"));
        // @formatter:on
    }

}
