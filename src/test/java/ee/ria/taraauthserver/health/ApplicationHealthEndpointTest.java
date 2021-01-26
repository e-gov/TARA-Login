package ee.ria.taraauthserver.health;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;

import java.time.Clock;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static java.time.ZoneId.of;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.when;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"})
public class ApplicationHealthEndpointTest extends BaseTest {

    @MockBean
    protected BuildProperties buildProperties;

    @MockBean
    protected GitProperties gitProperties;

    @SpyBean
    TruststoreHealthIndicator truststoreHealthIndicator;

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_ok() {
        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        Instant testTime = Instant.now();
        when(gitProperties.getCommitId()).thenReturn("commit-id");
        when(gitProperties.getBranch()).thenReturn("branch");
        when(buildProperties.getName()).thenReturn("tara-auth-server");
        when(buildProperties.getVersion()).thenReturn("0.0.1-SNAPSHOT");
        when(buildProperties.getTime()).thenReturn(testTime);

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(200)
                .body("commitId", equalTo("commit-id"))
                .body("version", equalTo("0.0.1-SNAPSHOT"))
                .body("commitBranch", equalTo("branch"))
                .body("status", equalTo("UP"))
                .body("name", equalTo("tara-auth-server"))
                .body("buildTime", equalTo(testTime.toString()))
                .body("dependencies[0].name", equalTo("oidcServer"))
                .body("dependencies[0].status", equalTo("UP"))
                .body("dependencies[1].name", equalTo("truststore"))
                .body("dependencies[1].status", equalTo("UP"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_Oidc_health_endpoint_response_404() {
        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(404)));

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("dependencies[0].name", equalTo("oidcServer"))
                .body("dependencies[0].status", equalTo("DOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_WARN_KEY_EXPIRATION")
    void applicationHealth_when_certificate_about_to_expire() {
        Instant expectedTime = Instant.parse("2023-09-01T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));

        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("warnings[0]", equalTo("Truststore certificate 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE' with serial number '99797407197858021528704268478232071100' is expiring at 2023-09-07T12:06:09Z"))
                .body("dependencies[0].name", equalTo("oidcServer"))
                .body("dependencies[0].status", equalTo("UP"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_when_certificate_has_expired() {
        Instant expectedTime = Instant.parse("2023-10-01T08:50:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, of("UTC")));

        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("warnings[0]", equalTo("Truststore certificate 'EMAILADDRESS=pki@sk.ee, CN=TEST of ESTEID-SK 2011, O=AS Sertifitseerimiskeskus, C=EE' with serial number '99797407197858021528704268478232071100' is expiring at 2023-09-07T12:06:09Z"))
                .body("dependencies[1].name", equalTo("truststore"))
                .body("dependencies[1].status", equalTo("UNKNOWN"));
    }

}
