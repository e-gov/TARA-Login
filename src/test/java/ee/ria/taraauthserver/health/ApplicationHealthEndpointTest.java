package ee.ria.taraauthserver.health;

import ee.ria.taraauthserver.BaseTest;
import io.restassured.response.Response;
import java.util.Arrays;
import java.util.List;
import org.apache.ignite.Ignite;
import org.apache.ignite.cluster.ClusterState;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static java.time.ZoneId.of;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.mockito.Mockito.when;

public class ApplicationHealthEndpointTest extends BaseTest {

    @MockitoBean
    protected BuildProperties buildProperties;

    @Autowired
    private Ignite ignite;

    @MockitoBean
    protected GitProperties gitProperties;

    @MockitoSpyBean
    TruststoreHealthIndicator truststoreHealthIndicator;

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_ok() {
        Instant testTime = Instant.parse("2025-01-01T00:00:00Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(testTime, of("UTC")));

        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        when(gitProperties.getCommitId()).thenReturn("commit-id");
        when(gitProperties.getBranch()).thenReturn("branch");
        when(buildProperties.getName()).thenReturn("tara-auth-server");
        when(buildProperties.getVersion()).thenReturn("0.0.1-SNAPSHOT");
        when(buildProperties.getTime()).thenReturn(testTime);

        List<String> expectedDependencies = Arrays.asList("ignite", "oidcServer", "truststore");
        Response response =
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
                // Assert that the dependency names list contains all expected dependencies
                .body("dependencies.name", hasItems(expectedDependencies.toArray(new String[0])))
                .body("dependencies.name", not(hasItem("ssl")))
                .extract().response();

        expectedDependencies.forEach(dep ->
            response.then().body("dependencies.find { it.name == '" + dep + "' }.status", equalTo("UP"))
        );
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
                .body("dependencies[1].name", equalTo("oidcServer"))
                .body("dependencies[1].status", equalTo("DOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_WARN_KEY_EXPIRATION")
    void applicationHealth_when_certificate_about_to_expire() {
        Instant expectedTime = Instant.parse("2025-03-21T00:00:00Z");
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
                .body("warnings[0]", equalTo("Truststore certificate 'CN=TEST of KLASS3-SK 2010, OU=Sertifitseerimisteenused, O=AS Sertifitseerimiskeskus, C=EE' with serial number '46174084079274426180990408274615839251' is expiring at 2025-03-21T10:58:29Z"))
                .body("dependencies[1].name", equalTo("oidcServer"))
                .body("dependencies[1].status", equalTo("UP"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_when_certificate_has_expired() {
        Instant expectedTime = Instant.parse("2025-03-21T23:59:59Z");
        Mockito.when(truststoreHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(expectedTime, ZoneOffset.UTC));

        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        given()
            .when()
            .get("/heartbeat")
            .then()
            .assertThat()
            .statusCode(200)
            .body("status", equalTo("UP"))
            .body("warnings[0]", equalTo("Truststore certificate 'CN=TEST of KLASS3-SK 2010, OU=Sertifitseerimisteenused, O=AS Sertifitseerimiskeskus, C=EE' with serial number '46174084079274426180990408274615839251' is expiring at 2025-03-21T10:58:29Z"))
            .body("dependencies.find{it.name=='truststore'}.name", equalTo("truststore"))
            .body("dependencies.find{it.name=='truststore'}.status", equalTo("UNKNOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_when_ignite_is_down() {

        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(200)));

        ignite.cluster().state(ClusterState.INACTIVE);

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("dependencies[0].name", equalTo("ignite"))
                .body("dependencies[0].status", equalTo("DOWN"));

        ignite.cluster().state(ClusterState.ACTIVE);
    }

}
