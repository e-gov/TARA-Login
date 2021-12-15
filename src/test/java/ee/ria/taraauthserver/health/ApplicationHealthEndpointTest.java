package ee.ria.taraauthserver.health;

import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;
import com.github.dockerjava.api.model.TmpfsOptions;
import ee.ria.taraauthserver.BaseTest;
import lombok.SneakyThrows;
import org.apache.groovy.util.Maps;
import org.apache.ignite.Ignite;
import org.apache.ignite.cluster.ClusterState;
import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.unit.DataSize;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.utility.LazyFuture;

import java.io.File;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Future;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static java.time.ZoneId.of;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"})
class ApplicationHealthEndpointTest extends BaseTest {
    private static final Map<String, String> TESTCONTAINER_ENV = Map.of("LOG_HOME", "/logs",
            "LOG_FILE_LEVEL", "INFO",
            "spring.config.location", "/workspace/src/test/resources/application.yml",
            "tara.hydra-service.health-url", String.format("https://hydra:%s/health/ready", MockServerContainer.PORT),
            "tara.tls.trust-store-location", "/workspace/src/test/resources/tls-truststore.jks",
            "management.endpoints.web.exposure.exclude", "",
            "management.endpoints.web.exposure.include", "heartbeat",
            "management.endpoint.health.show-details", "always");
    private static final Future<String> TESTCONTAINER_IMAGE_BUILD_FUTURE = new LazyFuture<>() {
        @Override
        protected String resolve() {
            buildApplicationImage();
            return "tara-login-server:latest:latest";
        }
    };

    @MockBean
    BuildProperties buildProperties;

    @Autowired
    Ignite ignite;

    @MockBean
    GitProperties gitProperties;

    @SpyBean
    TruststoreHealthIndicator truststoreHealthIndicator;

    @SneakyThrows
    static void buildApplicationImage() {
        System.setProperty("maven.home", findMvn());

        var properties = new Properties();
        properties.put("skipTests", "true");

        File cwd = new File(".");
        while (!new File(cwd, "pom.xml").isFile()) {
            cwd = cwd.getParentFile();
        }

        var request = new DefaultInvocationRequest()
                .setPomFile(new File(cwd, "pom.xml"))
                .setGoals(List.of("spring-boot:build-image"))
                .setProperties(properties);

        var invocationResult = new DefaultInvoker().execute(request);
        if (invocationResult.getExitCode() != 0) {
            throw new RuntimeException(invocationResult.getExecutionException());
        }
    }

    static String findMvn() {
        String m2Home = System.getenv("M2_HOME");
        if (m2Home != null) {
            return m2Home;
        }
        for (String dirname : System.getenv("PATH").split(File.pathSeparator)) {
            File file = new File(dirname, "mvn");
            if (file.isFile() && file.canExecute()) {
                return new File(dirname).getParentFile().toString();
            }
        }
        throw new RuntimeException("Maven not found");
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenDependenciesUp_HealthUp() {

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
                .body("dependencies[0].name", equalTo("ignite"))
                .body("dependencies[0].status", equalTo("UP"))
                .body("dependencies[1].name", equalTo("logger"))
                .body("dependencies[1].status", equalTo("UP"))
                .body("dependencies[2].name", equalTo("oidcServer"))
                .body("dependencies[2].status", equalTo("UP"))
                .body("dependencies[3].name", equalTo("truststore"))
                .body("dependencies[3].status", equalTo("UP"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenOidcHealthStatus404_HealthDown() {
        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(404)));

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("dependencies[2].name", equalTo("oidcServer"))
                .body("dependencies[2].status", equalTo("DOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenOidcHealthStatus503_HealthDown() {
        wireMockServer.stubFor(any(urlPathEqualTo("/health/ready"))
                .willReturn(aResponse().withStatus(503)));

        given()
                .when()
                .get("/heartbeat")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("dependencies[2].name", equalTo("oidcServer"))
                .body("dependencies[2].status", equalTo("DOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_WARN_KEY_EXPIRATION")
    void applicationHealth_WhenTruststoreCertificateAboutToExpire_HealthUpWithWarnings() {
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
                .body("dependencies[2].name", equalTo("oidcServer"))
                .body("dependencies[2].status", equalTo("UP"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenTruststoreCertificateHasExpired_HealthDownWithWarnings() {
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
                .body("dependencies[3].name", equalTo("truststore"))
                .body("dependencies[3].status", equalTo("UNKNOWN"));
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenIgniteClusterStateInactive_HealthDown() {

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

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenFileDeleted_HealthDown() {
        try (GenericContainer<?> container = new GenericContainer<>(TESTCONTAINER_IMAGE_BUILD_FUTURE)
                .withTmpFs(Maps.of("/logs", "rw"))
                .withFileSystemBind("./src/test/resources", "/workspace/src/test/resources")
                .withEnv(TESTCONTAINER_ENV)
                .withExposedPorts(8080)) {
            container.start();
            Integer mappedPort = container.getMappedPort(8080);
            assertTrue(container.isRunning());
            given()
                    .when()
                    .port(mappedPort)
                    .get("/heartbeat")
                    .then()
                    .assertThat()
                    .statusCode(503)
                    .body("dependencies[1].name", equalTo("logger"))
                    .body("dependencies[1].status", equalTo("UP"));
            String fileDate = DateTimeFormatter.ofPattern("yyyy-MM-dd").format(ZonedDateTime.now(ZoneId.of("UTC")));
            String logFileName = String.format("/logs/TaraLoginService.%s.log", fileDate);
            assertDoesNotThrow(() -> container.execInContainer("rm", logFileName));

            given()
                    .when()
                    .port(mappedPort)
                    .get("/heartbeat")
                    .then()
                    .assertThat()
                    .statusCode(503)
                    .body("status", equalTo("DOWN"))
                    .body("dependencies[1].name", equalTo("logger"))
                    .body("dependencies[1].status", equalTo("DOWN"))
                    .body("dependencies[1].details.error", equalTo("File handle error"));

        }
    }

    @Test
    @Tag(value = "HEALTH_MONITORING_ENDPOINT")
    @Tag(value = "HEALTH_MONITORING_STATUS")
    void applicationHealth_WhenNoDiskSpace_HealthDown() {
        try (GenericContainer<?> container = new GenericContainer<>(TESTCONTAINER_IMAGE_BUILD_FUTURE)
                .withCreateContainerCmdModifier(cmd -> cmd.getHostConfig()
                        .withMounts(of(new Mount()
                                        .withTarget("/logs")
                                        .withType(MountType.TMPFS)
                                        .withTmpfsOptions(new TmpfsOptions()
                                                .withSizeBytes(DataSize.ofKilobytes(1).toBytes()))
                                )
                        )
                )
                .withFileSystemBind("./src/test/resources", "/workspace/src/test/resources")
                .withEnv(TESTCONTAINER_ENV)
                .withExposedPorts(8080)) {
            container.start();
            assertTrue(container.isRunning());
            Integer mappedPort = container.getMappedPort(8080);

            await().atMost(FIVE_SECONDS)
                    .untilAsserted(() -> given()
                            .when()
                            .port(mappedPort)
                            .get("/heartbeat")
                            .then()
                            .assertThat()
                            .statusCode(503)
                            .body("status", equalTo("DOWN"))
                            .body("dependencies[1].name", equalTo("logger"))
                            .body("dependencies[1].status", equalTo("DOWN"))
                            .body("dependencies[1].details.error", equalTo("I/O error")));

        }
    }
}
