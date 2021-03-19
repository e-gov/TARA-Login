package ee.ria.taraauthserver;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.config.SessionConfig;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.ContextConfiguration;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ch.qos.logback.classic.Level.*;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.DEFAULT_CONTENT_SECURITY_POLICY;
import static io.restassured.RestAssured.config;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@ContextConfiguration(classes = {BaseTestConfiguration.class})
public abstract class BaseTest {
    public static final String CHARSET_UTF_8 = ";charset=UTF-8";

    protected static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<>() {{
        put("X-XSS-Protection", "1; mode=block");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", DEFAULT_CONTENT_SECURITY_POLICY);
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
    }};

    protected static final OCSPValidatorTest.OcspResponseTransformer ocspResponseTransformer = new OCSPValidatorTest.OcspResponseTransformer(false);
    protected static final WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9877)
            .keystorePath("src/test/resources/tls-keystore.jks")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .extensions(ocspResponseTransformer)
            .notifier(new ConsoleNotifier(true))
    );
    private static ListAppender<ILoggingEvent> mockAppender;
    @Autowired
    protected SessionRepository<Session> sessionRepository;

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        System.setProperty("IGNITE_QUIET", "false");
        System.setProperty("IGNITE_HOME", System.getProperty("java.io.tmpdir"));
        System.setProperty("java.net.preferIPv4Stack", "true");
        wireMockServer.start();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        config = config()
                .redirect(redirectConfig().followRedirects(false))
                .sessionConfig(new SessionConfig().sessionIdName("SESSION"));
    }

    protected static void createMidApiAuthenticationStub(String response, int status) {
        createMidApiAuthenticationStub(response, status, 0);
    }

    protected static void createMidApiAuthenticationStub(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
                .withRequestBody(matchingJsonPath("$.language", WireMock.equalTo("EST")))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    protected static void createMidApiPollStub(String response, int status) {
        createMidApiPollStub(response, status, 0);
    }

    protected static void createMidApiPollStub(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathMatching("/mid-api/authentication/session/.*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    protected static void createSidApiAuthenticationStub(String response, int status) {
        createSidApiAuthenticationStub(response, status, 0);
    }

    protected static void createSidApiAuthenticationStub(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v2/authentication/etsi/.*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    protected static void createSidApiPollStub(String response, int status) {
        createSidApiPollStub(response, status, 0);
    }

    protected static void createSidApiPollStub(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v2/session/de305d54-75b4-431b-adb2-eb6b9e546014"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.responseSpecification = new ResponseSpecBuilder().expectHeaders(EXPECTED_RESPONSE_HEADERS).build();
        RestAssured.port = port;
        configureMockLogAppender();
        wireMockServer.resetAll();
    }

    @AfterEach
    public void afterEachTest() {
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockAppender);
    }

    private void configureMockLogAppender() {
        mockAppender = new ListAppender<>();
        mockAppender.start();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockAppender);
    }

    protected void assertInfoIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, INFO, messagesInRelativeOrder);
    }

    protected void assertWarningIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, WARN, messagesInRelativeOrder);
    }

    protected void assertErrorIsLogged(String... messagesInRelativeOrder) {
        assertMessageIsLogged(null, ERROR, messagesInRelativeOrder);
    }

    protected void assertInfoIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, INFO, messagesInRelativeOrder);
    }

    protected void assertWarningIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, WARN, messagesInRelativeOrder);
    }

    protected void assertErrorIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        assertMessageIsLogged(loggerClass, ERROR, messagesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private void assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel,
                                       String... messagesInRelativeOrder) {
        List<String> events = mockAppender.list.stream()
                .filter(e -> e.getLevel() == loggingLevel && (loggerClass == null
                        || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .collect(toList());

        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + List.of(messagesInRelativeOrder) + ",\n\tActual log messages: " + events, events, containsInRelativeOrder(stream(messagesInRelativeOrder)
                .map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
    }
}
