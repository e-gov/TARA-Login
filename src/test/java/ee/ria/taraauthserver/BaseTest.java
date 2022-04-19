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
import ee.ria.taraauthserver.logging.StatisticsLogger;
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
import java.util.function.Predicate;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.DEFAULT_CONTENT_SECURITY_POLICY;
import static io.restassured.RestAssured.config;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@ContextConfiguration(classes = {BaseTestConfiguration.class})
public abstract class BaseTest {
    public static final String CHARSET_UTF_8 = ";charset=UTF-8";

    protected static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<>() {{
        put("X-XSS-Protection", "0");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", DEFAULT_CONTENT_SECURITY_POLICY);
        put("Pragma", "no-cache");
        put("Expires", "0");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        // TODO: Returned during actual application run but for some reason not returned during tests
        // put("Strict-Transport-Security", "max-age=16070400 ; includeSubDomains");
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
    protected static final WireMockServer govssoWireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(8877)
            .keystorePath("src/test/resources/tls-keystore.jks")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
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
        govssoWireMockServer.start();
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
        resetMockLogAppender();
        wireMockServer.resetAll();
        govssoWireMockServer.resetAll();
    }

    @AfterEach
    public void afterEachTest() {
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockAppender);
    }

    protected void resetMockLogAppender() {
        mockAppender = new ListAppender<>();
        mockAppender.start();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockAppender);
    }

    protected List<ILoggingEvent> assertInfoIsLogged(String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(null, INFO, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(null, WARN, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(null, ERROR, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertInfoIsLogged(Class<?> loggerClass, String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, INFO, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(Class<?> loggerClass, String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, WARN, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(Class<?> loggerClass, String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, ERROR, messagePrefixesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertMessageIsLogged(Predicate<ILoggingEvent> additionalFilter, String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(null, null, additionalFilter, messagePrefixesInRelativeOrder);
    }

    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, String... messagePrefixesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, loggingLevel, null, messagePrefixesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String... messagePrefixesInRelativeOrder) {
        List<String> expectedMessages = of(messagePrefixesInRelativeOrder);
        Stream<ILoggingEvent> eventStream = mockAppender.list.stream()
                .filter(e -> loggingLevel == null || e.getLevel() == loggingLevel)
                .filter(e -> loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName()))
                .filter(e -> expectedMessages.stream().anyMatch(expected -> e.getFormattedMessage().startsWith(expected)));
        if (additionalFilter != null) {
            eventStream = eventStream.filter(additionalFilter);
        }
        List<ILoggingEvent> events = eventStream.collect(toList());
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).collect(toList());
        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + of(messagePrefixesInRelativeOrder) + ",\n\tActual log messages: " + messages,
                messages, containsInRelativeOrder(expectedMessages.stream().map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
        return events;
    }

    protected void assertMessageIsNotLogged(Class<?> loggerClass, String exactMessage) {
        String loggedMessage = mockAppender.list.stream()
                .filter(e -> (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .filter(msg -> msg.equals(exactMessage))
                .findFirst()
                .orElse(null);
        assertNull(loggedMessage);
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, String exactMessage, String markerValuePrefix) {
        List<ILoggingEvent> loggingEvents = mockAppender.list.stream()
                .filter(e -> (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())) &&
                        e.getMarker() != null &&
                        e.getFormattedMessage().equals(exactMessage))
                .collect(toList());
        assertThat(loggingEvents, hasSize(1));
        ILoggingEvent loggingEvent = loggingEvents.get(0);
        assertEquals(loggingLevel, loggingEvent.getLevel());
        assertThat(loggingEvent.getMarker().toString(), startsWith(markerValuePrefix));
    }

    protected void assertStatisticsIsLoggedOnce(Level loggingLevel, String exactMessage, String markerValuePrefix) {
        assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, loggingLevel, exactMessage, markerValuePrefix);
    }

    protected void assertStatisticsIsNotLogged() {
        List<ILoggingEvent> loggingEvents = mockAppender.list.stream()
                .filter(e -> e.getLoggerName().equals(StatisticsLogger.class.getCanonicalName()))
                .collect(toList());
        assertThat("No statistics should be logged", loggingEvents, hasSize(0));
    }
}
