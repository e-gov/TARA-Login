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
import ee.ria.taraauthserver.logging.StatisticsLogger.SessionStatistics;
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
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
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
import static java.util.stream.Collectors.toUnmodifiableList;
import net.logstash.logback.marker.LogstashMarker;
import org.slf4j.Marker;
import static net.logstash.logback.marker.Markers.appendFields;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@Import({ConfigurationPropertiesReloader.class})
public abstract class BaseTest {

    @TestBean
    Clock clock;

    static Clock clock() {
        return Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneOffset.UTC);
    }

    public static final String TARA_SESSION_COOKIE_NAME = "__Host-SESSION";
    public static final String CHARSET_UTF_8 = ";charset=UTF-8";

    protected static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<>() {{
        put("X-XSS-Protection", "0");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", DEFAULT_CONTENT_SECURITY_POLICY);
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        put("Expires", "0");
        // TODO: Use HTTPS for API tests. Given header only returned over https.
        // put("Strict-Transport-Security", "max-age=16070400 ; includeSubDomains");
    }};

    protected static final OCSPValidatorTest.OcspResponseTransformer ocspResponseTransformer = new OCSPValidatorTest.OcspResponseTransformer(false);
    protected static final WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9877)
            .keystorePath("src/test/resources/localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .extensions(ocspResponseTransformer)
            .globalTemplating(true)
            .notifier(new ConsoleNotifier(true))
    );
    protected static final WireMockServer govSsoWireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(8877)
            .keystorePath("src/test/resources/localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );
    protected static final WireMockServer xroadWireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
        .httpDisabled(true)
        .httpsPort(7877)
        .needClientAuth(true)
        .trustStorePath("src/test/resources/localhost.truststore.p12")
        .trustStorePassword("changeit")
        .keystorePath("src/test/resources/localhost.keystore.p12")
        .keystorePassword("changeit")
        .keyManagerPassword("changeit")
        .notifier(new ConsoleNotifier(true))
    );
    protected static final Map<String, String> SHORT_NAME_TRANSLATIONS = Map.of(
            "et", "short name et",
            "en", "short name en",
            "ru", "short name with õ"
    );
    private static ListAppender<ILoggingEvent> mockAppender;
    @Autowired
    protected SessionRepository<Session> sessionRepository;

    @Autowired
    protected ConfigurationPropertiesReloader configurationPropertiesReloader;

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        System.setProperty("IGNITE_QUIET", "false");
        System.setProperty("IGNITE_HOME", System.getProperty("java.io.tmpdir"));
        System.setProperty("java.net.preferIPv4Stack", "true");
        wireMockServer.start();
        govSsoWireMockServer.start();
        xroadWireMockServer.start();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        config = config()
                .redirect(redirectConfig().followRedirects(false))
                .sessionConfig(new SessionConfig().sessionIdName(TARA_SESSION_COOKIE_NAME));
    }

    protected static void createMidApiAuthenticationStub(String response, int status) {
        createMidApiAuthenticationStub(response, status, 0);
    }

    protected static void createMidApiAuthenticationStub(String response, int status, int delayInMilliseconds) {
        createMidApiAuthenticationStub(response, status, delayInMilliseconds, "EST", "default short name");
    }

    protected static void createMidApiAuthenticationStub(String response, int status, int delayInMilliseconds, String language, String shortName) {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
                .withRequestBody(matchingJsonPath("$.language", WireMock.equalTo(language)))
                .withRequestBody(matchingJsonPath("$.displayText", WireMock.equalTo(expectedDisplayText(language, shortName))))
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
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v3/authentication/notification/etsi/.*"))
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
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v3/session/de305d54-75b4-431b-adb2-eb6b9e546014"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    private static String expectedDisplayText(String language, String shortName) {
        String prefix = switch (language) {
            case "EST" -> "Logi sisse:";
            case "ENG" -> "Log in:";
            case "RUS" -> "Войти:";
            default -> throw new IllegalArgumentException("Unsupported language: " + language);
        };
        return prefix + " " + shortName;
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.responseSpecification = new ResponseSpecBuilder().expectHeaders(EXPECTED_RESPONSE_HEADERS).build();
        RestAssured.port = port;
        resetMockLogAppender();
        wireMockServer.resetAll();
        govSsoWireMockServer.resetAll();
        xroadWireMockServer.resetAll();
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
        List<ILoggingEvent> events = eventStream.toList();
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat("Expected log messages not found in output.\n\t"
                + "Expected log messages: " + of(messagePrefixesInRelativeOrder) + ",\n\t"
                + "Actual log messages: " + messages,
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

    /**
     * Allows statistics log fields to match regex patterns instead of exact values.
     * Useful for fields that can't use injected test values.
     * Currently not used.
     */
    protected record DynamicField(String name, String pattern) {
        public static DynamicField nonNull(String name) {
            return new DynamicField(name, "[^,)]+");
        }
    }

    private List<ILoggingEvent> findLogEvents(Class<?> loggerClass, Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String exactMessage) {
        Stream<ILoggingEvent> stream = mockAppender.list.stream()
                .filter(e -> (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())) &&
                        e.getLevel().equals(loggingLevel) &&
                        e.getMarker() != null &&
                        e.getFormattedMessage().equals(exactMessage));
        if (additionalFilter != null) {
            stream = stream.filter(additionalFilter);
        }
        return stream.collect(toUnmodifiableList());
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, String exactMessage, String expectedStatistics) {
        assertMessageWithMarkerIsLoggedOnce(loggerClass, loggingLevel, null, exactMessage, expectedStatistics);
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String exactMessage, String expectedStatistics) {
        List<ILoggingEvent> loggingEvents = findLogEvents(loggerClass, loggingLevel, additionalFilter, exactMessage);
        assertThat(loggingEvents, hasSize(1));
        assertThat(loggingEvents.get(0).getMarker().toString(), equalTo(expectedStatistics));
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, String exactMessage, Pattern markerPattern) {
        List<ILoggingEvent> loggingEvents = findLogEvents(loggerClass, loggingLevel, null, exactMessage);
        assertThat(loggingEvents, hasSize(1));
        assertThat(loggingEvents.get(0).getMarker().toString(), matchesPattern(markerPattern));
    }

    protected void assertStatisticsIsLoggedOnce(Level loggingLevel, String exactMessage, SessionStatistics expectedStatistics) {
        assertStatisticsIsLoggedOnce(loggingLevel, null, exactMessage, expectedStatistics, Set.of());
    }

    protected void assertStatisticsIsLoggedOnce(Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String exactMessage, SessionStatistics expectedStatistics) {
        assertStatisticsIsLoggedOnce(loggingLevel, additionalFilter, exactMessage, expectedStatistics, Set.of());
    }

    protected void assertStatisticsIsLoggedOnce(Level loggingLevel, String exactMessage, SessionStatistics expectedStatistics, Set<DynamicField> fieldPatterns) {
        assertStatisticsIsLoggedOnce(loggingLevel, null, exactMessage, expectedStatistics, fieldPatterns);
    }

    protected void assertStatisticsIsLoggedOnce(Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String exactMessage, SessionStatistics expectedStatistics, Set<DynamicField> dynamicFields) {
        List<ILoggingEvent> loggingEvents = findLogEvents(StatisticsLogger.class, loggingLevel, additionalFilter, exactMessage);
        assertThat(loggingEvents, hasSize(1));

        String actualString = extractSessionStatisticsString(loggingEvents.get(0));
        Map<String, String> actualFields = parseStatisticsFields(actualString);
        String expectedString = appendFields(expectedStatistics).toString();
        Map<String, String> expectedFields = parseStatisticsFields(expectedString);
        assertStatisticsFields(actualFields, expectedFields, dynamicFields);
    }

    private void assertStatisticsFields(Map<String, String> actualFields, Map<String, String> expectedFields, Set<DynamicField> dynamicFields) {
        for (Map.Entry<String, String> field : expectedFields.entrySet()) {
            String fieldName = field.getKey();
            DynamicField dynamicField = findDynamicField(fieldName, dynamicFields);
            if (dynamicField != null) {
                String actualValue = actualFields.get(fieldName);
                assertThat("Dynamic field: " + fieldName, actualValue, matchesPattern(dynamicField.pattern()));
                continue;
            }
            String actualValue = actualFields.get(fieldName);
            String expectedValue = field.getValue();
            assertThat("Static field: " + fieldName, actualValue, equalTo(expectedValue));
        }

        Set<String> unexpectedKeys = new HashSet<>(actualFields.keySet());
        unexpectedKeys.removeAll(expectedFields.keySet());
        assertThat("Unexpected fields in actual statistics", unexpectedKeys, empty());
    }

    private DynamicField findDynamicField(String fieldName, Set<DynamicField> dynamicFields) {
        for (DynamicField dynamicField : dynamicFields) {
            if (dynamicField.name().equals(fieldName)) {
                return dynamicField;
            }
        }
        return null;
    }

    private static String extractSessionStatisticsString(ILoggingEvent event) {
        Marker marker = event.getMarker();
        if (!(marker instanceof LogstashMarker)) {
            throw new AssertionError("Expected LogstashMarker for statistics event but got: " + marker.getClass().getName());
        }
        LogstashMarker statisticsMarker = (LogstashMarker) marker;
        if (!statisticsMarker.hasReferences()) {
            return statisticsMarker.toString();
        }
        String fullString = statisticsMarker.toString();
        return removeReferencesSuffix(fullString, findReferencesSuffix(statisticsMarker));
    }

    private static String findReferencesSuffix(LogstashMarker marker) {
        StringBuilder sb = new StringBuilder();
        for (Marker ref : marker) {
            String refStr = ref.toString();
            if (!refStr.isEmpty()) {
                sb.append(", ").append(refStr);
            }
        }
        return sb.toString();
    }

    private static String removeReferencesSuffix(String fullString, String suffix) {
        return fullString.substring(0, fullString.length() - suffix.length());
    }

    private static Map<String, String> parseStatisticsFields(String statisticsString) {
        return parseFields(stripOuterParentheses(statisticsString));
    }

    private static String stripOuterParentheses(String statisticsString) {
        int openParen = statisticsString.indexOf('(');
        int closeParen = statisticsString.lastIndexOf(')');
        if (openParen >= 0 && closeParen > openParen) {
            return statisticsString.substring(openParen + 1, closeParen);
        }
        return statisticsString;
    }

    private static Map<String, String> parseFields(String content) {
        Map<String, String> fields = new HashMap<>();
        for (String pairString : content.split(", ")) {
            int separatorIndex = pairString.indexOf('=');
            if (separatorIndex > 0) {
                String key = pairString.substring(0, separatorIndex);
                String value = pairString.substring(separatorIndex + 1);
                fields.put(key, value);
            }
        }
        return fields;
    }

    protected static SessionStatistics.SessionStatisticsBuilder defaultStatisticsMarkerBuilder() {
        return SessionStatistics.builder();
    }

    protected void assertStatisticsIsNotLogged() {
        List<ILoggingEvent> loggingEvents = mockAppender.list.stream()
                .filter(e -> e.getLoggerName().equals(StatisticsLogger.class.getCanonicalName()))
                .collect(toList());
        assertThat("No statistics should be logged", loggingEvents, hasSize(0));
    }
}
