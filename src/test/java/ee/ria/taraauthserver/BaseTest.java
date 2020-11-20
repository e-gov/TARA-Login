package ee.ria.taraauthserver;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static ch.qos.logback.classic.Level.*;
import static io.restassured.RestAssured.config;
import static io.restassured.RestAssured.given;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest {
    protected MockMvc mock;
    protected static WireMockServer wireMockServer;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @LocalServerPort
    protected int port;

    private static ListAppender<ILoggingEvent> mockAppender;

    @Test
    @Order(1)
    void contextLoads() {
        assertNotNull(webApplicationContext, "Should not be null!");
    }

    @BeforeAll
    static void setUpAll() {
        configureWiremockServer();
        configureRestAssured();
    }

    @AfterAll
    static void tearDownAll() {
        wireMockServer.stop();
    }

    @BeforeEach
    public void beforeEachTest() {
        mock = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        RestAssured.port = port;
        setupMockLogAppender();
        wireMockServer.resetAll();
    }

    @AfterEach
    public void afterEachTest() {
        wireMockServer.resetAll();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockAppender);
    }

    private void setupMockLogAppender() {
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

    protected static void configureRestAssured() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        config = config().redirect(redirectConfig().followRedirects(false));
    }

    private static void configureWiremockServer() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .httpDisabled(true)
                .httpsPort(9877)
                .keystorePath("src/test/resources/tls-keystore.jks")
                .keystorePassword("changeit")
                .notifier(new ConsoleNotifier(true))
        );
        wireMockServer.start();
    }

}
