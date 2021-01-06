package ee.ria.taraauthserver;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.taraauthserver.authentication.idcard.OCSPValidatorTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.RestAssured;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static ch.qos.logback.classic.Level.*;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.config;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static java.util.Arrays.asList;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest {
    protected static final OCSPValidatorTest.OcspResponseTransformer ocspResponseTransformer = new OCSPValidatorTest.OcspResponseTransformer(false);
    protected MockMvc mock;

    @RegisterExtension
    protected static WiremockExtension wireMockServer = new WiremockExtension(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9877)
            .keystorePath("src/test/resources/tls-keystore.jks")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .extensions(ocspResponseTransformer)
            .notifier(new ConsoleNotifier(true))
    );

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    protected SessionRepository<Session> sessionRepository;

    @LocalServerPort
    protected int port;

    private static ListAppender<ILoggingEvent> mockAppender;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        System.setProperty("IGNITE_QUIET", "false");
        System.setProperty("IGNITE_HOME", System.getProperty("java.io.tmpdir"));
        System.setProperty("java.net.preferIPv4Stack", "true");
    }

    @BeforeEach
    public void beforeEachTest() {
        mock = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        RestAssured.port = port;
        setupMockLogAppender();
    }

    @AfterEach
    public void afterEachTest() {
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
        wireMockServer.stubFor(any(urlPathMatching("/mid-api/authentication/session/.*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    protected Session createNewAuthenticationSession(AuthenticationType... authenticationTypes) {
        Session session = sessionRepository.createSession();
        TaraSession testSession = new TaraSession(session.getId());
        testSession.setAllowedAuthMethods(asList(authenticationTypes));
        testSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.Client client = new TaraSession.Client();
        TaraSession.MetaData metaData = new TaraSession.MetaData();
        TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();
        oidcClient.setShortName("short_name");
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        lri.setClient(client);
        testSession.setLoginRequestInfo(lri);
        session.setAttribute(TARA_SESSION, testSession);
        sessionRepository.save(session);
        return session;
    }
}
