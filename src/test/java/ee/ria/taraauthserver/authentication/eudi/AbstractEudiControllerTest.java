package ee.ria.taraauthserver.authentication.eudi;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.logging.StatisticsLogger.SessionStatistics;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import io.restassured.response.ValidatableResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.function.Predicate;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EUDI_WALLET;
import static ee.ria.taraauthserver.security.SessionManagementFilter.MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.EXTERNAL_TRANSACTION;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_CALLBACK;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.DC_API;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.WEB2APP;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"}) // Disabled to avoid EIDAS /supportedCountries API call
abstract class AbstractEudiControllerTest extends BaseTest {

    /** Session id of mock_responses/eudi/offer_web2app_response.json. */
    protected static final String WEB2APP_PRESENTATION_SESSION_ID = "5f0a7c2e-1d2e-4f3a-9b8c-7d6e5f4a3b2c";
    /** Session id of mock_responses/eudi/offer_dc_api_response.json. */
    protected static final String DC_API_PRESENTATION_SESSION_ID = "2e4b6d8f-0a1c-4e3d-8f5a-6b7c8d9e0f1a";
    /** walletNonce of the Digital Credentials API session fixtures. */
    protected static final String DC_API_WALLET_NONCE = "c4d5e6f7-1111-4abc-9def-0123456789ab";
    protected static final String DC_API_WALLET_RESPONSE_PATH = "/presentations/" + DC_API_WALLET_NONCE + "/oid4vp";
    /** A compact JWE, as a wallet answers with response mode dc_api.jwt. Encrypted for eudiplo, opaque to TARA. */
    protected static final String WALLET_JWE = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..aXYtMTIzNDU2.Y2lwaGVydGV4dC1vZi10aGUtcHJlc2VudGF0aW9u.dGFn";
    /** responseCode of the completed Web2App session fixtures. */
    protected static final String RESPONSE_CODE = "3c2b1a09-5555-4666-8777-888899990000";
    /** tara.site-origin of the test configuration + the callback path. */
    protected static final String EXPECTED_REDIRECT_URI = "https://example.com/auth/eudi/callback";
    /** eudi_settings.presentation_config_id of the client of the mock sessions. */
    protected static final String PRESENTATION_CONFIG_ID = "pid-openIdDemo";

    protected static final String CALLBACK_INVALID_MESSAGE =
            "Digikukru rakenduse vastust ei õnnestunud kontrollida. Palun alustage sisselogimist uuesti.";
    protected static final String INTERNAL_ERROR_MESSAGE =
            "Euroopa Liidu digikukruga autentimisel esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti.";


    protected void startWeb2AppAuthentication(MockSessionFilter sessionFilter) {
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(200);
    }

    protected void startDcApiAuthentication(MockSessionFilter sessionFilter) {
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(200);
    }

    protected ValidatableResponse dcApiResponse(MockSessionFilter sessionFilter, String body) {
        return given()
                .filter(sessionFilter)
                .contentType("application/json")
                .accept("application/json")
                .body(body)
                .when()
                .post("/auth/eudi/dc-api/response")
                .then()
                .assertThat();
    }

    protected ValidatableResponse dcApiError(MockSessionFilter sessionFilter, String body) {
        return given()
                .filter(sessionFilter)
                .contentType("application/json")
                .accept("application/json")
                .body(body)
                .when()
                .post("/auth/eudi/dc-api/error")
                .then()
                .assertThat();
    }

    protected static String walletResponseBody() {
        return "{\"response\":\"" + WALLET_JWE + "\"}";
    }

    protected static String dcApiRequestObject() {
        try {
            return new ObjectMapper()
                    .readTree(Path.of("src/test/resources/__files/mock_responses/eudi/session_dc_api_active_response.json").toFile())
                    .get("requestObject").asText();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    protected void assertDcApiResponseFailed(MockSessionFilter sessionFilter, ErrorCode errorCode, String expectedReason) {
        assertErrorIsLogged("User exception: " + expectedReason);
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(DC_API, null, errorCode));
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: AUTHENTICATION_FAILED",
                eudiStatisticsBuilder(DC_API).authenticationState(AUTHENTICATION_FAILED).errorCode(errorCode).build());
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    protected ValidatableResponse callback(MockSessionFilter sessionFilter, String responseCode) {
        var request = given().filter(sessionFilter);
        if (responseCode != null) {
            request.queryParam("response_code", responseCode);
        }
        return request
                .when()
                .get("/auth/eudi/callback")
                .then()
                .assertThat();
    }

    protected MockSessionFilter completeWeb2AppAuthentication() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);
        callback(sessionFilter, RESPONSE_CODE).statusCode(200);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, getTaraSession(sessionFilter).getState());
        return sessionFilter;
    }

    protected ValidatableResponse web2AppPoll(MockSessionFilter sessionFilter) {
        return web2AppPoll(sessionFilter.getSession().getId());
    }

    protected ValidatableResponse web2AppPoll(String sessionId) {
        wireMockServer.resetRequests();
        resetMockLogAppender();
        var request = given().accept("application/json");
        if (sessionId != null) {
            request.sessionId(sessionId);
        }
        return request
                .when()
                .get("/auth/eudi/web2app/poll")
                .then()
                .assertThat();
    }

    protected void assertPollLeftSessionAlone(MockSessionFilter sessionFilter, TaraAuthenticationState expectedState) {
        assertNotNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session must not be invalidated");
        assertEquals(expectedState, getTaraSession(sessionFilter).getState());
        assertStatisticsIsNotLogged(loggedFor(sessionFilter));
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    /**
     * The poll read eudiplo once and changed nothing.
     */
    protected void assertPollKeptLoginWaiting(MockSessionFilter sessionFilter) {
        assertNotNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session must not be invalidated");
        assertEquals(WAITING_EUDI_CALLBACK, getTaraSession(sessionFilter).getState());
        assertStatisticsIsNotLogged(loggedFor(sessionFilter));
        wireMockServer.verify(1, getRequestedFor(urlPathEqualTo("/api/session/" + WEB2APP_PRESENTATION_SESSION_ID)));
    }

    protected void assertWeb2AppLoginFailed(MockSessionFilter sessionFilter, ErrorCode errorCode, String expectedReason) {
        assertErrorIsLogged("User exception: " + expectedReason);
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, errorCode));
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: AUTHENTICATION_FAILED",
                eudiStatisticsBuilder(WEB2APP).authenticationState(AUTHENTICATION_FAILED).errorCode(errorCode).build());
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    /**
     * Matched by the flow trace id of this test's session. The test clock is fixed, so the event duration is 0.
     */
    protected static SessionStatistics eudiStatistics(TaraSession.EudiFlow flow, String idCode, ErrorCode errorCode) {
        return eudiStatisticsBuilder(flow)
                .idCode(idCode)
                .authenticationState(EXTERNAL_TRANSACTION)
                .errorCode(errorCode)
                .eventDuration(0L)
                .build();
    }

    protected static SessionStatistics.SessionStatisticsBuilder eudiStatisticsBuilder(TaraSession.EudiFlow flow) {
        return defaultStatisticsMarkerBuilder()
                .clientId("openIdDemo")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .authenticationType(EUDI_WALLET)
                .eudiFlow(flow);
    }

    protected void assertCancelLogged(MockSessionFilter sessionFilter, TaraSession.EudiFlow flow) {
        TaraSession taraSession = getTaraSession(sessionFilter);
        assertEquals(AUTHENTICATION_CANCELED, taraSession.getState());
        assertNull(taraSession.getEudiSession());
        assertNull(taraSession.getAuthFlowEndTime());
        assertStatisticsIsLoggedOnce(INFO, loggedFor(sessionFilter), "Authentication result: AUTHENTICATION_CANCELED",
                eudiStatisticsBuilder(flow).authenticationState(AUTHENTICATION_CANCELED).build());
    }

    protected static void assertAuthFlowStarted(TaraSession taraSession) {
        assertNotNull(taraSession.getAuthFlowStartTime());
        assertNull(taraSession.getAuthFlowEndTime());
    }

    protected static Predicate<ILoggingEvent> loggedFor(MockSessionFilter sessionFilter) {
        String flowTraceId = DigestUtils.sha256Hex(sessionFilter.getSession().getId());
        return event -> flowTraceId.equals(event.getMDCPropertyMap().get(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID));
    }

    protected TaraSession getTaraSession(MockSessionFilter sessionFilter) {
        return sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
    }

    protected MockSessionFilter createDcApiMockSessionFilter() {
        return MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EUDI_WALLET))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS)
                .eudiPresentationConfigId(PRESENTATION_CONFIG_ID)
                .csrfMode(MockSessionFilter.CsrfMode.HEADER).build();
    }

    protected MockSessionFilter createMockSessionFilter() {
        return createMockSessionFilter(PRESENTATION_CONFIG_ID);
    }

    protected MockSessionFilter createMockSessionFilter(String presentationConfigId) {
        return MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EUDI_WALLET))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS)
                .eudiPresentationConfigId(presentationConfigId).build();
    }

    /**
     * The access token is cached by the context's EudiploClient, so a given test may not call the token endpoint.
     */
    protected void createTokenStub(int status) {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile("mock_responses/eudi/token_response.json")));
    }

    protected void createWeb2AppOfferStub() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(201)
                        .withBodyFile("mock_responses/eudi/offer_web2app_response.json")));
    }

    protected void createDcApiOfferStub() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(201)
                        .withBodyFile("mock_responses/eudi/offer_dc_api_response.json")));
    }

    protected void createWalletResponseStub(int status, String body) {
        wireMockServer.stubFor(post(urlPathMatching("/presentations/[^/]+/oid4vp"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBody(body)));
    }

    protected void createSessionStub(String bodyFile) {
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile(bodyFile)));
    }

    protected void createSessionStubWithoutPidClaim(String bodyFile, String claim) {
        String body;
        try {
            JsonNode session = new ObjectMapper().readTree(Path.of("src/test/resources/__files", bodyFile).toFile());
            ((ObjectNode) session.at("/credentials/0/values/0")).remove(claim);
            body = session.toString();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBody(body)));
    }

}
