package ee.ria.taraauthserver.authentication.eudi;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.EudiploSession.StatusEnum;
import ee.ria.taraauthserver.authentication.eudi.eudiplo.model.OfferResponse;
import ee.ria.taraauthserver.config.properties.EudiConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.RestTemplateErrorLogger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A fresh EudiploClient per test, so that the token cache does not carry over between tests.
 */
@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"}) // Disabled to avoid EIDAS /supportedCountries API call
class EudiploClientTest extends BaseTest {

    private static final String PRESENTATION_SESSION_ID = "9d1b1e9c-c3d4-4e5f-8899-aabbccddeeff";
    private static final String WALLET_NONCE = "c4d5e6f7-1111-4abc-9def-0123456789ab";
    private static final String CLIENT_SECRET = "test-eudiplo-client-secret";
    private static final String ACCESS_TOKEN =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dGVzdC1hY2Nlc3MtdG9rZW4.c2lnbmF0dXJl";

    @Autowired
    @Qualifier("eudiploRestClient")
    private RestClient eudiploRestClient;

    @Autowired
    private EudiConfigurationProperties eudiConfigurationProperties;

    @Test
    void getPresentationSession_calledTwice_acquiresAccessTokenOnce() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        client.getPresentationSession(PRESENTATION_SESSION_ID);
        client.getPresentationSession(PRESENTATION_SESSION_ID);

        wireMockServer.verify(1, postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
        wireMockServer.verify(2, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
    }

    @Test
    void getPresentationSession_postsClientCredentialsInFormBodyAndSendsAccessToken() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        client.getPresentationSession(PRESENTATION_SESSION_ID);

        // The client secret must travel in the form body, never in the URL.
        wireMockServer.verify(postRequestedFor(urlEqualTo("/api/oauth2/token"))
                .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                .withRequestBody(containing("grant_type=client_credentials"))
                .withRequestBody(containing("client_secret=" + CLIENT_SECRET)));
        wireMockServer.verify(getRequestedFor(urlEqualTo("/api/session/" + PRESENTATION_SESSION_ID))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN))
                .withHeader("Accept", WireMock.equalTo("application/json")));
    }

    @Test
    void getPresentationSession_cachedTokenIsAboutToExpire_acquiresNewTokenBeforeExpiry() {
        // expires_in is 60 seconds, so the refresh is scheduled halfway through rather than at the 5 minute margin.
        createTokenStub("mock_responses/eudi/token_response_short_lived.json");
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        MutableClock clock = new MutableClock(Instant.parse("2026-08-25T12:00:00Z"));
        EudiploClient client = createClient(clock);

        client.getPresentationSession(PRESENTATION_SESSION_ID);
        clock.advance(Duration.ofSeconds(31));
        client.getPresentationSession(PRESENTATION_SESSION_ID);

        wireMockServer.verify(2, postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
    }

    @Test
    void getPresentationSession_cachedTokenRejected_acquiresNewTokenAndRetries() {
        createTokenStub("mock_responses/eudi/token_response.json");
        // A restarted eudiplo rejects a token that has not expired yet, so the first call must be retried once.
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .inScenario("rejected access token")
                .whenScenarioStateIs(STARTED)
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(401)
                        .withBody("{\"statusCode\":401,\"message\":\"Unauthorized\"}"))
                .willSetStateTo("access token reacquired"));
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .inScenario("rejected access token")
                .whenScenarioStateIs("access token reacquired")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile("mock_responses/eudi/session_web2app_active_response.json")));
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        assertEquals(StatusEnum.ACTIVE, client.getPresentationSession(PRESENTATION_SESSION_ID).getStatus());

        wireMockServer.verify(2, postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
        wireMockServer.verify(2, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
    }

    @Test
    void getPresentationSession_accessTokenRejectedTwice_failsWithInternalError() {
        createTokenStub("mock_responses/eudi/token_response.json");
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse().withStatus(401)));
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        ServiceNotAvailableException exception = assertThrows(ServiceNotAvailableException.class,
                () -> client.getPresentationSession(PRESENTATION_SESSION_ID));

        assertEquals(ErrorCode.EUDI_INTERNAL_ERROR, exception.getErrorCode());
        wireMockServer.verify(2, postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
    }

    @Test
    void getPresentationSession_clientCredentialsRejected_failsWithTheEudiploErrorResponse() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(401)
                        .withBody("{\"error\":\"invalid_client\",\"error_description\":\"Invalid client credentials\"}")));
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        ServiceNotAvailableException exception = assertThrows(ServiceNotAvailableException.class,
                () -> client.getPresentationSession(PRESENTATION_SESSION_ID));

        assertEquals(ErrorCode.EUDI_INTERNAL_ERROR, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Invalid client credentials"),
                "The eudiplo error response tells a wrong secret apart from a missing tenant: "
                        + exception.getMessage());
        assertInfoIsLogged(EudiploClient.class, "EUDIPLO response: 401");
        assertFalse(exception.getMessage().contains(CLIENT_SECRET),
                "The client secret must not reach an exception message");
    }

    @Test
    void createPresentationOffer_sendsRedirectUri() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createOfferStub("mock_responses/eudi/offer_web2app_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));
        String redirectUri = "https://example.com/auth/eudi/callback";

        OfferResponse offer = client.createPresentationOffer("pid-openIdDemo", redirectUri);

        assertFalse(offer.getUri().contains("no-redirect"));
        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/verifier/offer"))
                .withRequestBody(matchingJsonPath("$.response_type", WireMock.equalTo("uri")))
                .withRequestBody(matchingJsonPath("$.requestId", WireMock.equalTo("pid-openIdDemo")))
                .withRequestBody(matchingJsonPath("$.redirectUri", WireMock.equalTo(redirectUri))));
    }

    @Test
    void createDcApiPresentationOffer_sendsExpectedOriginWithoutRedirectUri() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createOfferStub("mock_responses/eudi/offer_dc_api_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        OfferResponse offer = client.createDcApiPresentationOffer("pid-openIdDemo", "https://example.com");

        assertEquals("2e4b6d8f-0a1c-4e3d-8f5a-6b7c8d9e0f1a", offer.getSession());
        // eudiplo's offer schema is strict: an absent field must be left out rather than sent as an explicit null.
        // The generated model's defaults (clientIdScheme, an empty transaction_data) are not sent either.
        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/verifier/offer"))
                .withHeader("Accept", WireMock.equalTo("application/json"))
                .withRequestBody(WireMock.equalToJson("""
                        {"response_type": "dc-api", "requestId": "pid-openIdDemo", "expected_origin": "https://example.com"}
                        """)));
    }

    @Test
    void getPresentationSession_dcApiSession_readsRequestObject() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        EudiploSession session = client.getPresentationSession("2e4b6d8f-0a1c-4e3d-8f5a-6b7c8d9e0f1a");

        assertTrue(session.getRequestObject().startsWith("eyJ"));
    }

    @Test
    void submitWalletResponse_eudiploAccepts_postsUnauthenticatedAndReturnsTrue() {
        createWalletResponseStub(200);
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        assertTrue(client.submitWalletResponse(new WalletResponse("a.b.c.d.e", null), WALLET_NONCE));

        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/presentations/" + WALLET_NONCE + "/oid4vp"))
                .withoutHeader("Authorization")
                .withRequestBody(WireMock.equalToJson("{\"response\":\"a.b.c.d.e\"}")));
        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
    }

    @Test
    void submitWalletResponse_eudiploRejects_returnsFalseAndLogsResponseAtInfo() {
        createWalletResponseStub(400);
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        assertFalse(client.submitWalletResponse(new WalletResponse("a.b.c.d.e", null), WALLET_NONCE));

        assertInfoIsLogged(EudiploClient.class, "EUDIPLO response: 400");
        assertMessageIsNotLogged(RestTemplateErrorLogger.class, "EUDIPLO response: 400");
    }

    @Test
    void submitWalletResponse_eudiploFails_throwsInternalError() {
        createWalletResponseStub(500);
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        ServiceNotAvailableException exception = assertThrows(ServiceNotAvailableException.class,
                () -> client.submitWalletResponse(new WalletResponse("a.b.c.d.e", null), WALLET_NONCE));

        assertEquals(ErrorCode.EUDI_INTERNAL_ERROR, exception.getErrorCode());
        assertFalse(exception.getMessage().contains("a.b.c.d.e"), "The wallet response must not reach an exception message");
    }

    @Test
    void pollPresentationSession_readsStatusWithoutLoggingTheRequestOrResponse() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        EudiploSession session = client.pollPresentationSession(PRESENTATION_SESSION_ID);

        assertEquals(StatusEnum.ACTIVE, session.getStatus());
        assertNothingIsLoggedContaining("/api/session/");
    }

    @Test
    void pollPresentationSession_eudiploFails_throwsInternalErrorWithoutLoggingTheResponse() {
        createTokenStub("mock_responses/eudi/token_response.json");
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse().withStatus(503)));
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        ServiceNotAvailableException exception = assertThrows(ServiceNotAvailableException.class,
                () -> client.pollPresentationSession(PRESENTATION_SESSION_ID));

        assertEquals(ErrorCode.EUDI_INTERNAL_ERROR, exception.getErrorCode());
        assertMessageIsNotLogged(EudiploClient.class, "EUDIPLO response: 503");
    }

    @Test
    void getPresentationSession_completedWeb2AppSession_readsResponseCodeAndClaims() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        EudiploSession session = client.getPresentationSession("5f0a7c2e-1d2e-4f3a-9b8c-7d6e5f4a3b2c");

        assertEquals(StatusEnum.COMPLETED, session.getStatus());
        assertEquals("3c2b1a09-5555-4666-8777-888899990000", session.getResponseCode());
        assertNull(session.getFailureCode());
        assertEquals("47101010033",
                session.getCredentials().get(0).path("values").path(0).path("personal_administrative_number").asString());
    }

    @Test
    void getPresentationSession_walletDeclined_readsFailureCode() {
        createTokenStub("mock_responses/eudi/token_response.json");
        createSessionStub("mock_responses/eudi/session_web2app_failed_access_denied_response.json");
        EudiploClient client = createClient(new MutableClock(Instant.parse("2026-08-25T12:00:00Z")));

        EudiploSession session = client.getPresentationSession(PRESENTATION_SESSION_ID);

        assertEquals(StatusEnum.FAILED, session.getStatus());
        assertEquals("access_denied", session.getFailureCode());
        assertNull(session.getResponseCode());
    }

    private EudiploClient createClient(Clock clock) {
        return new EudiploClient(eudiploRestClient, eudiConfigurationProperties, clock);
    }

    private void createTokenStub(String bodyFile) {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile(bodyFile)));
    }

    private void createOfferStub(String bodyFile) {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(201)
                        .withBodyFile(bodyFile)));
    }

    private void createWalletResponseStub(int status) {
        wireMockServer.stubFor(post(urlPathMatching("/presentations/[^/]+/oid4vp"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBody("{}")));
    }

    private void createSessionStub(String bodyFile) {
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile(bodyFile)));
    }

    private static class MutableClock extends Clock {

        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

}
