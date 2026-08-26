package ee.ria.taraauthserver.authentication.eudi;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.error.ErrorAttributes;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.LocalDate;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EUDI_WALLET;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.config.properties.LevelOfAssurance.HIGH;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_CALLBACK;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.WEB2APP;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EudiWeb2AppControllerTest extends AbstractEudiControllerTest {

    @Test
    void eudiWeb2AppInit_sessionStateIncorrect_returnsBadRequest() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(EUDI_WALLET))
                        .authenticationState(WAITING_EUDI_CALLBACK).build())
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_CALLBACK', expected one of: [INIT_AUTH_PROCESS]");
        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo("/api/verifier/offer")));
    }

    @Test
    void eudiWeb2AppInit_eudiWalletNotAllowed_returnsBadRequest() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of())
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: EUDI wallet authentication method is not allowed");
        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo("/api/verifier/offer")));
    }

    @Test
    void eudiWeb2AppInit_clientWithoutPresentationConfig_returnsBadRequestAndCreatesNoOffer() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        MockSessionFilter sessionFilter = createMockSessionFilter(null);

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(400)
                // EUDI_CLIENT_NOT_REGISTERED is deliberately absent from ErrorAttributes.notReportableErrors: a client
                // without a presentation configuration is an operator error, not something the user did.
                .body("reportable", equalTo(true));

        assertErrorIsLogged("User exception: No eudi_settings.presentation_config_id in metadata of client \"openIdDemo\"");
        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo("/api/verifier/offer")));
    }

    @Test
    void eudiWeb2AppInit_offerCarriesRedirectUri_rendersWalletLink() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("id=\"eudiWeb2AppLink\""))
                .body(containsString("action=\"/auth/eudi/web2app/cancel\""))
                .body(containsString("href=\"openid4vp://?client_id=x509_hash%3AaGFzaC1vZi13cnBhYy1sZWFm&amp;request_uri=https%3A%2F%2Flocalhost%3A9877%2Fpresentations%2F1b2c3d4e-aaaa-4bbb-8ccc-ddddeeeeffff%2Foid4vp%2Frequest&amp;request_uri_method=get\""))
                // Never the no-redirect link of the same eudiplo session, which would deliver no response code.
                .body(not(containsString("no-redirect")))
                // eudi-web2app-poll.js shows its errors with eudi-error.js, so that one runs first.
                .body(stringContainsInOrder("/scripts/eudi-error.js", "/scripts/eudi-web2app-poll.js"))
                .body(not(containsString("/scripts/eudi-dc-api.js")));

        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/verifier/offer"))
                .withRequestBody(matchingJsonPath("$.response_type", WireMock.equalTo("uri")))
                .withRequestBody(matchingJsonPath("$.requestId", WireMock.equalTo(PRESENTATION_CONFIG_ID)))
                .withRequestBody(matchingJsonPath("$.redirectUri", WireMock.equalTo(EXPECTED_REDIRECT_URI))));

        TaraSession taraSession = getTaraSession(sessionFilter);
        assertEquals(WAITING_EUDI_CALLBACK, taraSession.getState());
        assertEquals(WEB2APP_PRESENTATION_SESSION_ID, taraSession.getEudiSession().getPresentationSessionId());
        assertEquals(WEB2APP, taraSession.getEudiFlowType());
        assertAuthFlowStarted(taraSession);
    }

    @Test
    void eudiWeb2AppInit_offerWithoutWalletLink_failsWithInternalError() {
        createTokenStub(200);
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(201)
                        .withBodyFile("mock_responses/eudi/offer_web2app_without_uri_response.json")));
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: eudiplo did not return a WEB2APP wallet link for presentation session "
                + WEB2APP_PRESENTATION_SESSION_ID);
    }

    @Test
    void eudiWeb2AppInit_eudiploUnavailable_returnsReportableInternalError() {
        createTokenStub(200);
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse().withStatus(503)));
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: eudiplo request POST https://localhost:9877/api/verifier/offer failed: 503");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiWeb2AppInit_tokenRequestFails_returnsReportableInternalError() {
        createTokenStub(500);
        // An access token cached by an earlier test is discarded on the 401, so the token is requested either way.
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse().withStatus(401)));
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: eudiplo request POST https://localhost:9877/api/oauth2/token failed: 500");
        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/oauth2/token")));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiCallback_validResponseCode_authenticationSucceedsAndContinuesToAccept() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(200)
                .header("Referrer-Policy", "no-referrer")
                .body(containsString("<form id=\"authenticationRedirectForm\" method=\"post\" action=\"/auth/accept\">"))
                .body(containsString("name=\"_csrf\""))
                .body(containsString("/scripts/form-redirect.js"));

        TaraSession taraSession = getTaraSession(sessionFilter);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        TaraSession.EudiAuthenticationResult result =
                (TaraSession.EudiAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("47101010033", result.getIdCode());
        assertEquals("Mari-Liis", result.getFirstName());
        assertEquals("Männik", result.getLastName());
        assertEquals(LocalDate.of(1971, 1, 1), result.getDateOfBirth());
        assertEquals("EE47101010033", result.getSubject());
        assertEquals(EUDI_WALLET, result.getAmr());
        assertEquals(HIGH, result.getAcr());

        wireMockServer.verify(1, getRequestedFor(urlPathEqualTo("/api/session/" + WEB2APP_PRESENTATION_SESSION_ID)));
        assertInfoIsLogged("EUDI wallet WEB2APP presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                + " verified");
        assertStatisticsIsLoggedOnce(INFO, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, "47101010033", null));
        assertNothingIsLoggedContaining(RESPONSE_CODE);
    }

    @Test
    void eudiCallback_walletPresentsForeignPid_subjectCarriesIssuingCountry() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_foreign_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE).statusCode(200);

        TaraSession taraSession = getTaraSession(sessionFilter);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        TaraSession.EudiAuthenticationResult result =
                (TaraSession.EudiAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("010171-10000", result.getIdCode());
        assertEquals("LV", result.getCountry());
        assertEquals("LV010171-10000", result.getSubject());
    }

    @Test
    void eudiCallback_moreThanOneCredentialSetPresented_returnsInternalError() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_multiple_credentials_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(502)
                .body("reportable", equalTo(true));

        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, ErrorCode.EUDI_INTERNAL_ERROR));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @ParameterizedTest
    @ValueSource(strings = {"personal_administrative_number", "issuing_country", "given_name", "family_name", "birth_date"})
    void eudiCallback_mandatoryPidClaimMissing_returnsInternalError(String claim) {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStubWithoutPidClaim("mock_responses/eudi/session_web2app_completed_response.json", claim);
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: Presented PID is missing mandatory claim \"" + claim + "\"");
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, ErrorCode.EUDI_INTERNAL_ERROR));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiCallback_presentationVerificationFailed_returnsPresentationRejected() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_failed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, null)
                .statusCode(400)
                .body("message", equalTo("Teie isikuandmete tõendit ei õnnestunud kontrollida. Palun proovige uuesti või valige mõni teine autentimisviis."))
                .body("reportable", equalTo(false));

        assertTrue(ErrorAttributes.notReportableErrors.contains(ErrorCode.EUDI_PRESENTATION_REJECTED),
                "A rejected presentation must not be reported as an incident");
        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_PRESENTATION_REJECTED,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                        + " ended in status failed, failure code signature_invalid: Presentation signature is invalid");
    }

    @Test
    void eudiCallback_eudiploTrustListUnavailable_returnsReportableInternalError() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_failed_trust_list_unavailable_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, null)
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        String reason = "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                + " ended in status failed, failure code trust_list_unavailable: The trusted list could not be loaded, so the credential could not be validated.";
        assertErrorIsLogged("Service not available: " + reason);
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, ErrorCode.EUDI_INTERNAL_ERROR));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiCallback_replayedAfterSuccess_returnsBadRequest() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);
        callback(sessionFilter, RESPONSE_CODE).statusCode(200);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."));

        assertErrorIsLogged("User exception: Invalid authentication state: 'NATURAL_PERSON_AUTHENTICATION_COMPLETED', "
                + "expected one of: [WAITING_EUDI_CALLBACK]");
        wireMockServer.verify(1, getRequestedFor(urlPathEqualTo("/api/session/" + WEB2APP_PRESENTATION_SESSION_ID)));
    }

    @Test
    void eudiCallback_responseCodeMismatch_authenticationFails() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, "3c2b1a09-5555-4666-8777-888899990001")
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "EUDI wallet callback response code does not match eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID);
        assertNothingIsLoggedContaining(RESPONSE_CODE);
    }

    @Test
    void eudiCallback_responseCodeMissing_authenticationFails() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, null)
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "EUDI wallet callback response code does not match eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID);
    }

    @Test
    void eudiCallback_noTaraSession_returnsSessionNotFound() {
        given()
                .when()
                .queryParam("response_code", RESPONSE_CODE)
                .get("/auth/eudi/callback")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", startsWith("Käesolev leht on avanenud teises veebibrauseris"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Session not found on EUDI wallet callback");
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
    }

    @Test
    void eudiCallback_taraSessionNotWaitingForCallback_returnsBadRequest() {
        MockSessionFilter sessionFilter = createMockSessionFilter();

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', "
                + "expected one of: [WAITING_EUDI_CALLBACK]");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
    }

    @Test
    void eudiCallback_eudiWalletNotAllowed_returnsBadRequest() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of())
                .authenticationState(WAITING_EUDI_CALLBACK).build();

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: EUDI wallet authentication method is not allowed");
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
    }

    @Test
    void eudiCallback_activePresentationPastExpiry_failsWithTimeout() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_active_past_expiry_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo("Te ei esitanud tõendit ettenähtud aja jooksul. Palun proovige uuesti."));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_TIMEOUT,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                        + " expired at 2024-12-31T23:59Z in status active");
    }

    @Test
    void eudiCallback_eudiploSessionNotCompleted_authenticationFails() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "EUDI wallet callback arrived, but eudiplo presentation session "
                        + WEB2APP_PRESENTATION_SESSION_ID + " is in status active");
    }

    @Test
    void eudiCallback_userDeclinedInWallet_returnsUserCancel() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_failed_access_denied_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, null)
                .statusCode(400)
                .body("message", equalTo("Katkestasite autentimise digikukru rakenduses."))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_USER_CANCEL,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                        + " ended in status failed, failure code access_denied: Wallet error: access_denied");
    }

    @Test
    void eudiCallback_eudiploUnavailable_returnsReportableInternalError() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse().withStatus(500)));
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE)
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, ErrorCode.EUDI_INTERNAL_ERROR));
    }

    @Test
    void eudiCancel_web2App_redirectsToAuthInit() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/cancel")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("/auth/init?login_challenge=abcdefg098AAdsCC"));

        assertCancelLogged(sessionFilter, WEB2APP);
    }

    @Test
    void eudiCancel_web2App_dcApiLogin_returnsBadRequest() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/web2app/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_DC_API_RESPONSE', expected one of: [WAITING_EUDI_CALLBACK]");
    }

    @Test
    void eudiWeb2AppPoll_waitingForCallback_returnsPending() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_active_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("PENDING"));

        assertPollKeptLoginWaiting(sessionFilter);
        // The read of a poll that repeats about once a second is not logged.
        assertNothingIsLoggedContaining("/api/session/");
    }

    @Test
    void eudiWeb2AppPoll_afterSuccessfulCallback_returnsCompleted() {
        MockSessionFilter sessionFilter = completeWeb2AppAuthentication();

        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        assertPollLeftSessionAlone(sessionFilter, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

    /**
     * The tab the wallet opened moves the shared session on after the callback; the poll must not fail the login there.
     */
    @ParameterizedTest
    @EnumSource(value = TaraAuthenticationState.class, names = {
            "NATURAL_PERSON_AUTHENTICATION_COMPLETED",
            "LEGAL_PERSON_AUTHENTICATION_INIT",
            "GET_LEGAL_PERSON_LIST",
            "LEGAL_PERSON_AUTHENTICATION_COMPLETED",
            "AUTHENTICATION_SUCCESS",
            "INIT_CONSENT_PROCESS",
            "CONSENT_NOT_REQUIRED"})
    void eudiWeb2AppPoll_loginContinuedAfterCallback_returnsCompletedAndLeavesTheSessionAlone(
            TaraAuthenticationState state) {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(EUDI_WALLET))
                .authenticationState(state).build();

        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        assertPollLeftSessionAlone(sessionFilter, state);
    }

    @Test
    void eudiWeb2AppPoll_noSession_returnsEnded() {
        web2AppPoll((String) null)
                .statusCode(200)
                .body("status", equalTo("ENDED"));

        assertStatisticsIsNotLogged();
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void eudiWeb2AppPoll_otherMethodLogin_returnsBadRequest() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.POLL_SID_QR_CODE).build();

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'POLL_SID_QR_CODE', expected one of: [");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void eudiWeb2AppPoll_dcApiLogin_returnsBadRequest() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_DC_API_RESPONSE', expected one of: [");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void eudiWeb2AppPoll_eudiWalletNotAllowed_returnsBadRequest() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of())
                .authenticationState(WAITING_EUDI_CALLBACK).build();

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: EUDI wallet authentication method is not allowed");
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void eudiWeb2AppPoll_presentationFetched_returnsPending() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_fetched_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        // The wallet has fetched the request object but not answered yet.
        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("PENDING"));

        assertPollKeptLoginWaiting(sessionFilter);
    }

    @Test
    void eudiWeb2AppPoll_presentationCompleted_returnsPendingAndLeavesLoginToCallback() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_completed_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("PENDING"));
        assertPollKeptLoginWaiting(sessionFilter);

        callback(sessionFilter, RESPONSE_CODE).statusCode(200);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, getTaraSession(sessionFilter).getState());
    }

    @Test
    void eudiWeb2AppPoll_eudiploUnavailable_returnsPendingAndKeepsLoginWaiting() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse().withStatus(503)));
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("PENDING"));

        assertNotNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session must not be invalidated");
        assertEquals(WAITING_EUDI_CALLBACK, getTaraSession(sessionFilter).getState());
        assertStatisticsIsNotLogged(loggedFor(sessionFilter));
        assertWarningIsLogged("EUDI wallet presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                + " status poll failed");
    }

    @Test
    void eudiWeb2AppPoll_userDeclinedInWallet_failsLoginWithUserCancel() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_failed_access_denied_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Katkestasite autentimise digikukru rakenduses."))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_USER_CANCEL,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                        + " ended in status failed, failure code access_denied: Wallet error: access_denied");

        // The login is gone, so a later poll neither reads eudiplo nor reports the failure again.
        web2AppPoll(sessionFilter)
                .statusCode(200)
                .body("status", equalTo("ENDED"));
        assertStatisticsIsNotLogged();
        wireMockServer.verify(0, anyRequestedFor(anyUrl()));
    }

    @Test
    void eudiWeb2AppPoll_presentationExpired_failsLoginWithTimeout() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_expired_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Te ei esitanud tõendit ettenähtud aja jooksul. Palun proovige uuesti."))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_TIMEOUT,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID + " ended in status expired");
    }

    @Test
    void eudiWeb2AppPoll_activePresentationPastExpiry_failsLoginWithTimeout() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_active_past_expiry_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(400)
                .body("message", equalTo("Te ei esitanud tõendit ettenähtud aja jooksul. Palun proovige uuesti."))
                .body("reportable", equalTo(false));

        assertWeb2AppLoginFailed(sessionFilter, ErrorCode.EUDI_TIMEOUT,
                "eudiplo presentation session " + WEB2APP_PRESENTATION_SESSION_ID
                        + " expired at 2024-12-31T23:59Z in status active");
    }

    @Test
    void eudiWeb2AppPoll_presentationCancelled_failsLoginWithReportableInternalError() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        createSessionStub("mock_responses/eudi/session_web2app_cancelled_response.json");
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        web2AppPoll(sessionFilter)
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        // TARA never cancels a presentation session, so an operator did: a technical error, logged as such.
        assertErrorIsLogged("Service not available: eudiplo presentation session "
                + WEB2APP_PRESENTATION_SESSION_ID + " ended in status cancelled");
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(WEB2APP, null, ErrorCode.EUDI_INTERNAL_ERROR));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

}
