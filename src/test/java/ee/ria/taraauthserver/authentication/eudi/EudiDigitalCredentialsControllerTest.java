package ee.ria.taraauthserver.authentication.eudi;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.notContaining;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EUDI_WALLET;
import static ee.ria.taraauthserver.config.properties.LevelOfAssurance.HIGH;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;
import static ee.ria.taraauthserver.session.TaraSession.EudiFlow.DC_API;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EudiDigitalCredentialsControllerTest extends AbstractEudiControllerTest {

    @Test
    void eudiDcApiInit_offerBoundToOrigin_rendersRequestObjectAndNeverPolls() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("id=\"eudiDcApi\""))
                .body(containsString("data-request=\"" + dcApiRequestObject() + "\""))
                .body(containsString("id=\"eudiDcApiButton\""))
                .body(containsString("action=\"/auth/eudi/dc-api/cancel\""))
                // eudi-dc-api.js shows its errors with eudi-error.js, so that one runs first.
                .body(stringContainsInOrder("/scripts/eudi-error.js", "/scripts/eudi-dc-api.js"))
                .body(not(containsString("/scripts/eudi-web2app-poll.js")))
                // Neither wallet link of the offer: they would let a wallet answer eudiplo past this browser.
                .body(not(containsString("openid4vp://")))
                .body(not(containsString("eudiWeb2AppLink")));

        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/verifier/offer"))
                .withRequestBody(matchingJsonPath("$.response_type", WireMock.equalTo("dc-api")))
                .withRequestBody(matchingJsonPath("$.requestId", WireMock.equalTo(PRESENTATION_CONFIG_ID)))
                .withRequestBody(matchingJsonPath("$.expected_origin", WireMock.equalTo("https://example.com")))
                .withRequestBody(notContaining("redirectUri")));

        TaraSession taraSession = getTaraSession(sessionFilter);
        assertEquals(WAITING_EUDI_DC_API_RESPONSE, taraSession.getState());
        assertEquals(DC_API_PRESENTATION_SESSION_ID, taraSession.getEudiSession().getPresentationSessionId());
        assertEquals(DC_API_WALLET_NONCE, taraSession.getEudiSession().getWalletNonce());
        assertEquals(DC_API, taraSession.getEudiFlowType());
        assertAuthFlowStarted(taraSession);

        // Read once, for the request object.
        wireMockServer.verify(1, getRequestedFor(urlPathEqualTo("/api/session/" + DC_API_PRESENTATION_SESSION_ID)));
    }

    @Test
    void eudiDcApiInit_eudiWalletNotAllowed_returnsBadRequest() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of())
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."));

        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo("/api/verifier/offer")));
    }

    @Test
    void eudiDcApiInit_eudiploRejectsOffer_returnsReportableInternalError() {
        createTokenStub(200);
        // TARA built the request, so a 4xx is no fault of the user's either.
        wireMockServer.stubFor(post(urlPathEqualTo("/api/verifier/offer"))
                .willReturn(aResponse().withStatus(400)));
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: eudiplo request POST https://localhost:9877/api/verifier/offer failed: 400");
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/api/session/[^/]+")));
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiDcApiInit_eudiploUnavailable_returnsReportableInternalError() {
        createTokenStub(200);
        createDcApiOfferStub();
        wireMockServer.stubFor(get(urlPathMatching("/api/session/[^/]+"))
                .willReturn(aResponse().withStatus(503)));
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: eudiplo request GET https://localhost:9877/api/session/"
                + DC_API_PRESENTATION_SESSION_ID + " failed: 503");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiDcApiInit_sessionWithoutRequestObject_failsWithInternalError() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_without_request_object_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertErrorIsLogged("Service not available: eudiplo presentation session " + DC_API_PRESENTATION_SESSION_ID
                + " has no request object or wallet nonce");
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
    }

    @Test
    void eudiDcApiResponse_walletPresentsPid_authenticationSucceeds() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        // The page posts the credential's data unchanged; anything but the wallet's answer stays with TARA.
        dcApiResponse(sessionFilter, "{\"response\":\"" + WALLET_JWE + "\",\"sendResponse\":true}")
                .statusCode(204);

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

        wireMockServer.verify(postRequestedFor(urlPathEqualTo(DC_API_WALLET_RESPONSE_PATH))
                .withoutHeader("Authorization")
                .withRequestBody(matchingJsonPath("$.response", WireMock.equalTo(WALLET_JWE)))
                .withRequestBody(notContaining("sendResponse")));
        assertInfoIsLogged("EUDI wallet DC_API presentation session " + DC_API_PRESENTATION_SESSION_ID
                + " verified");
        assertStatisticsIsLoggedOnce(INFO, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(DC_API, "47101010033", null));
        assertNothingIsLoggedContaining(WALLET_JWE);
    }

    @Test
    void eudiDcApiResponse_replayedAfterSuccess_isRejected() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);
        dcApiResponse(sessionFilter, walletResponseBody()).statusCode(204);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."));

        assertErrorIsLogged("User exception: Invalid authentication state: 'NATURAL_PERSON_AUTHENTICATION_COMPLETED', expected one of: [WAITING_EUDI_DC_API_RESPONSE]");
        wireMockServer.verify(1, postRequestedFor(urlPathEqualTo(DC_API_WALLET_RESPONSE_PATH)));
    }

    @Test
    void eudiDcApiResponse_sessionCompletedThroughAnotherChannel_authenticationFails() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        createWalletResponseStub(400, "{\"message\":\"The presentation offer has already been used\"}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE))
                .body("reportable", equalTo(false));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "eudiplo presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " was completed by a response that this browser did not submit");
    }

    @Test
    void eudiDcApiResponse_presentationVerificationFailed_returnsPresentationRejected() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_failed_response.json");
        createWalletResponseStub(400, "{\"error\":\"invalid_request\"}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo("Teie isikuandmete tõendit ei õnnestunud kontrollida. Palun proovige uuesti või valige mõni teine autentimisviis."))
                .body("reportable", equalTo(false));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_PRESENTATION_REJECTED,
                "eudiplo presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " ended in status failed, failure code signature_invalid: Presentation signature is invalid");
    }

    @Test
    void eudiDcApiResponse_walletReportsAccessDenied_returnsUserCancel() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_failed_access_denied_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, "{\"error\":\"access_denied\",\"error_description\":\"User declined\"}")
                .statusCode(400)
                .body("message", equalTo("Katkestasite autentimise digikukru rakenduses."));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_USER_CANCEL,
                "eudiplo presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " ended in status failed, failure code access_denied: Wallet error: access_denied");
        wireMockServer.verify(postRequestedFor(urlPathEqualTo(DC_API_WALLET_RESPONSE_PATH))
                .withRequestBody(matchingJsonPath("$.error", WireMock.equalTo("access_denied")))
                .withRequestBody(notContaining("response\""))
                .withRequestBody(notContaining("User declined")));
    }

    @Test
    void eudiDcApiResponse_eudiploRejectsActivePresentationPastExpiry_failsWithTimeout() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_past_expiry_response.json");
        createWalletResponseStub(400, "{\"message\":\"The session has expired\"}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo("Te ei esitanud tõendit ettenähtud aja jooksul. Palun proovige uuesti."));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_TIMEOUT,
                "eudiplo presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " expired at 2024-12-31T23:59Z in status active");
    }

    @Test
    void eudiDcApiResponse_eudiploRejectsWithoutRecordingFailure_fails() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        createWalletResponseStub(400, "{\"message\":\"Missing response field in authorization response\"}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "eudiplo rejected the wallet response, but presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " is in status active");
    }

    @Test
    void eudiDcApiResponse_neitherResponseNorError_failsWithoutForwarding() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, "{\"vp_token\":{\"pid\":[\"o2d2ZXJzaW9u\"]}}")
                .statusCode(400)
                .body("message", equalTo(CALLBACK_INVALID_MESSAGE));

        assertDcApiResponseFailed(sessionFilter, ErrorCode.EUDI_CALLBACK_INVALID,
                "EUDI wallet response for presentation session " + DC_API_PRESENTATION_SESSION_ID
                        + " must carry exactly one of response and error");
        wireMockServer.verify(0, postRequestedFor(urlPathEqualTo(DC_API_WALLET_RESPONSE_PATH)));
    }

    @Test
    void eudiDcApiResponse_eudiploUnavailable_returnsReportableInternalError() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        createWalletResponseStub(500, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiResponse(sessionFilter, walletResponseBody())
                .statusCode(502)
                .body("message", equalTo(INTERNAL_ERROR_MESSAGE))
                .body("reportable", equalTo(true));

        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: EXTERNAL_TRANSACTION",
                eudiStatistics(DC_API, null, ErrorCode.EUDI_INTERNAL_ERROR));
        assertNothingIsLoggedContaining(WALLET_JWE);
    }

    @Test
    void eudiDcApiResponse_withoutCsrfToken_isRejectedWithoutForwarding() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        createWalletResponseStub(200, "{}");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        given()
                .sessionId(sessionFilter.getSession().getId())
                .contentType("application/json")
                .accept("application/json")
                .body(walletResponseBody())
                .when()
                .post("/auth/eudi/dc-api/response")
                .then()
                .assertThat()
                .statusCode(403);

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertEquals(WAITING_EUDI_DC_API_RESPONSE, getTaraSession(sessionFilter).getState());
        wireMockServer.verify(0, postRequestedFor(urlPathMatching("/presentations/.+")));
    }

    @Test
    void eudiDcApiError_browserReportsError_failsLoginWithDcApiError() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        dcApiError(sessionFilter, "{\"name\":\"NotSupportedError\",\"message\":\"No wallet answered\"}")
                .statusCode(400)
                .body("message", equalTo("Veebibrauseril ei õnnestunud digikukru rakenduselt vastust saada. Palun alustage sisselogimist uuesti või valige mõni teine autentimisviis."))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        assertMessageWithMarkerIsLoggedOnce(EudiDigitalCredentialsController.class, ERROR,
                "Client-side Digital Credentials API error: NotSupportedError",
                "tara.session.eudi.dc_api_error_message=No wallet answered");
        assertErrorIsLogged("User exception: Client-side Digital Credentials API error: NotSupportedError");
        assertStatisticsIsLoggedOnce(ERROR, loggedFor(sessionFilter), "Authentication result: AUTHENTICATION_FAILED",
                eudiStatisticsBuilder(DC_API)
                        .authenticationState(AUTHENTICATION_FAILED)
                        .errorCode(ErrorCode.EUDI_DC_API_ERROR)
                        .build());
        assertNull(sessionRepository.findById(sessionFilter.getSession().getId()), "Session should be invalidated");
        wireMockServer.verify(0, postRequestedFor(urlPathMatching("/presentations/.+")));
    }

    @Test
    void eudiDcApiError_sessionNotWaitingForDcApiResponse_returnsBadRequest() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        dcApiError(sessionFilter, "{\"name\":\"NotSupportedError\"}")
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_CALLBACK', expected one of: [WAITING_EUDI_DC_API_RESPONSE]");
        assertMessageIsNotLogged(EudiDigitalCredentialsController.class, "Client-side Digital Credentials API error: NotSupportedError");
    }

    @Test
    void eudiDcApiError_eudiWalletNotAllowed_returnsBadRequest() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of())
                .authenticationState(WAITING_EUDI_DC_API_RESPONSE)
                .csrfMode(MockSessionFilter.CsrfMode.HEADER).build();

        dcApiError(sessionFilter, "{\"name\":\"NotSupportedError\"}")
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: EUDI wallet authentication method is not allowed");
        assertMessageIsNotLogged(EudiDigitalCredentialsController.class, "Client-side Digital Credentials API error: NotSupportedError");
    }

    @Test
    void eudiDcApiError_withoutCsrfToken_isRejectedAndLoginKeepsWaiting() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        given()
                .sessionId(sessionFilter.getSession().getId())
                .contentType("application/json")
                .accept("application/json")
                .body("{\"name\":\"NotSupportedError\"}")
                .when()
                .post("/auth/eudi/dc-api/error")
                .then()
                .assertThat()
                .statusCode(403);

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertEquals(WAITING_EUDI_DC_API_RESPONSE, getTaraSession(sessionFilter).getState());
        assertMessageIsNotLogged(EudiDigitalCredentialsController.class, "Client-side Digital Credentials API error: NotSupportedError");
    }

    @Test
    void eudiFlows_cannotCompleteEachOthersTransaction() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_completed_response.json");
        MockSessionFilter dcApiSession = createDcApiMockSessionFilter();
        startDcApiAuthentication(dcApiSession);

        callback(dcApiSession, RESPONSE_CODE)
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."));
        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_DC_API_RESPONSE', "
                + "expected one of: [WAITING_EUDI_CALLBACK]");

        createWeb2AppOfferStub();
        MockSessionFilter web2AppSession = createDcApiMockSessionFilter();
        startWeb2AppAuthentication(web2AppSession);

        dcApiResponse(web2AppSession, walletResponseBody())
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."));
        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_CALLBACK', expected one of: [WAITING_EUDI_DC_API_RESPONSE]");
        wireMockServer.verify(0, postRequestedFor(urlPathMatching("/presentations/.+")));
    }

    @Test
    void eudiCancel_dcApi_redirectsToAuthInit() {
        createTokenStub(200);
        createDcApiOfferStub();
        createSessionStub("mock_responses/eudi/session_dc_api_active_response.json");
        MockSessionFilter sessionFilter = createDcApiMockSessionFilter();
        startDcApiAuthentication(sessionFilter);

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/cancel")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("/auth/init?login_challenge=abcdefg098AAdsCC"));

        assertCancelLogged(sessionFilter, DC_API);
    }

    @Test
    void eudiCancel_dcApi_web2AppLogin_returnsBadRequest() {
        createTokenStub(200);
        createWeb2AppOfferStub();
        MockSessionFilter sessionFilter = createMockSessionFilter();
        startWeb2AppAuthentication(sessionFilter);

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/eudi/dc-api/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'WAITING_EUDI_CALLBACK', expected one of: [WAITING_EUDI_DC_API_RESPONSE]");
    }

}
