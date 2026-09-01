package ee.ria.taraauthserver.authentication.smartid.web2app;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.FlowType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.UUID;

import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_SID_WEB2APP;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.when;
import static ee.ria.taraauthserver.error.ErrorCode.SID_COUNTRY_NOT_ALLOWED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.EXTERNAL_TRANSACTION;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"}) // Disabled to avoid EIDAS /supportedCountries API call
class SmartIdWeb2AppControllerTest extends BaseTest {

    // Base64URL-without-padding of SHA-256(Base64Decode("dGVzdC1zZWNyZXQ"))
    // where "dGVzdC1zZWNyZXQ" is the sessionSecret from sid_device_link_init_response.json
    private static final String SESSION_SECRET_DIGEST = "nK8Gu0Q2zb-iCvkSGmJrwQk8T1SzHA-pN5V4VhNTRbY";
    private static final String TEST_SESSION_TOKEN = "test-session-token";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @MockitoBean
    private DeviceLinkAuthenticationResponseValidator responseValidator;

    @Test
    void sidWeb2AppCallbackPoll_countryAllowed_authenticationSucceeds() {
        createDeviceLinkAuthInitStub();
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("EE");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .chosenLanguage("et")
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/web2app/init")
                .then()
                .assertThat()
                .statusCode(200);
        TaraSession taraSessionAfterPoll = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED)));
        String urlToken = taraSessionAfterPoll.getSmartIdWeb2AppSession().getUrlToken();
        given()
                .filter(sessionFilter)
                .queryParam("value", urlToken)
                .queryParam("sessionSecretDigest", SESSION_SECRET_DIGEST)
                .queryParam("userChallengeVerifier", "test-verifier")
                .when()
                .get("/auth/sid/web2app/callback/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        TaraSession.SidAuthenticationResult result = (TaraSession.SidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("EE", result.getCountry());
        assertEquals("38001085718", result.getIdCode());
        assertEquals("Jaak-Kristjan", result.getFirstName());
        assertEquals("Jõeorg", result.getLastName());
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                .clientId("openIdDemo")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .authenticationType(SMART_ID)
                .authenticationState(EXTERNAL_TRANSACTION)
                .smartIdFlowType(FlowType.WEB2APP)
                .eventDuration(0L)
                .build());
    }

    @Test
    void sidWeb2AppCallbackPoll_countryNotAllowed_authenticationFails() {
        createDeviceLinkAuthInitStub();
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("LV");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .chosenLanguage("et")
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/web2app/init")
                .then()
                .assertThat()
                .statusCode(200);
        TaraSession taraSessionAfterPoll = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED)));
        String urlToken = taraSessionAfterPoll.getSmartIdWeb2AppSession().getUrlToken();
        given()
                .filter(sessionFilter)
                .queryParam("value", urlToken)
                .queryParam("sessionSecretDigest", SESSION_SECRET_DIGEST)
                .queryParam("userChallengeVerifier", "test-verifier")
                .when()
                .get("/auth/sid/web2app/callback/poll")
                .then()
                .assertThat()
                .statusCode(400);

        assertWarningIsLogged("Smart-ID authentication failed: Smart-ID authentication is not allowed for country: LV, Error code: SID_COUNTRY_NOT_ALLOWED");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                .clientId("openIdDemo")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .authenticationType(SMART_ID)
                .authenticationState(AUTHENTICATION_FAILED)
                .errorCode(SID_COUNTRY_NOT_ALLOWED)
                .smartIdFlowType(FlowType.WEB2APP)
                .build());
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                .clientId("openIdDemo")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .authenticationType(SMART_ID)
                .authenticationState(EXTERNAL_TRANSACTION)
                .smartIdFlowType(FlowType.WEB2APP)
                .eventDuration(0L)
                .build());
    }

    @Test
    void sidWeb2AppPoll_sessionMissing_returns400() {
        given()
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    void sidWeb2AppPoll_sessionInIncorrectState_returns400() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS'");
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"INIT_SID_WEB2APP", "POLL_SID_WEB2APP_STATUS"},
            mode = EnumSource.Mode.INCLUDE)
    void sidWeb2AppPoll_returnsPending(TaraAuthenticationState state) {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(state).build();
        addWeb2AppSession(sessionFilter, TEST_SESSION_TOKEN);

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("PENDING"));

        assertStatisticsIsNotLogged();
    }

    @Test
    void sidWeb2AppPoll_returnsPinEntered_whenStateIsAfterFinalStatusReceived() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED).build();
        addWeb2AppSession(sessionFilter, TEST_SESSION_TOKEN);

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("AWAITING_CALLBACK"));

        assertStatisticsIsNotLogged();
    }

    @Test
    void sidWeb2AppPoll_returnsCompleted_whenStateIsNaturalPersonAuthenticationCompleted() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(NATURAL_PERSON_AUTHENTICATION_COMPLETED).build())
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        assertStatisticsIsNotLogged();
    }

    @Test
    void sidWeb2AppPoll_returnsCompleted_whenStateIsAuthenticationSuccess() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(AUTHENTICATION_SUCCESS).build();
        resetMockLogAppender();

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        assertStatisticsIsNotLogged();
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"INIT_CONSENT_PROCESS", "CONSENT_NOT_REQUIRED"},
            mode = EnumSource.Mode.INCLUDE)
    void sidWeb2AppPoll_returnsCompleted_whenStateIsPostAuthConsentState(TaraAuthenticationState state) {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(state).build())
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        assertStatisticsIsNotLogged();
    }

    @Test
    void sidWeb2AppPoll_authenticationFailed_returns400() {
        TaraSession.AuthenticationResult authenticationResult = new TaraSession.AuthenticationResult();
        authenticationResult.setErrorCode(ErrorCode.SID_USER_REFUSED);

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(AUTHENTICATION_FAILED)
                        .authenticationResult(authenticationResult).build())
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Kasutaja katkestas autentimise<span translate=\"no\" lang=\"en\"> Smart-ID </span>rakenduses."))
                .body("reportable", equalTo(false));
    }

    @Test
    void sidWeb2AppPoll_sessionTokenMismatch_returns400() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_WEB2APP_STATUS).build();
        addWeb2AppSession(sessionFilter, TEST_SESSION_TOKEN);

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", "different-token")
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Session was reset before accessing resource: Session was reset while polling");
    }

    @Test
    void sidWeb2AppPoll_pollingNodeLeftCluster_pollingIsResumedOnThisNode() {
        createSidApiPollStubForAnySession("mock_responses/sid/sid_poll_response_ok.json");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_WEB2APP_STATUS).build();
        addWeb2AppSession(sessionFilter, TEST_SESSION_TOKEN);
        replacePollingNodeIdWithNodeOutsideCluster(sessionFilter);

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED)));
        assertWarningIsLogged("Resuming Smart-ID session status polling on this node");
    }

    @Test
    void sidWeb2AppPoll_pollingNodeStillInCluster_pollingIsNotResumed() {
        createSidApiPollStubForAnySession("mock_responses/sid/sid_poll_response_ok.json");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_WEB2APP_STATUS).build();
        addWeb2AppSession(sessionFilter, TEST_SESSION_TOKEN);

        given()
                .filter(sessionFilter)
                .queryParam("sessionToken", TEST_SESSION_TOKEN)
                .when()
                .get("/auth/sid/web2app/poll")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(POLL_SID_WEB2APP_STATUS, taraSession.getState());
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/smart-id-rp/v3/session/.*")));
    }

    private void replacePollingNodeIdWithNodeOutsideCluster(MockSessionFilter sessionFilter) {
        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        taraSession.setPollingNodeId(UUID.randomUUID().toString());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void createSidApiPollStubForAnySession(String response) {
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v3/session/.*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile(response)));
    }

    private void addWeb2AppSession(MockSessionFilter sessionFilter, String sessionToken) {
        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        taraSession.setSmartIdWeb2AppSession(
                new TaraSession.SmartIdWeb2AppSession("sid-session-id", "session-secret", sessionToken, null, "url-token"));
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private void createDeviceLinkAuthInitStub() {
        wireMockServer.stubFor(any(urlPathEqualTo("/smart-id-rp/v3/authentication/device-link/anonymous"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile("mock_responses/sid/sid_device_link_init_response.json")));
    }

    private void mockDeviceLinkAuthenticationResponseValidator(String country) {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setCountry(country);
        authenticationIdentity.setIdentityNumber("38001085718");
        authenticationIdentity.setGivenName("Jaak-Kristjan");
        authenticationIdentity.setSurname("Jõeorg");
        when(responseValidator.validate(
                any(SessionStatus.class),
                any(DeviceLinkAuthenticationSessionRequest.class),
                nullable(String.class),
                any(String.class)
        )).thenReturn(authenticationIdentity);
    }
}
