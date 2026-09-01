package ee.ria.taraauthserver.authentication.smartid.qrcode;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.smartid.SmartIdDeviceLinkSession;
import ee.ria.taraauthserver.session.IgniteClusterNodes;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static java.nio.charset.StandardCharsets.UTF_8;

import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.FlowType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.UUID;

import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static ee.ria.taraauthserver.error.ErrorCode.SID_COUNTRY_NOT_ALLOWED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.EXTERNAL_TRANSACTION;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"}) // Disabled to avoid EIDAS /supportedCountries API call
class SmartIdQrCodeControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @MockitoBean
    private DeviceLinkAuthenticationResponseValidator responseValidator;

    @MockitoSpyBean
    private AuthSidQrCodeService authSidQrCodeService;

    @Autowired
    private IgniteClusterNodes igniteClusterNodes;

    @Test
    void sidQrCodeAuthInit_countryAllowed_authenticationSucceeds() {
        createDeviceLinkAuthInitStub(200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("EE");
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/qr-code/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
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
                .idCode("38001085718")
                .authenticationType(SMART_ID)
                .authenticationState(EXTERNAL_TRANSACTION)
                .smartIdFlowType(FlowType.QR)
                .eventDuration(0L)
                .build());
    }

    @Test
    void sidQrCodeAuthInit_countryNotAllowed_authenticationFails() {
        createDeviceLinkAuthInitStub(200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("LV");
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/qr-code/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(ee.ria.taraauthserver.error.ErrorCode.SID_COUNTRY_NOT_ALLOWED,
                taraSession.getAuthenticationResult().getErrorCode());
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
                .smartIdFlowType(FlowType.QR)
                .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                .clientId("openIdDemo")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .authenticationType(SMART_ID)
                .authenticationState(EXTERNAL_TRANSACTION)
                .errorCode(SID_COUNTRY_NOT_ALLOWED)
                .smartIdFlowType(FlowType.QR)
                .eventDuration(0L)
                .build());
    }

    @Test
    void sidQrCodeAuthInit_technicalError_externalTransactionLogged() {
        createDeviceLinkAuthInitStub(500);
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/qr-code/init")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(SMART_ID)
                        .authenticationState(AUTHENTICATION_FAILED)
                        .errorCode(ee.ria.taraauthserver.error.ErrorCode.SID_INTERNAL_ERROR)
                        .smartIdFlowType(FlowType.QR)
                        .build());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                defaultStatisticsMarkerBuilder()
                        .clientId("openIdDemo")
                        .sector("public")
                        .registryCode("10001234")
                        .country("EE")
                        .authenticationType(SMART_ID)
                        .authenticationState(EXTERNAL_TRANSACTION)
                        .errorCode(ee.ria.taraauthserver.error.ErrorCode.SID_INTERNAL_ERROR)
                        .smartIdFlowType(FlowType.QR)
                        .build());
    }

    @Test
    void resumePolling_pollingNodeLeftCluster_pollingIsResumedOnThisNode() throws Exception {
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("EE");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_QR_CODE).build();
        addQrCodeSessionPolledByNodeOutsideCluster(sessionFilter);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        authSidQrCodeService.resumePollingIfPollingNodeHasLeftCluster(taraSession);

        TaraSession completedSession = awaitSessionState(sessionFilter, NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        TaraSession.SidAuthenticationResult result = (TaraSession.SidAuthenticationResult) completedSession.getAuthenticationResult();
        assertEquals("38001085718", result.getIdCode());
        assertWarningIsLogged("Resuming Smart-ID session status polling on this node");
    }

    @Test
    void resumePolling_pollingNodeStillInCluster_pollingIsNotResumed() throws Exception {
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_QR_CODE).build();
        addQrCodeSessionPolledByNodeOutsideCluster(sessionFilter);
        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        taraSession.setPollingNodeId(igniteClusterNodes.localNodeId());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);

        authSidQrCodeService.resumePollingIfPollingNodeHasLeftCluster(taraSession);

        TaraSession sessionAfterResume = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(POLL_SID_QR_CODE, sessionAfterResume.getState());
        wireMockServer.verify(0, getRequestedFor(urlPathMatching("/smart-id-rp/v3/session/.*")));
    }

    @Test
    void sidQrCodePoll_checksWhetherPollingNodeHasLeftCluster() {
        MockSessionFilter sessionFilter = createMockSessionFilter();

        given()
                .filter(sessionFilter)
                .when()
                .get("/auth/sid/qr-code/poll")
                .then()
                .assertThat()
                .statusCode(200);

        Mockito.verify(authSidQrCodeService).resumePollingIfPollingNodeHasLeftCluster(any(TaraSession.class));
    }

    private void addQrCodeSessionPolledByNodeOutsideCluster(MockSessionFilter sessionFilter) throws Exception {
        DeviceLinkAuthenticationSessionRequest sessionRequest = new DeviceLinkAuthenticationSessionRequest(
                "rp-uuid", "rp-name", "QUALIFIED", null, null, "interactions-in-base64", null, null, "https://localhost/callback");
        DeviceLinkSessionResponse sessionResponse = new DeviceLinkSessionResponse(
                "de305d54-75b4-431b-adb2-eb6b9e546014", "session-token", "session-secret",
                new URI("https://localhost:9999/device-link-base"));
        SmartIdDeviceLinkSession deviceLinkSession = new SmartIdDeviceLinkSession(
                Instant.EPOCH, new RpChallenge("rp-challenge".getBytes(UTF_8)), sessionRequest, sessionResponse);

        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        TaraSession.SidAuthenticationResult authenticationResult =
                new TaraSession.SidAuthenticationResult(deviceLinkSession.sessionId());
        authenticationResult.setAmr(SMART_ID);
        taraSession.setAuthenticationResult(authenticationResult);
        taraSession.setSmartIdQrCodeSession(deviceLinkSession);
        taraSession.setPollingNodeId(UUID.randomUUID().toString());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

    private TaraSession awaitSessionState(MockSessionFilter sessionFilter, TaraAuthenticationState state) {
        return await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(state)));
    }

    private void createDeviceLinkAuthInitStub(int status) {
        wireMockServer.stubFor(any(urlPathEqualTo("/smart-id-rp/v3/authentication/device-link/anonymous"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile("mock_responses/sid/sid_device_link_init_response.json")));
    }

    private MockSessionFilter createMockSessionFilter() {
        return MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
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
                isNull(),
                any(String.class)
        )).thenReturn(authenticationIdentity);
    }
}
