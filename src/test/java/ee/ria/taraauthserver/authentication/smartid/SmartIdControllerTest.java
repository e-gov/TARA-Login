package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.function.Function;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.error.ErrorCode.SID_REQUEST_TIMEOUT;
import static ee.ria.taraauthserver.security.SessionManagementFilter.MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.awaitility.Durations.TEN_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@Slf4j
class SmartIdControllerTest extends BaseTest {

    // NB! Certificate in sid_poll_response_ok.json expires Dec 17 23:59:59 2030 GMT.

    @SpyBean
    private AuthSidService authSidService;

    @Autowired
    private SmartIdClient sidClient;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private SmartIdConfigurationProperties sidConfigurationProperties;

    private static final String ID_CODE = "idCode";
    private static final String ID_CODE_VALUE = "10101010005";

    @BeforeEach
    void beforeEach() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA==");
        mockHashToSign.setHashType(HashType.SHA512);
        Mockito.doReturn(mockHashToSign).when(authSidService).getAuthenticationHash();
        sidConfigurationProperties.setDisplayText("default short name");
    }

    @Test
    @Tag("CSRF_PROTECTION")
    void sidAuthInit_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag("SID_AUTH_CHECKS_SESSION")
    @Tag("CSRF_PROTECTION")
    void sidAuthInit_session_missing() {
        given()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_status_incorrect() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_SID).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_SID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_SmartIdNotAllowed() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Smart-ID authentication method is not allowed");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_missing() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Validation failed for argument [0] in public java.lang.String");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_blank() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Validation failed for argument [0] in public java.lang.String");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalidLength() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "382929292911")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Validation failed for argument [0] in public java.lang.String");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalid() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "31107s14721")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie poolt sisestatud isikukood ei olnud korrektne. Palun pöörduge tagasi autentimismeetodite valiku juurde ja veenduge, et sisestate korrektse isikukoodi."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: Validation failed for argument [0] in public java.lang.String");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_ok() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        TaraSession.SidAuthenticationResult result = (TaraSession.SidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(ID_CODE_VALUE, result.getIdCode());
        assertEquals("EE", result.getCountry());
        assertEquals("DEMO", result.getFirstName());
        assertEquals("SMART-ID", result.getLastName());
        assertEquals("EE10101010005", result.getSubject());
        assertEquals("1801-01-01", result.getDateOfBirth().toString());
        assertEquals(SMART_ID, result.getAmr());
        assertEquals(LevelOfAssurance.HIGH, result.getAcr());
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_ok_default_language() {
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v2/authentication/etsi/.*"))
                .withRequestBody(matchingJsonPath("$.allowedInteractionsOrder[?(@.type == 'displayTextAndPIN' && @.displayText60 == 'default short name')]"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile("mock_responses/sid/sid_authentication_init_response.json")));
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_ok_non_default_language() {
        wireMockServer.stubFor(any(urlPathMatching("/smart-id-rp/v2/authentication/etsi/.*"))
                .withRequestBody(matchingJsonPath(String.format("$.allowedInteractionsOrder[?(@.type == 'displayTextAndPIN' && @.displayText60 == '%s')]",
                        SHORT_NAME_TRANSLATIONS.get("et"))))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile("mock_responses/sid/sid_authentication_init_response.json")));
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS)
                .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                .build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Nested
    @Disabled("Broken since update to Spring Boot 3")
    class RelyingPartyTest {

        private SmartIdConnector smartIdConnectorSpy;
        private final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier(
                SemanticsIdentifier.IdentityType.PNO,
                SemanticsIdentifier.CountryCode.EE,
                ID_CODE_VALUE);
        private final String CLIENT_RELYING_PARTY_NAME = "client-rp-name";
        private final String CLIENT_RELYING_PARTY_UUID = "f47d57df-899a-4614-87dd-6fbdc866ef3e";

        @BeforeEach
        void setUp() {
            smartIdConnectorSpy = spy(sidClient.getSmartIdConnector());
            sidClient.setSmartIdConnector(smartIdConnectorSpy);
        }

        @Test
        @Tag(value = "SID_AUTH_INIT_REQUEST")
        @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
        void sidAuthInit_nonGovssoLogin_clientSpecificSidRelyingParty() {
            createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
            createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(SMART_ID))
                    .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                smartIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                smartIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                loginRequestInfo.getClient().getMetaData().getOidcClient().setSmartIdSettings(smartIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .when()
                    .formParam(ID_CODE, ID_CODE_VALUE)
                    .post("/auth/sid/init")
                    .then()
                    .assertThat()
                    .statusCode(200);

            await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionId).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

            ArgumentCaptor<AuthenticationSessionRequest> authRequestCaptor =
                    ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(smartIdConnectorSpy, times(1)).authenticate(
                    argThat((SemanticsIdentifier actual) -> SEMANTICS_IDENTIFIER.getIdentifier().equals(actual.getIdentifier())),
                    authRequestCaptor.capture());
            AuthenticationSessionRequest authRequest = authRequestCaptor.getValue();
            assertEquals(CLIENT_RELYING_PARTY_NAME, authRequest.getRelyingPartyName());
            assertEquals(CLIENT_RELYING_PARTY_UUID, authRequest.getRelyingPartyUUID());
        }

        @Test
        @Tag(value = "SID_AUTH_INIT_REQUEST")
        @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
        void sidAuthInit_nonGovssoLogin_defaultSidRelyingParty() {
            createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
            createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(SMART_ID))
                    .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                loginRequestInfo.getClient().getMetaData().getOidcClient().setSmartIdSettings(smartIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .when()
                    .formParam(ID_CODE, ID_CODE_VALUE)
                    .post("/auth/sid/init")
                    .then()
                    .assertThat()
                    .statusCode(200);

            await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionId).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

            ArgumentCaptor<AuthenticationSessionRequest> authRequestCaptor =
                    ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(smartIdConnectorSpy, times(1)).authenticate(
                    argThat((SemanticsIdentifier actual) -> SEMANTICS_IDENTIFIER.getIdentifier().equals(actual.getIdentifier())),
                    authRequestCaptor.capture());
            AuthenticationSessionRequest authRequest = authRequestCaptor.getValue();
            assertEquals(sidConfigurationProperties.getRelyingPartyName(), authRequest.getRelyingPartyName());
            assertEquals(sidConfigurationProperties.getRelyingPartyUuid(), authRequest.getRelyingPartyUUID());
        }

        @Test
        @Tag(value = "SID_AUTH_INIT_REQUEST")
        @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
        void sidAuthInit_govssoLogin_clientSpecificSidRelyingParty() {
            createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
            createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(SMART_ID))
                    .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                smartIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                smartIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(smartIdSettings);

                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                smartIdSettings.setRelyingPartyName("ignored");
                smartIdSettings.setRelyingPartyUuid("ignored");
                loginRequestInfo.getClient().getMetaData().getOidcClient().setSmartIdSettings(smartIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .when()
                    .formParam(ID_CODE, ID_CODE_VALUE)
                    .post("/auth/sid/init")
                    .then()
                    .assertThat()
                    .statusCode(200);

            await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionId).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

            ArgumentCaptor<AuthenticationSessionRequest> authRequestCaptor =
                    ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(smartIdConnectorSpy, times(1)).authenticate(
                    argThat((SemanticsIdentifier actual) -> SEMANTICS_IDENTIFIER.getIdentifier().equals(actual.getIdentifier())),
                    authRequestCaptor.capture());
            AuthenticationSessionRequest authRequest = authRequestCaptor.getValue();
            assertEquals(CLIENT_RELYING_PARTY_NAME, authRequest.getRelyingPartyName());
            assertEquals(CLIENT_RELYING_PARTY_UUID, authRequest.getRelyingPartyUUID());
        }

        @Test
        @Tag(value = "SID_AUTH_INIT_REQUEST")
        @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
        void sidAuthInit_govssoLogin_defaultSidRelyingParty() {
            createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
            createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(SMART_ID))
                    .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(smartIdSettings);

                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .when()
                    .formParam(ID_CODE, ID_CODE_VALUE)
                    .post("/auth/sid/init")
                    .then()
                    .assertThat()
                    .statusCode(200);

            await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionId).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

            ArgumentCaptor<AuthenticationSessionRequest> authRequestCaptor =
                    ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(smartIdConnectorSpy, times(1)).authenticate(
                    argThat((SemanticsIdentifier actual) -> SEMANTICS_IDENTIFIER.getIdentifier().equals(actual.getIdentifier())),
                    authRequestCaptor.capture());
            AuthenticationSessionRequest authRequest = authRequestCaptor.getValue();
            assertEquals(sidConfigurationProperties.getRelyingPartyName(), authRequest.getRelyingPartyName());
            assertEquals(sidConfigurationProperties.getRelyingPartyUuid(), authRequest.getRelyingPartyUUID());
        }

        @Test
        @Tag(value = "SID_AUTH_INIT_REQUEST")
        @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
        void sidAuthInit_govssoLogin_taraClientSidRelyingParty() {
            createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
            createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(SMART_ID))
                    .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(smartIdSettings);

                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.SmartIdSettings smartIdSettings = new TaraSession.SmartIdSettings();
                smartIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                smartIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                loginRequestInfo.getClient().getMetaData().getOidcClient().setSmartIdSettings(smartIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .when()
                    .formParam(ID_CODE, ID_CODE_VALUE)
                    .post("/auth/sid/init")
                    .then()
                    .assertThat()
                    .statusCode(200);

            await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionId).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));

            ArgumentCaptor<AuthenticationSessionRequest> authRequestCaptor =
                    ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(smartIdConnectorSpy, times(1)).authenticate(
                    argThat((SemanticsIdentifier actual) -> SEMANTICS_IDENTIFIER.getIdentifier().equals(actual.getIdentifier())),
                    authRequestCaptor.capture());
            AuthenticationSessionRequest authRequest = authRequestCaptor.getValue();
            assertEquals(CLIENT_RELYING_PARTY_NAME, authRequest.getRelyingPartyName());
            assertEquals(CLIENT_RELYING_PARTY_UUID, authRequest.getRelyingPartyUUID());
        }

        private TaraSession.LoginRequestInfo createGovSsoLoginRequest(TaraSession.SmartIdSettings smartIdSettings) {
            TaraSession.LoginRequestInfo govSsoLoginRequestInfo = new TaraSession.LoginRequestInfo();
            TaraSession.Client client = new TaraSession.Client();
            String expectedClientId = "govsso_test_client_id";
            String expectedRegistryCode = "govsso_test_registry_code";
            SPType expectedSector = SPType.PUBLIC;
            client.setClientId(expectedClientId);

            TaraSession.MetaData metaData = new TaraSession.MetaData();
            TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();
            TaraSession.Institution institution = new TaraSession.Institution();

            institution.setSector(expectedSector);
            institution.setRegistryCode(expectedRegistryCode);
            oidcClient.setInstitution(institution);

            oidcClient.setSmartIdSettings(smartIdSettings);

            metaData.setOidcClient(oidcClient);
            client.setMetaData(metaData);

            govSsoLoginRequestInfo.setClient(client);
            govSsoLoginRequestInfo.setChallenge("challenge-ignored");

            return govSsoLoginRequestInfo;
        }

        void updateSession(String sessionId, Function<TaraSession, TaraSession> fn) {
            Session session = sessionRepository.findById(sessionId);
            TaraSession originalTaraSession = session.getAttribute(TARA_SESSION);
            TaraSession updatedTaraSession = fn.apply(originalTaraSession);
            session.setAttribute(TARA_SESSION, updatedTaraSession);
            sessionRepository.save(session);
        }

    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_successfulAuthentication() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Smart-ID authentication session",
                "State: INIT_AUTH_PROCESS -> INIT_SID",
                "Smart-ID request",
                "Smart-ID response: 200",
                "Initiated Smart-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "State: INIT_SID -> POLL_SID_STATUS",
                "Starting Smart-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Smart-ID response: 200",
                "SID session id de305d54-75b4-431b-adb2-eb6b9e546014 authentication result: OK, document number: PNOEE-10101010005-Z1B2-Q, status: COMPLETE",
                "State: POLL_SID_STATUS -> NATURAL_PERSON_AUTHENTICATION_COMPLETED");
        assertStatisticsIsLoggedOnce(INFO, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_failedAuthentication() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_user_refused.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Smart-ID authentication session",
                "State: INIT_AUTH_PROCESS -> INIT_SID",
                "Smart-ID request",
                "Smart-ID response: 200",
                "Initiated Smart-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "State: INIT_SID -> POLL_SID_STATUS",
                "Starting Smart-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Smart-ID response: 200",
                "SID session id de305d54-75b4-431b-adb2-eb6b9e546014 authentication result: USER_REFUSED, document number: null, status: COMPLETE",
                "State: POLL_SID_STATUS -> AUTHENTICATION_FAILED",
                "Smart-ID authentication failed: User pressed cancel in app, Error code: SID_USER_REFUSED",
                "Authentication result: AUTHENTICATION_FAILED");
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_USER_REFUSED)");
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_USER_REFUSED)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_timeout() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200, 6100);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS)
                .authenticationResult(new TaraSession.SidAuthenticationResult("testSessionId")).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(TEN_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.SidAuthenticationResult result = (TaraSession.SidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(SID_REQUEST_TIMEOUT, result.getErrorCode());
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_REQUEST_TIMEOUT)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_REQUEST_TIMEOUT)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_not_timeout() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200, 5100);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(TEN_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_signatureAuthentication_fails() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGsSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA=");
        mockHashToSign.setHashType(HashType.SHA512);
        Mockito.doReturn(mockHashToSign).when(authSidService).getAuthenticationHash();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_VALIDATION_ERROR, taraSession.getAuthenticationResult().getErrorCode());
        assertErrorIsLogged("Smart-ID authentication exception: Failed to verify validity of signature returned by Smart-ID");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_VALIDATION_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_VALIDATION_ERROR)");
    }

    @Test
    @Tag(value = "MID_AUTH_POLL_RESPONSE")
    void sidAuthInit_PollResponse_400() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 400);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertErrorIsLogged("Smart-ID authentication exception: HTTP 400 Bad Request");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_POLL_RESPONSE")
    void sidAuthInit_PollResponse_401() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 401);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertErrorIsLogged("Smart-ID authentication exception: HTTP 401 Unauthorized");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_POLL_RESPONSE")
    void sidAuthInit_PollResponse_404() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 404);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertErrorIsLogged("Smart-ID authentication exception: null");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_POLL_RESPONSE")
    void sidAuthInit_PollResponse_405() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 405);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertErrorIsLogged("Smart-ID authentication exception: HTTP 405 Method Not Allowed");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_POLL_RESPONSE")
    void sidAuthInit_PollResponse_500() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 500);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_INTERNAL_ERROR, taraSession.getAuthenticationResult().getErrorCode());
        assertErrorIsLogged("Smart-ID authentication exception: HTTP 500 Server Error");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_INTERNAL_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_userRefused() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_user_refused.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_USER_REFUSED, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User pressed cancel in app, Error code: SID_USER_REFUSED");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_USER_REFUSED)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_USER_REFUSED)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_timeout() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_timeout.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_SESSION_TIMEOUT, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: Session timed out without getting any response from user, Error code: SID_SESSION_TIMEOUT");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_SESSION_TIMEOUT)");
        //TODO AUT-1528 Is logged double
        assertMessageWithMarkerIsLogged(StatisticsLogger.class, ERROR, null, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_SESSION_TIMEOUT)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_documentUnusable() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_document_unusable.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_DOCUMENT_UNUSABLE, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: DOCUMENT_UNUSABLE. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason., Error code: SID_DOCUMENT_UNUSABLE");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_DOCUMENT_UNUSABLE)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_DOCUMENT_UNUSABLE)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_wrongVc() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_wrong_vc.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_WRONG_VC, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User selected wrong verification code, Error code: SID_WRONG_VC");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_WRONG_VC)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_WRONG_VC)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_requiredInteractionNotSupportedByApp() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_required_interaction_not_supported_by_app.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_INTERACTION_NOT_SUPPORTED, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User app version does not support any of the allowedInteractionsOrder interactions., Error code: SID_INTERACTION_NOT_SUPPORTED");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_INTERACTION_NOT_SUPPORTED)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_INTERACTION_NOT_SUPPORTED)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_userRefusedCertChoice() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_user_refused_cert_choice.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_USER_REFUSED_CERT_CHOICE, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User has multiple accounts and pressed Cancel on device choice screen on any device., Error code: SID_USER_REFUSED_CERT_CHOICE");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_USER_REFUSED_CERT_CHOICE)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_USER_REFUSED_CERT_CHOICE)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_userRefusedDisplaytextandpin() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_user_refused_displaytextandpin.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_USER_REFUSED_DISAPLAYTEXTANDPIN, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User pressed Cancel on PIN screen., Error code: SID_USER_REFUSED_DISAPLAYTEXTANDPIN");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_USER_REFUSED_DISAPLAYTEXTANDPIN)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_USER_REFUSED_DISAPLAYTEXTANDPIN)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_userRefusedVcChoice() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_user_refused_vc_choice.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_USER_REFUSED_VC_CHOICE, taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: User cancelled verificationCodeChoice screen, Error code: SID_USER_REFUSED_VC_CHOICE");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_USER_REFUSED_VC_CHOICE)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_USER_REFUSED_VC_CHOICE)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_unknownStatus() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_unknown_status.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_VALIDATION_ERROR, taraSession.getAuthenticationResult().getErrorCode());
        assertErrorIsLogged("Smart-ID authentication exception: Session status end result is 'UNKNOWN_STATUS'");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_VALIDATION_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_VALIDATION_ERROR)");
    }

    @Test
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_ERRORS")
    void sidAuthInit_PollResponse_ok_unknownCertificateLevel() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200);
        createSidApiPollStub("mock_responses/sid/sid_poll_response_unknown_certificate_level.json", 200);

        given()
                .filter(sessionFilter)
                .when()
                .formParam(ID_CODE, ID_CODE_VALUE)
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorCode.SID_VALIDATION_ERROR, taraSession.getAuthenticationResult().getErrorCode());
        assertErrorIsLogged("Smart-ID authentication exception: Signer's certificate is below requested certificate level");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_VALIDATION_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=10101010005, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_VALIDATION_ERROR)");
    }
}
