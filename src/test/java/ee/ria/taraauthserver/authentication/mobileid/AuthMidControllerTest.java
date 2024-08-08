package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MidAuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.MidAuthenticationHashToSign;
import ee.sk.mid.MidClient;
import ee.sk.mid.MidHashType;
import ee.sk.mid.rest.MidConnector;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.function.Function;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.error.ErrorCode.ERROR_GENERAL;
import static ee.ria.taraauthserver.error.ErrorCode.MID_INTERNAL_ERROR;
import static ee.ria.taraauthserver.security.SessionManagementFilter.MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.awaitility.Durations.TEN_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.spy;

@Slf4j
class AuthMidControllerTest extends BaseTest {
    private final MidAuthenticationHashToSign MOCK_HASH_TO_SIGN = new MidAuthenticationHashToSign.MobileIdAuthenticationHashToSignBuilder()
            .withHashType(MidHashType.SHA512)
            .withHashInBase64("rbk7bdU+rc5CEbJ4h7I5l6chpMzdBiWkxIENPmcLLmI=").build();

    @SpyBean
    private AuthMidService authMidService;

    @Autowired
    private MidClient midClient;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Autowired
    private MidAuthConfigurationProperties midAuthConfigurationProperties;

    @BeforeEach
    void beforeEach() {
        Mockito.doReturn(MOCK_HASH_TO_SIGN).when(authMidService).getAuthenticationHash();
        midAuthConfigurationProperties.setDisplayText("default short name");
    }

    @AfterEach
    void afterEach() {
        Mockito.reset(authMidService);
    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_successfulAuthentication() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200);
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Mobile-ID authentication session",
                "State: INIT_AUTH_PROCESS -> INIT_MID",
                "Mobile-ID request",
                "Mobile-ID response: 200",
                "State: INIT_MID -> POLL_MID_STATUS",
                "Initiated Mobile-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Starting Mobile-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Mobile-ID response: 200",
                "MID session id de305d54-75b4-431b-adb2-eb6b9e546015 authentication result: OK, status: COMPLETE",
                "State: POLL_MID_STATUS -> NATURAL_PERSON_AUTHENTICATION_COMPLETED");
        assertStatisticsIsLoggedOnce(INFO, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    @Tag(value = "LOG_TARA_TRACE_ID")
    void taraTraceIdOnAllLogsWhen_failedAuthentication() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200);
        createMidApiPollStub("mock_responses/mid/mid_poll_response_sim_error.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        String taraTraceId = DigestUtils.sha256Hex(taraSession.getSessionId());
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Mobile-ID authentication session",
                "State: INIT_AUTH_PROCESS -> INIT_MID",
                "Mobile-ID request",
                "Mobile-ID response: 200",
                "State: INIT_MID -> POLL_MID_STATUS",
                "Initiated Mobile-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Starting Mobile-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Mobile-ID response: 200",
                "Error with SIM or communicating with it",
                "State: POLL_MID_STATUS -> AUTHENTICATION_FAILED",
                "Mobile-ID authentication failed: SMS sending error, Error code: MID_DELIVERY_ERROR",
                "Authentication result: AUTHENTICATION_FAILED");
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=MID_DELIVERY_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, e -> e.getMDCPropertyMap().getOrDefault(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, "missing").equals(taraTraceId),
                "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=MID_DELIVERY_ERROR)");
    }

    @Test
    @Tag("CSRF_PROTECTION")
    void midAuthInit_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    @Tag("CSRF_PROTECTION")
    void midAuthInit_session_missing() {
        given()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    void midAuthInit_session_status_incorrect() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(TaraAuthenticationState.INIT_MID).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void nationalIdNumber_missing() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User input exception: Validation failed for argument [0]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void nationalIdNumber_blank() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User input exception: Validation failed for argument [0]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumber_invalidLength() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "382929292911")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User input exception: Validation failed for argument [0]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumber_invalid() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "31107114721")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User input exception: Validation failed for argument [0]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void phoneNumber_missing() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_INIT_ENDPOINT")
    void phoneNumber_blank() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_invalid() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "123abc456def")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_tooShort() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "45")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_TEL")
    void phoneNumber_tooLong() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "000007669837468734593465")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_VALID_INPUT_IDCODE")
    void nationalIdNumberinvalid_and_phoneNumberInvalid() {
        given()
                .filter(MockSessionFilter.withTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .formParam("idCode", "31107114721")
                .formParam("telephoneNumber", "123abc456def")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne.; Telefoninumber ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User input exception: Validation failed for argument [0]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    void midAuthInit_session_mid_not_allowed() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(ID_CARD))
                        .authenticationState(INIT_AUTH_PROCESS).build())
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Mobile-ID authentication method is not allowed");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INVALID_REQUEST)");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT")
    @Tag(value = "MID_AUTH_INIT_REQUEST")
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void phoneNumberAndIdCodeValid() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200);
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001017716")
                .formParam("telephoneNumber", "59100366")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertAuthenticationResult(result);
        assertInfoIsLogged(
                "Initiating Mobile-ID authentication session",
                "State: INIT_AUTH_PROCESS -> INIT_MID",
                "Mobile-ID request",
                "Mobile-ID response: 200",
                "State: INIT_MID -> POLL_MID_STATUS",
                "Initiated Mobile-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Starting Mobile-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546015",
                "Mobile-ID response: 200",
                "MID session id de305d54-75b4-431b-adb2-eb6b9e546015 authentication result: OK, status: COMPLETE",
                "State: POLL_MID_STATUS -> NATURAL_PERSON_AUTHENTICATION_COMPLETED");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    void midAuthInit_request_language_is_correct() {
        createMidApiAuthenticationStub(
                "mock_responses/mid/mid_authenticate_response.json",
                200,
                0,
                "ENG",
                "default short name"
        );
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001017716")
                .formParam("telephoneNumber", "59100366")
                .when()
                .post("/auth/mid/init?lang=en")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertAuthenticationResult(result);
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Test
    void midAuthInit_request_non_default_language_is_correct() {
        createMidApiAuthenticationStub(
                "mock_responses/mid/mid_authenticate_response.json",
                200,
                0,
                "EST",
                SHORT_NAME_TRANSLATIONS.get("et")
        );
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                .build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001017716")
                .formParam("telephoneNumber", "59100366")
                .when()
                .post("/auth/mid/init?lang=et")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertAuthenticationResult(result);
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    @Nested
    @Disabled("Broken since update to Spring Boot 3")
    class RelyingPartyTest {

        private MidConnector mobileIdConnectorSpy;
        private final String CLIENT_RELYING_PARTY_NAME = "client-rp-name";
        private final String CLIENT_RELYING_PARTY_UUID = "f47d57df-899a-4614-87dd-6fbdc866ef3e";

        @BeforeEach
        void setUp() {
            mobileIdConnectorSpy = spy(midClient.getMobileIdConnector());
            ReflectionTestUtils.setField(midClient, "connector", mobileIdConnectorSpy);
        }

        @Test
        void midAuthInit_nonGovssoLogin_clientSpecificSidRelyingParty() {
            createMidApiAuthenticationStub(
                    "mock_responses/mid/mid_authenticate_response.json",
                    200,
                    0,
                    "EST",
                    SHORT_NAME_TRANSLATIONS.get("et")
            );
            createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(MOBILE_ID))
                    .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                    .build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                mobileIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                mobileIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                loginRequestInfo.getClient().getMetaData().getOidcClient().setMidSettings(mobileIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .formParam("idCode", "60001017716")
                    .formParam("telephoneNumber", "59100366")
                    .when()
                    .post("/auth/mid/init?lang=et")
                    .then()
                    .assertThat()
                    .statusCode(200);

            TaraSession taraSession = await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
            TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
            assertAuthenticationResult(result);
            assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
        }

        @Test
        void midAuthInit_nonGovssoLogin_defaultSidRelyingParty() {
            createMidApiAuthenticationStub(
                    "mock_responses/mid/mid_authenticate_response.json",
                    200,
                    0,
                    "EST",
                    SHORT_NAME_TRANSLATIONS.get("et")
            );
            createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(MOBILE_ID))
                    .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                    .build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                loginRequestInfo.getClient().getMetaData().getOidcClient().setMidSettings(mobileIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .formParam("idCode", "60001017716")
                    .formParam("telephoneNumber", "59100366")
                    .when()
                    .post("/auth/mid/init?lang=et")
                    .then()
                    .assertThat()
                    .statusCode(200);

            TaraSession taraSession = await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
            TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
            assertAuthenticationResult(result);
            assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
        }

        @Test
        void midAuthInit_govssoLogin_clientSpecificSidRelyingParty() {
            createMidApiAuthenticationStub(
                    "mock_responses/mid/mid_authenticate_response.json",
                    200,
                    0,
                    "EST",
                    midAuthConfigurationProperties.getDisplayText()
            );
            createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(MOBILE_ID))
                    .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                    .build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                mobileIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                mobileIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(mobileIdSettings);
                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .formParam("idCode", "60001017716")
                    .formParam("telephoneNumber", "59100366")
                    .when()
                    .post("/auth/mid/init?lang=et")
                    .then()
                    .assertThat()
                    .statusCode(200);

            TaraSession taraSession = await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
            TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
            assertAuthenticationResult(result);
            assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=GOVSSO, clientId=govsso_test_client_id, eidasRequesterId=null, sector=public, registryCode=govsso_test_registry_code, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
        }

        @Test
        void midAuthInit_govssoLogin_defaultSidRelyingParty() {
            createMidApiAuthenticationStub(
                    "mock_responses/mid/mid_authenticate_response.json",
                    200,
                    0,
                    "EST",
                    midAuthConfigurationProperties.getDisplayText()
            );
            createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(MOBILE_ID))
                    .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                    .build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(mobileIdSettings);
                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .formParam("idCode", "60001017716")
                    .formParam("telephoneNumber", "59100366")
                    .when()
                    .post("/auth/mid/init?lang=et")
                    .then()
                    .assertThat()
                    .statusCode(200);

            TaraSession taraSession = await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
            TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
            assertAuthenticationResult(result);
            assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=GOVSSO, clientId=govsso_test_client_id, eidasRequesterId=null, sector=public, registryCode=govsso_test_registry_code, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
        }

        @Test
        void midAuthInit_govssoLogin_taraClientSidRelyingParty() {
            createMidApiAuthenticationStub(
                    "mock_responses/mid/mid_authenticate_response.json",
                    200,
                    0,
                    "EST",
                    midAuthConfigurationProperties.getDisplayText()
            );
            createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
            MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                    .sessionRepository(sessionRepository)
                    .authenticationTypes(of(MOBILE_ID))
                    .shortNameTranslations(SHORT_NAME_TRANSLATIONS)
                    .build();
            String sessionId = sessionFilter.getSession().getId();

            updateSession(sessionId, session -> {
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                TaraSession.LoginRequestInfo govSsoLoginRequestInfo = createGovSsoLoginRequest(mobileIdSettings);
                session.setGovSsoLoginRequestInfo(govSsoLoginRequestInfo);
                return session;
            });

            updateSession(sessionId, session -> {
                TaraSession.LoginRequestInfo loginRequestInfo = session.getLoginRequestInfo();
                TaraSession.MidSettings mobileIdSettings = new TaraSession.MidSettings();
                mobileIdSettings.setRelyingPartyName(CLIENT_RELYING_PARTY_NAME);
                mobileIdSettings.setRelyingPartyUuid(CLIENT_RELYING_PARTY_UUID);
                loginRequestInfo.getClient().getMetaData().getOidcClient().setMidSettings(mobileIdSettings);
                return session;
            });

            given()
                    .filter(sessionFilter)
                    .formParam("idCode", "60001017716")
                    .formParam("telephoneNumber", "59100366")
                    .when()
                    .post("/auth/mid/init?lang=et")
                    .then()
                    .assertThat()
                    .statusCode(200);

            TaraSession taraSession = await().atMost(FIVE_SECONDS)
                    .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
            TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
            assertAuthenticationResult(result);
            assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=GOVSSO, clientId=govsso_test_client_id, eidasRequesterId=null, sector=public, registryCode=govsso_test_registry_code, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
        }

        private TaraSession.LoginRequestInfo createGovSsoLoginRequest(TaraSession.MidSettings mobileIdSettings) {
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

            oidcClient.setMidSettings(mobileIdSettings);

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
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_400() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 400);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(ERROR_GENERAL, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: HTTP 400 Bad Request");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_401() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 401);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(ERROR_GENERAL, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: Request is unauthorized for URI https://localhost:9877/mid-api/authentication: HTTP 401 Unauthorized");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_405() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 405);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(ERROR_GENERAL, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: HTTP 405 Method Not Allowed");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=ERROR_GENERAL)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=ERROR_GENERAL)");
    }

    @Test
    @Tag(value = "MID_AUTH_INIT_RESPONSE")
    void midAuthInit_response_500() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 500);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(MID_INTERNAL_ERROR, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=MID_INTERNAL_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=MID_INTERNAL_ERROR)");
    }

    @Test
    void midAuthInit_response_no_certificate() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 500);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(TEN_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(MID_INTERNAL_ERROR, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=MID_INTERNAL_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=MID_INTERNAL_ERROR)");
    }

    @Test
    void midAuthInit_response_timeout() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200, midAuthConfigurationProperties.getReadTimeoutMilliseconds() + 100);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        TaraSession taraSession = await().atMost(TEN_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(AUTHENTICATION_FAILED)));
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals(MID_INTERNAL_ERROR, result.getErrorCode());
        assertErrorIsLogged("Mobile-ID authentication exception: Unknown error when connecting to Host");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=MID_INTERNAL_ERROR)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=MID_INTERNAL_ERROR)");
    }

    @Test
    void midAuthInit_response_not_timeout() {
        createMidApiAuthenticationStub("mock_responses/mid/mid_authenticate_response.json", 200, midAuthConfigurationProperties.getReadTimeoutMilliseconds() - 100);
        createMidApiPollStub("mock_responses/mid/mid_poll_response.json", 200);
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID)).build();

        given()
                .filter(sessionFilter)
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .when()
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        await().atMost(TEN_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION), hasProperty("state", equalTo(NATURAL_PERSON_AUTHENTICATION_COMPLETED)));
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=60001017716, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null)");
    }

    private void assertAuthenticationResult(TaraSession.MidAuthenticationResult result) {
        assertEquals("60001017716", result.getIdCode());
        assertEquals("EE", result.getCountry());
        assertEquals("ONE", result.getFirstName());
        assertEquals("TESTNUMBER", result.getLastName());
        assertEquals("+37259100366", result.getPhoneNumber());
        assertEquals("EE60001017716", result.getSubject());
        assertEquals("2000-01-01", result.getDateOfBirth().toString());
        assertEquals(MOBILE_ID, result.getAmr());
        assertEquals(LevelOfAssurance.HIGH, result.getAcr());
    }
}
