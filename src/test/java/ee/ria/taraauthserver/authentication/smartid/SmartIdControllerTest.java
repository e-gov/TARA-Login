package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.HashType;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.error.ErrorCode.SID_REQUEST_TIMEOUT;
import static ee.ria.taraauthserver.security.SessionManagementFilter.TARA_TRACE_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
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
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class SmartIdControllerTest extends BaseTest {

    @SpyBean
    private AuthSidService authSidService;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    private static final String ID_CODE = "idCode";
    private static final String ID_CODE_VALUE = "10101010005";

    @BeforeEach
    void beforeEach() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA==");
        mockHashToSign.setHashType(HashType.SHA512);
        Mockito.doReturn(mockHashToSign).when(authSidService).getAuthenticationHash();
    }

    @Test
    @Tag("CSRF_PROTCTION")
    void sidAuthInit_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(403)
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_missing() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_status_incorrect() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_MID).build())
                .formParam(ID_CODE, ID_CODE_VALUE)
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_SESSION")
    void sidAuthInit_session_SmartIdNotAllowed() {
        given()
                .filter(withTaraSession()
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
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User exception: Smart-ID authentication method is not allowed");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_missing() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_blank() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalidLength() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "382929292911")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    @Tag(value = "SID_AUTH_CHECKS_IDCODE")
    void sidAuthInit_idCode_invalid() {
        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build())
                .when()
                .formParam(ID_CODE, "31107s14721")
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Isikukood ei ole korrektne."))
                .body("error", equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE + CHARSET_UTF_8);

        assertErrorIsLogged("User input exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
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
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(TARA_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Smart-ID authentication session",
                "Tara session state change: INIT_AUTH_PROCESS -> INIT_SID",
                "Smart-ID service request",
                "Smart-ID service response. Status code: 200",
                "Initiated Smart-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Tara session state change: INIT_SID -> POLL_SID_STATUS",
                "Saving session with state: POLL_SID_STATUS",
                "Starting Smart-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Smart-ID service response. Status code: 200",
                "SID session id de305d54-75b4-431b-adb2-eb6b9e546014 authentication result: OK, document number: PNOEE-10101010005-Z1B2-Q, status: COMPLETE",
                "Tara session state change: POLL_SID_STATUS -> NATURAL_PERSON_AUTHENTICATION_COMPLETED",
                "Saving session with state: NATURAL_PERSON_AUTHENTICATION_COMPLETED");
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
        assertMessageIsLogged(e -> e.getMDCPropertyMap().getOrDefault(TARA_TRACE_ID, "missing").equals(taraTraceId),
                "Initiating Smart-ID authentication session",
                "Tara session state change: INIT_AUTH_PROCESS -> INIT_SID",
                "Smart-ID service request",
                "Smart-ID service response. Status code: 200",
                "Initiated Smart-ID session with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Tara session state change: INIT_SID -> POLL_SID_STATUS",
                "Saving session with state: POLL_SID_STATUS",
                "Starting Smart-ID session status polling with id: de305d54-75b4-431b-adb2-eb6b9e546014",
                "Smart-ID service response. Status code: 200",
                "SID session id de305d54-75b4-431b-adb2-eb6b9e546014 authentication result: USER_REFUSED, document number: null, status: COMPLETE",
                "Tara session state change: POLL_SID_STATUS -> AUTHENTICATION_FAILED",
                "Smart-ID authentication failed: User pressed cancel in app, Error code: SID_USER_REFUSED",
                "Authentication result: AUTHENTICATION_FAILED",
                "Saving session with state: AUTHENTICATION_FAILED");
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
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_not_timeout() {
        createSidApiAuthenticationStub("mock_responses/sid/sid_authentication_init_response.json", 200, 5100);

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
    }

    @Test
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_signatureAuthentication_fails() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGsSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA==");
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

        assertErrorIsLogged("Smart-ID authentication exception: Failed to verify validity of signature returned by Smart-ID");

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
        assertEquals(ErrorCode.ERROR_GENERAL, taraSession.getAuthenticationResult().getErrorCode());

        assertErrorIsLogged("Smart-ID authentication exception: Session status end result is 'UNKNOWN_STATUS'");
    }

}