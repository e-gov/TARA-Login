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
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class SmartIdControllerTest extends BaseTest {

    @SpyBean
    private SmartIdController smartIdController;

    @Autowired
    private SessionRepository<Session> sessionRepository;

    private static final String ID_CODE = "smartIdCode";
    private static final String ID_CODE_VALUE = "10101010005";

    @BeforeEach
    void beforeEach() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA==");
        mockHashToSign.setHashType(HashType.SHA512);
        Mockito.doReturn(mockHashToSign).when(smartIdController).getAuthenticationHash();
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
                .body("message", equalTo("Forbidden"))
                .body("path", equalTo("/auth/sid/init"));
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

        assertErrorIsLogged("User exception: Smart ID authentication method is not allowed");
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

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
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

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
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

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
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

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
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
    @Tag(value = "SID_AUTH_INIT_REQUEST")
    @Tag(value = "SID_AUTH_POLL_RESPONSE_COMPLETED_OK")
    void sidAuthInit_signatureAuthentication_fails() {
        AuthenticationHash mockHashToSign = new AuthenticationHash();
        mockHashToSign.setHashInBase64("mri6grZmsF8wXJgTNzGRsoodshrFsdPTorCaBKsDOGsSGCh64R+tPbu+ULVvKIh9QRVu0pLiPx3cpeX/TgsdyNA==");
        mockHashToSign.setHashType(HashType.SHA512);
        Mockito.doReturn(mockHashToSign).when(smartIdController).getAuthenticationHash();

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

        assertErrorIsLogged("received sid poll exception: Failed to verify validity of signature returned by Smart-ID");

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

        assertErrorIsLogged("received sid poll exception: HTTP 400 Bad Request");
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

        assertErrorIsLogged("received sid poll exception: HTTP 401 Unauthorized");
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

        assertErrorIsLogged("received sid poll exception: null");
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

        assertErrorIsLogged("received sid poll exception: HTTP 405 Method Not Allowed");
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
        assertEquals(ErrorCode.INTERNAL_ERROR, taraSession.getAuthenticationResult().getErrorCode());

        assertErrorIsLogged("received sid poll exception: HTTP 500 Server Error");
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

        assertErrorIsLogged("received sid poll exception: User pressed cancel in app");
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

        assertErrorIsLogged("received sid poll exception: Session timed out without getting any response from user");
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

        assertErrorIsLogged("received sid poll exception: DOCUMENT_UNUSABLE. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.");
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

        assertErrorIsLogged("received sid poll exception: User selected wrong verification code");
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

        assertErrorIsLogged("received sid poll exception: User app version does not support any of the allowedInteractionsOrder interactions.");
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

        assertErrorIsLogged("received sid poll exception: User has multiple accounts and pressed Cancel on device choice screen on any device.");
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

        assertErrorIsLogged("received sid poll exception: User pressed Cancel on PIN screen.");
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

        assertErrorIsLogged("received sid poll exception: User cancelled verificationCodeChoice screen");
    }

}