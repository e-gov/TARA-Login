package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.ErrorTranslationCodes;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.annotation.DirtiesContext;

import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthMidControllerTest extends BaseTest {

    // TODO parameter names (idCode vs id_code)

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private SessionRepository sessionRepository;

    @Test
    void midAuthInit_session_missing() {

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", Matchers.equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    void nationalIdNumber_missing() {

        given()
                .when()
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Isikukood ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    void nationalIdNumber_blank() {
        given()
                .when()
                .formParam("idCode", "")
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Isikukood ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    void nationalIdNumber_invalidLength() {
        given()
                .when()
                .formParam("idCode", "382929292911")
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Isikukood ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    void nationalIdNumber_invalid() {
        given()
                .when()
                .formParam("idCode", "31107114721")
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Isikukood ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 1 errors");
    }

    @Test
    void phoneNumber_missing() {
        given()
                .when()
                .formParam("idCode", "60001019906")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Telefoninumber ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));
    }

    @Test
    void phoneNumber_blank() {
        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Telefoninumber ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));
    }

    @Test
    void phoneNumber_invalid() {
        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "123abc456def")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Telefoninumber ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));
    }

    @Test
    void phoneNumber_tooShort() {
        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "+12345")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Telefoninumber ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));

    }

    @Test
    void phoneNumber_tooLong() {
        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "000007669837468734593465")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Telefoninumber ei ole korrektne."))
                .body("error", Matchers.equalTo("Bad Request"));
    }

    @Test
    void phoneNumberAndIdCodeValid() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(1000);

        assertInfoIsLogged("Mid init request: ee.sk.mid.rest.dao.request.MidAuthenticationRequest");
        assertInfoIsLogged("Mid init response: MidAbstractResponse{sessionID='de305d54-75b4-431b-adb2-eb6b9e546015'}");
        assertInfoIsLogged("Mobile ID authentication process with MID session id de305d54-75b4-431b-adb2-eb6b9e546015 has been initiated");

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        TaraSession.MidAuthenticationResult result = (TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("60001019906", result.getIdCode());
        assertEquals("EE", result.getCountry());
        assertEquals("MARY ÄNN", result.getFirstName());
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", result.getLastName());
        assertEquals("+37200000266", result.getPhoneNumber());
        assertEquals("EE60001019906", result.getSubject());
        assertEquals("2000-01-01", result.getDateOfBirth().toString());
        assertEquals(AuthenticationType.MobileID, result.getAmr());
        assertEquals(LevelOfAssurance.HIGH, result.getAcr());
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
    }

    @Test
    void midAuthInit_request_language_is_correct() {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
                .withRequestBody(matchingJsonPath("$.language", equalTo("ENG")))
                .willReturn(aResponse()
                        .withBodyFile("mock_responses/mid/mid_authenticate_response.json")
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)));

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init?lang=en")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void midAuthInit_session_status_incorrect() {
        Session session = sessionRepository.createSession();

        TaraSession testSession = new TaraSession();
        testSession.setState(TaraAuthenticationState.INIT_MID);

        session.setAttribute(TARA_SESSION, testSession);
        sessionRepository.save(session);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", session.getId())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Ebakorrektne päring."))
                .body("error", Matchers.equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: authSession state should be INIT_AUTH_PROCESS but was INIT_MID");
    }

    @Test
    void midAuthInit_session_mid_not_allowed() {
        Session session = sessionRepository.createSession();

        TaraSession testSession = new TaraSession();
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.IDCard);
        testSession.setAllowedAuthMethods(allowedMethods);
        testSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        session.setAttribute(TARA_SESSION, testSession);
        sessionRepository.save(session);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", session.getId())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", Matchers.equalTo("Ebakorrektne päring."))
                .body("error", Matchers.equalTo("Bad Request"))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        assertErrorIsLogged("User exception: Mobile ID authentication method is not allowed");
    }

    @Test
    void midAuthInit_response_400() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 400);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during MID authentication init: HTTP 400 Bad Request");
    }

    @Test
    void midAuthInit_response_401() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 401);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during MID authentication init: Request is unauthorized for URI https://localhost:9877/mid-api/authentication: HTTP 401 Unauthorized");
    }

    @Test
    void midAuthInit_response_405() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 405);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Server encountered an unexpected error: Internal error during MID authentication init: HTTP 405 Method Not Allowed");
    }

    @Test
    void midAuthInit_response_500() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 500);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: MID service is currently unavailable: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
    }

    @Test
    void midAuthInit_response_no_certificate() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 500);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502);

        assertErrorIsLogged("Service not available: MID service is currently unavailable: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
    }

    @Test
    void midAuthPoll_response_400() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_empty_response.json", 400);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: HTTP 400 Bad Request");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
    }

    @Test
    void midAuthPoll_response_401() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_empty_response.json", 401);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: HTTP 401 Unauthorized");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
    }

    @Test
    void midAuthPoll_response_404() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_empty_response.json", 404);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: Mobile-ID session was not found. Sessions time out in ~5 minutes.");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
    }

    @Test
    void midAuthPoll_response_405() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_empty_response.json", 405);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: HTTP 405 Method Not Allowed");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
    }

    @Test
    void midAuthPoll_response_500() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_empty_response.json", 500);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019939")
                .formParam("telephoneNumber", "00000266")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: HTTP 500 Server Error");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        // TODO assertEquals(ErrorMessages.MID_INTERNAL_ERROR.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_user_cancelled() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_user_cancelled.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: User cancelled the operation.");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_USER_CANCEL, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_not_mid_client() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_not_mid_client.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: User has no active certificates, and thus is not Mobile-ID client");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.NOT_MID_CLIENT, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_timeout() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_timeout.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: User didn't enter PIN code or communication error.");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_TRANSACTION_EXPIRED, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_signature_hash_mismatch() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_signature_hash_mismatch.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: Mobile-ID configuration on user's SIM card differs from what is configured on service provider side. User needs to contact his/her mobile operator.");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_HASH_MISMATCH, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_phone_absent() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_phone_absent.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: Unable to reach phone or SIM card");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_PHONE_ABSENT, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_delivery_error() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_delivery_error.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        Thread.sleep(500);

        assertInfoIsLogged("Mid polling failed: SMS sending error");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_DELIVERY_ERROR, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_sim_error() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid/mid_poll_response_sim_error.json", 200);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(200);

        assertInfoIsLogged("Mid polling failed: SMS sending error");
        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ErrorTranslationCodes.MID_DELIVERY_ERROR, ((TaraSession.MidAuthenticationResult) taraSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    @DirtiesContext
    void midAuthInit_response_timeout() {
        createAuthenticationStubWithResponse("mock_responses/mid/mid_authenticate_response.json", 200, 2000);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(502)
                .body("message", org.hamcrest.Matchers.equalTo("Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."));

        assertErrorIsLogged("Service not available: MID service is currently unavailable: java.net.SocketTimeoutException: Read timed out");
    }

    private void createAuthenticationStubWithResponse(String response, int status) {
        createAuthenticationStubWithResponse(response, status, 0);
    }

    private void createAuthenticationStubWithResponse(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
                .withRequestBody(matchingJsonPath("$.language", equalTo("EST")))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withFixedDelay(delayInMilliseconds)
                        .withBodyFile(response)));
    }

    private void createPollStubWithResponse(String response, int status) {
        wireMockServer.stubFor(any(urlPathMatching("/mid-api/authentication/session/.*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    private String createCorrectSession() {
        Session session = sessionRepository.createSession();
        TaraSession testSession = new TaraSession();
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.MobileID);
        testSession.setAllowedAuthMethods(allowedMethods);
        testSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.Client client = new TaraSession.Client();
        TaraSession.MetaData metaData = new TaraSession.MetaData();
        TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();
        oidcClient.setShortName("short_name");
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        lri.setClient(client);
        testSession.setLoginRequestInfo(lri);
        session.setAttribute(TARA_SESSION, testSession);
        sessionRepository.save(session);
        return session.getId();
    }
}