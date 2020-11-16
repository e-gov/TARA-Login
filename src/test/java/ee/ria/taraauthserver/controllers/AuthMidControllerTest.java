package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.config.LevelOfAssurance;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.annotation.DirtiesContext;

import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class AuthMidControllerTest extends BaseTest {

    // TODO parameter names (idCode vs id_code)

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private SessionRepository sessionRepository;

    @Test
    void nationalIdNumber_missing() {
        given()
                .when()
                .formParam("telephoneNumber", "00000766")
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body(containsString("Isikukood ei ole korrektne"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 2 errors");
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
                .body(containsString("Isikukood ei ole korrektne"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 2 errors");
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
                .body(containsString("Isikukood ei ole korrektne"));

        assertErrorIsLogged("User exception: org.springframework.validation.BeanPropertyBindingResult: 2 errors");
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
                .body(containsString("Isikukood ei ole korrektne"));

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
                .body(containsString("Telefoninumber ei ole korrektne"));
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
                .body(containsString("Telefoninumber ei ole korrektne"));
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
                .body(containsString("Telefoninumber ei ole korrektne"));
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
                .body(containsString("Telefoninumber ei ole korrektne"));
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
                .body(containsString("Telefoninumber ei ole korrektne"));
    }

    @Test
    void phoneNumberAndIdCodeValid() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response.json", 200);

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

        assertInfoIsLogged("mid request: ee.sk.mid.rest.dao.request.MidAuthenticationRequest");
        assertInfoIsLogged("mid response: MidAbstractResponse{sessionID='de305d54-75b4-431b-adb2-eb6b9e546015'}");

        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        AuthSession.MidAuthenticationResult result = (AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult();
        assertEquals("60001019906", result.getIdCode());
        assertEquals("EE", result.getCountry());
        assertEquals("MARY ÄNN", result.getFirstName());
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", result.getLastName());
        assertEquals("+37200000266", result.getPhoneNumber());
        assertEquals("+37200000266", result.getSubject());
        assertEquals("2000-01-01", result.getDateOfBirth().toString());
        assertEquals(AuthenticationType.MobileID, result.getAmr());
        assertEquals(LevelOfAssurance.HIGH, result.getAcr());
    }

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
                .body(containsString("Sisendparameetrid ei ole korrektsel kujul."));

        assertErrorIsLogged("User exception: message.mid-rest.error.internal-error");
    }

    @Test
    void midAuthInit_session_status_incorrect() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.INIT_MID);

        session.setAttribute("session", testSession);
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
                .body(containsString("Sisendparameetrid ei ole korrektsel kujul."));

        assertErrorIsLogged("User exception: message.mid-rest.error.internal-error");
    }

    @Test
    void midAuthInit_session_mid_not_allowed() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.IDCard);
        testSession.setAllowedAuthMethods(allowedMethods);
        testSession.setState(AuthState.INIT_AUTH_PROCESS);
        session.setAttribute("session", testSession);
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
                .body(containsString("Sisendparameetrid ei ole korrektsel kujul."));

        assertErrorIsLogged("User exception: message.mid-rest.error.internal-error");
    }

    @Test
    void midAuthInit_response_400() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 400);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Mid authentication failed: ee.sk.mid.exception.MidMissingOrInvalidParameterException: HTTP 400 Bad Request");
        assertErrorIsLogged("Server encountered an unexpected error: message.error.general");
    }

    @Test
    void midAuthInit_response_401() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 401);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Mid authentication failed: ee.sk.mid.exception.MidUnauthorizedException: Request is unauthorized for URI https://localhost:9877/mid-api/authentication: HTTP 401 Unauthorized");
        assertErrorIsLogged("Server encountered an unexpected error: message.error.general");
    }

    @Test
    void midAuthInit_response_405() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 405);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Mid authentication failed: javax.ws.rs.NotAllowedException: HTTP 405 Method Not Allowed");
        assertErrorIsLogged("Server encountered an unexpected error: message.error.general");
    }

    @Test
    void midAuthInit_response_500() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 500);

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", createCorrectSession())
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("Mid authentication failed: Error getting response from cert-store/MSSP for URI https://localhost:9877/mid-api/authentication: HTTP 500 Server Error");
        assertErrorIsLogged("Server encountered an unexpected error: message.mid-rest.error.internal-error");
    }

    @Test
    void midAuthPoll_response_400() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_empty_response.json", 400);

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

        assertInfoIsLogged("Mid polling failed: javax.ws.rs.BadRequestException: HTTP 400 Bad Request");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
    }

    @Test
    void midAuthPoll_response_401() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_empty_response.json", 401);

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

        assertInfoIsLogged("Mid polling failed: javax.ws.rs.NotAuthorizedException: HTTP 401 Unauthorized");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
    }

    @Test
    void midAuthPoll_response_404() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_empty_response.json", 404);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidSessionNotFoundException: Mobile-ID session was not found. Sessions time out in ~5 minutes.");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
    }

    @Test
    void midAuthPoll_response_405() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_empty_response.json", 405);

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

        assertInfoIsLogged("Mid polling failed: javax.ws.rs.NotAllowedException: HTTP 405 Method Not Allowed");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
    }

    @Test
    void midAuthPoll_response_500() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_empty_response.json", 500);

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

        assertInfoIsLogged("Mid polling failed: javax.ws.rs.InternalServerErrorException: HTTP 500 Server Error");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_INTERNAL_ERROR.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
    }

    @Test
    void midAuthPoll_response_user_cancelled() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_user_cancelled.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidUserCancellationException: User cancelled the operation.");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_USER_CANCEL.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(400, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_not_mid_client() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_not_mid_client.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidNotMidClientException: User has no active certificates");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.NOT_MID_CLIENT.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(400, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_timeout() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_timeout.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidSessionTimeoutException: User didn't enter PIN code or communication error.");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_TRANSACTION_EXPIRED.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(500, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_signature_hash_mismatch() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_signature_hash_mismatch.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidInvalidUserConfigurationException: Mobile-ID configuration on user's SIM card differs from what is configured on service provider side. User needs to contact his/her mobile operator.");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_HASH_MISMATCH.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(500, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_phone_absent() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_phone_absent.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidPhoneNotAvailableException: Unable to reach phone or SIM card");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_PHONE_ABSENT.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(400, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_delivery_error() throws InterruptedException {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_delivery_error.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidDeliveryException: SMS sending error");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_DELIVERY_ERROR.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(400, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    void midAuthPoll_response_sim_error() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200);
        createPollStubWithResponse("mock_responses/mid_poll_response_sim_error.json", 200);

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

        assertInfoIsLogged("Mid polling failed: ee.sk.mid.exception.MidDeliveryException: SMS sending error");
        AuthSession authSession = sessionRepository.findById(sessionId).getAttribute("session");
        assertEquals(AuthState.AUTHENTICATION_FAILED, authSession.getState());
        assertEquals(ErrorMessages.MID_DELIVERY_ERROR.getMessage(), ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorMessage());
        assertEquals(400, ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).getErrorStatus());
    }

    @Test
    @DirtiesContext
    void midAuthInit_response_timeout() {
        createAuthenticationStubWithResponse("mock_responses/mid_authenticate_response.json", 200, 2000);

        String sessionId = createCorrectSession();

        given()
                .when()
                .formParam("idCode", "60001019906")
                .formParam("telephoneNumber", "00000766")
                .sessionId("SESSION", sessionId)
                .post("/auth/mid/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body("message", equalTo("Something went wrong internally. Please consult server logs for further details."));

        assertErrorIsLogged("Server encountered an unexpected error: java.net.SocketTimeoutException: Read timed out");
    }

    private void createAuthenticationStubWithResponse(String response, int status) {
        createAuthenticationStubWithResponse(response, status, 0);
    }

    private void createAuthenticationStubWithResponse(String response, int status, int delayInMilliseconds) {
        wireMockServer.stubFor(any(urlPathEqualTo("/mid-api/authentication"))
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
        AuthSession testSession = new AuthSession();
        List<AuthenticationType> allowedMethods = new ArrayList<>();
        allowedMethods.add(AuthenticationType.MobileID);
        testSession.setAllowedAuthMethods(allowedMethods);
        testSession.setState(AuthState.INIT_AUTH_PROCESS);
        AuthSession.LoginRequestInfo lri = new AuthSession.LoginRequestInfo();
        AuthSession.Client client = new AuthSession.Client();
        AuthSession.MetaData metaData = new AuthSession.MetaData();
        AuthSession.OidcClient oidcClient = new AuthSession.OidcClient();
        oidcClient.setShortName("short_name");
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        lri.setClient(client);
        testSession.setLoginRequestInfo(lri);
        session.setAttribute("session", testSession);
        sessionRepository.save(session);
        return session.getId();
    }
}