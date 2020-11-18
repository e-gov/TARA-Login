package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class AuthMidPollControllerTest extends BaseTest {

    @Autowired
    private SessionRepository sessionRepository;

    @Test
    void midAuth_session_missing() {
        given()
                .when()
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: The attribute 'session' was not found in session");
    }

    @Test
    void midAuth_session_status_incorrect() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.INIT_AUTH_PROCESS);

        session.setAttribute("session", testSession);
        sessionRepository.save(session);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Session not in expected status. Expected one of: [NATURAL_PERSON_AUTHENTICATION_COMPLETED, POLL_MID_STATUS], but was INIT_AUTH_PROCESS");
    }

    @Test
    void midAuth_session_status_poll_mid_status() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.POLL_MID_STATUS);

        session.setAttribute("session", testSession);
        sessionRepository.save(session);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("PENDING"));
    }

    @Test
    void midAuth_session_status_authentication_success() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        session.setAttribute("session", testSession);
        sessionRepository.save(session);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

    }

    @Test
    void midAuth_session_status_authentication_failed() {
        Session session = sessionRepository.createSession();

        AuthSession testSession = new AuthSession();
        testSession.setState(AuthState.AUTHENTICATION_FAILED);
        AuthSession.MidAuthenticationResult authResult = new AuthSession.MidAuthenticationResult();
        authResult.setErrorMessage(ErrorMessages.INVALID_REQUEST);
        testSession.setAuthenticationResult(authResult);

        session.setAttribute("session", testSession);
        sessionRepository.save(session);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: AuthSession state is: AUTHENTICATION_FAILED");
    }

}