package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.BaseTest;
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
                .body("message", equalTo("Bad request"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("AuthSession is null");
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
                .body("message", equalTo("Bad request"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("AuthSession state is incorrect");
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
        testSession.setState(AuthState.AUTHENTICATION_SUCCESS);

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
        authResult.setErrorMessage("mid authentication has failed for some reason");
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
                .body("message", equalTo("mid authentication has failed for some reason"))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("AuthSession state is: AUTHENTICATION_FAILED");
    }

}