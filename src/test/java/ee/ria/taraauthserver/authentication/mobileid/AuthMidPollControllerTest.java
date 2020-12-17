package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
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

        assertErrorIsLogged("User exception: Session was not found");
    }

    @Test
    void midAuth_session_status_incorrect() {
        Session session = sessionRepository.createSession();

        TaraSession taraSession = new TaraSession();
        taraSession.setState(TaraAuthenticationState.INIT_AUTH_PROCESS);
        TaraSession.MidAuthenticationResult authenticationResult = new TaraSession.MidAuthenticationResult();
        authenticationResult.setMidSessionId("testSessionId");
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);

        given()
                .when()
                .sessionId("SESSION", session.getId())
                .get("/auth/mid/poll")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected one of: '[NATURAL_PERSON_AUTHENTICATION_COMPLETED, POLL_MID_STATUS, AUTHENTICATION_FAILED]'");
    }

    @Test
    void midAuth_session_status_poll_mid_status() {
        Session session = sessionRepository.createSession();
        TaraSession taraSession = new TaraSession();
        taraSession.setState(TaraAuthenticationState.POLL_MID_STATUS);
        TaraSession.MidAuthenticationResult authenticationResult = new TaraSession.MidAuthenticationResult();
        authenticationResult.setMidSessionId("testSessionId");
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
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
        TaraSession taraSession = new TaraSession();
        taraSession.setState(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        TaraSession.MidAuthenticationResult authenticationResult = new TaraSession.MidAuthenticationResult();
        authenticationResult.setMidSessionId("testSessionId");
        taraSession.setAuthenticationResult(authenticationResult);
        session.setAttribute(TARA_SESSION, taraSession);
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

}