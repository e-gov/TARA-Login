package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.ERROR;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class IdCardInitControllerTest extends BaseTest {

    private static final String CHALLENGE_NONCE_KEY = "nonce";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_CorrectAuthenticationState_ReturnsNonce() throws AuthTokenException {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/id/init")
                .then()
                .assertThat()
                .statusCode(200)
                .body("nonce", equalTo(getNonceFromSession(sessionId)));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.NONCE_SENT, taraSession.getState());
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals(AuthenticationType.ID_CARD, result.getAmr());
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_SessionMissing_ReturnsError() {
        given()
                .when()
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"));

        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_IncorrectAuthenticationState_ReturnsError() {
        String sessionId = createSessionWithAuthenticationState(TaraAuthenticationState.INIT_MID);

        given()
                .when()
                .sessionId("SESSION", sessionId)
                .get("/auth/id")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=null, eidasRequesterId=null, sector=public, registryCode=null, legalPerson=false, country=null, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    private String createSessionWithAuthenticationState(TaraAuthenticationState authenticationState) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.getClient().getMetaData().getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        authSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(TARA_SESSION, authSession);
        sessionRepository.save(session);
        return session.getId();
    }

    private String getNonceFromSession(String sessionId) {
        return ((ChallengeNonce) sessionRepository.findById(sessionId).getAttribute(CHALLENGE_NONCE_KEY)).getBase64EncodedNonce();
    }
}
