package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockSessionFilter.CsrfMode;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.challenge.ChallengeNonce;
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
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
class IdCardInitControllerTest extends BaseTest {

    private static final String CHALLENGE_NONCE_KEY = "nonce";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag(value = "ESTEID_INIT")
    @Tag(value = "CSRF_PROTCTION")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_NoCsrf_Fails() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/init")
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
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_MissingSession_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withoutTaraSession()
                .sessionRepository(sessionRepository)
                .csrfMode(CsrfMode.HEADER)
                .build();
        given()
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_CorrectAuthenticationState_ReturnsNonce() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();
        String sessionId = mockSessionFilter.getSession().getId();

        given()
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/init")
                .then()
                .assertThat()
                .statusCode(200)
                .body("nonce", equalTo(getNonceFromSession(sessionId)));

        TaraSession taraSession = sessionRepository.findById(sessionId).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.NONCE_SENT, taraSession.getState());
        TaraSession.AuthenticationResult result = taraSession.getAuthenticationResult();
        assertEquals(AuthenticationType.ID_CARD, result.getAmr());
        assertInfoIsLogged("Generated nonce: " + getNonceFromSession(sessionId));
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "ESTEID_INIT")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_IncorrectAuthenticationState_ReturnsError() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .authenticationState(TaraAuthenticationState.INIT_MID)
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        given()
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/init")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_MID', expected one of: [INIT_AUTH_PROCESS]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=SESSION_STATE_INVALID)");
    }

    private String getNonceFromSession(String sessionId) {
        return ((ChallengeNonce) sessionRepository.findById(sessionId).getAttribute(CHALLENGE_NONCE_KEY)).getBase64EncodedNonce();
    }
}
