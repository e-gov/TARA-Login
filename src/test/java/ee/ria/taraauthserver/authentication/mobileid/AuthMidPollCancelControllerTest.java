package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.COMPLETE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthMidPollCancelControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag("CSRF_PROTCTION")
    void authMidPoll_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authMidPoll_sessionMissing() {

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authMidPoll_sessionIncorrectState() {

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(COMPLETE).build())
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'COMPLETE', expected one of: [INIT_MID, POLL_MID_STATUS, AUTHENTICATION_FAILED]");
    }

    @Test
    @Tag(value = "MID_AUTH_CANCELED")
    @Tag(value = "MID_AUTH_STATUS_CHECK_ENDPOINT")
    void authMidPoll_ok() {
        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(POLL_MID_STATUS).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .header("Location", "http://localhost:" + port + "/auth/init?login_challenge=abcdefg098AAdsCC")
                .statusCode(302);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.POLL_MID_STATUS_CANCELED, taraSession.getState());
        assertWarningIsLogged("Mobile-ID authentication process has been canceled");
    }
}
