package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.COMPLETE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;


class AuthSidCancelControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag("CSRF_PROTCTION")
    void authSidPollCancel_NoCsrf() {
        given()
                .filter(withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."));
    }

    @Test
    @Tag(value = "SID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authSidPollCancel_sessionMissing() {

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid session");
    }

    @Test
    @Tag(value = "SID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authSidPollCancel_sessionIncorrectState() {

        given()
                .filter(withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID))
                        .authenticationState(COMPLETE).build())
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale sessiooni staatus."))
                .body("error", equalTo("Bad Request"));

        assertErrorIsLogged("User exception: Invalid authentication state: 'COMPLETE', expected one of: [INIT_SID, POLL_SID_STATUS, AUTHENTICATION_FAILED]");
    }

    @Test
    @Tag(value = "SID_AUTH_CANCELED")
    @Tag(value = "SID_AUTH_STATUS_CHECK_ENDPOINT")
    void authSidPollCancel_ok() {
        TaraSession.SidAuthenticationResult sidAuthenticationResult = new TaraSession.SidAuthenticationResult("testSessionId");

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(POLL_SID_STATUS)
                .authenticationResult(sidAuthenticationResult).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .header("Location", "http://localhost:" + port + "/auth/init?login_challenge=abcdefg098AAdsCC")
                .statusCode(302);

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.POLL_SID_STATUS_CANCELED, taraSession.getState());
        assertWarningIsLogged("Smart ID authentication process with SID session id testSessionId has been canceled");
    }
}