package ee.ria.taraauthserver.authentication.mobileid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.COMPLETE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthMidPollCancelControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag("CSRF_PROTECTION")
    void authMidPoll_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag("MID_AUTH_STATUS_CHECK_VALID_SESSION")
    @Tag("CSRF_PROTECTION")
    void authMidPoll_session_missing() {
        given()
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "MID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authMidPoll_sessionIncorrectState() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(MOBILE_ID))
                        .authenticationState(COMPLETE).build())
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'COMPLETE', expected one of: [AUTHENTICATION_FAILED, INIT_MID, POLL_MID_STATUS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED]");
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"INIT_MID", "POLL_MID_STATUS", "AUTHENTICATION_FAILED", "NATURAL_PERSON_AUTHENTICATION_COMPLETED", "LEGAL_PERSON_AUTHENTICATION_COMPLETED"},
            mode = EnumSource.Mode.INCLUDE)
    @Tag(value = "MID_AUTH_CANCELED")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authMidPollCancel_redirectToAuthInit(TaraAuthenticationState state) {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(state).build();

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
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_CANCELED, errorCode=null)");
    }

    @Test
    @Tag(value = "SID_AUTH_CANCELED")
    void authMidPollCancel_redirectToClientWhenAuthenticationStateIsSuccess() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(MOBILE_ID))
                .authenticationState(AUTHENTICATION_SUCCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/mid/poll/cancel")
                .then()
                .assertThat()
                .header("Location", "https://oidc-client-mock:8451/oauth/response?error=user_cancel&error_description=User+canceled+the+authentication+process.&state=c46b216b-e73d-4cd2-907b-6c809b44cec1")
                .statusCode(302);

        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        assertNull(session);
    }
}
