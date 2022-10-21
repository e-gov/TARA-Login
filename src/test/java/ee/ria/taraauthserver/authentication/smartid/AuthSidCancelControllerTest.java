package ee.ria.taraauthserver.authentication.smartid;

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

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.COMPLETE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static java.lang.String.format;

class AuthSidCancelControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag("CSRF_PROTECTION")
    void authSidPollCancel_NoCsrf() {
        given()
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag("SID_AUTH_STATUS_CHECK_VALID_SESSION")
    @Tag("CSRF_PROTECTION")
    void authSidPollCancel_session_missing() {
        given()
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "SID_AUTH_STATUS_CHECK_VALID_SESSION")
    void authSidPollCancel_sessionIncorrectState() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(COMPLETE).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Ebakorrektne päring. Vale seansi staatus."))
                .body("error", equalTo("Bad Request"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid authentication state: 'COMPLETE', expected one of: [AUTHENTICATION_FAILED, INIT_SID, POLL_SID_STATUS, NATURAL_PERSON_AUTHENTICATION_COMPLETED, LEGAL_PERSON_AUTHENTICATION_COMPLETED]");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=SESSION_STATE_INVALID)", sessionFilter.getSession().getId()));
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"INIT_SID", "POLL_SID_STATUS", "AUTHENTICATION_FAILED", "NATURAL_PERSON_AUTHENTICATION_COMPLETED", "LEGAL_PERSON_AUTHENTICATION_COMPLETED"},
            mode = EnumSource.Mode.INCLUDE)
    @Tag(value = "SID_AUTH_CANCELED")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authSidPollCancel_redirectToAuthInit(TaraAuthenticationState state) {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(state).build();

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
        assertWarningIsLogged("Smart ID authentication process has been canceled");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_CANCELED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_CANCELED, authenticationSessionId=%s, errorCode=null)", taraSession.getSessionId()));
    }

    @Test
    @Tag(value = "SID_AUTH_CANCELED")
    void authSidPollCancel_redirectToClientWhenAuthenticationStateIsSuccess() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(AUTHENTICATION_SUCCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .header("Location", "https://oidc-client-mock:8451/oauth/response?error=user_cancel&error_description=User+canceled+the+authentication+process.&state=c46b216b-e73d-4cd2-907b-6c809b44cec1")
                .statusCode(302);

        Session session = sessionRepository.findById(sessionFilter.getSession().getId());
        assertNull(session);
    }
}
