package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_LOGIN_CHALLENGE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.COMPLETE;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;


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

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"INIT_SID", "POLL_SID_STATUS", "AUTHENTICATION_FAILED", "NATURAL_PERSON_AUTHENTICATION_COMPLETED", "LEGAL_PERSON_AUTHENTICATION_COMPLETED"},
            mode = EnumSource.Mode.INCLUDE)
    @Tag(value = "SID_AUTH_CANCELED")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authSidPollCancel_With_CancellableAuthenticationState_RedirectToAuthInit(TaraAuthenticationState cancellableStatus) {
        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(cancellableStatus).build();
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
        assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_CANCELED");
    }

    @Test
    @Tag(value = "SID_AUTH_CANCELED")
    @Tag(value = "LOG_EVENT_UNIQUE_STATUS")
    void authSidPollCancel_Without_CancellableAuthenticationState_ForwardToAuthReject() {
        wireMockServer.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + MOCK_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mockLoginAcceptResponse.json")));

        MockSessionFilter sessionFilter = withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(COMPLETE).build();
        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/poll/cancel")
                .then()
                .assertThat()
                .header("Location", Matchers.endsWith("some/test/url"))
                .statusCode(302);

        String sessionId = sessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertInfoIsLogged("Tara session state change: COMPLETE -> POLL_SID_STATUS_CANCELED");
        assertWarningIsLogged("Smart ID authentication process has been canceled");
        assertInfoIsLogged("OIDC login reject request: https://localhost:9877/oauth2/auth/requests/login/reject?login_challenge=abcdefg098AAdsCC");
        assertInfoIsLogged("Tara session state change: POLL_SID_STATUS_CANCELED -> AUTHENTICATION_CANCELED");
        assertWarningIsLogged("Session has been invalidated: " + sessionId);
        assertInfoIsLogged("Session is removed from cache: " + sessionId);

        assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_CANCELED");
    }
}